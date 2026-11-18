"""Loopback-only, read-only local web dashboard.

This module exposes GET-only diagnostic views. It never initializes storage,
executes tools, changes policy, or offers control endpoints.
"""
from __future__ import annotations

import json
import sqlite3
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from nexora.terminal.dashboard import (
    render_audit,
    render_overview,
    render_proposals,
    render_registry,
)

VIEWS = {
    "/api/overview": render_overview,
    "/api/audit": render_audit,
    "/api/proposals": render_proposals,
    "/api/capabilities": render_registry,
    "/api/memory": lambda root: _render_memory(root),
    "/api/runtime": lambda root: _render_runtime(),
    "/api/self-capabilities": lambda root: _render_self_capabilities(),
    "/api/family-evaluation": lambda root: _render_family_evaluation(root),
}


def _render_memory(data_dir: Path) -> str:
    from nexora.memory.long_term import MemoryStore

    database = Path(data_dir) / "memory.sqlite3"
    if not database.is_file():
        return "MEMORY — no local store"
    try:
        return json.dumps(
            MemoryStore(database, create=False).recent(50),
            ensure_ascii=False,
            indent=2,
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        return f"MEMORY — read failed closed ({type(exc).__name__})"


def _render_runtime() -> str:
    from nexora.intelligence.litertlm import runtime_status

    try:
        return json.dumps(runtime_status(), ensure_ascii=False, indent=2)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return json.dumps({"provider": "LiteRT-LM", "available": False,
                           "error": type(exc).__name__})


def _render_self_capabilities() -> str:
    from nexora.self_capability_report import build_report

    return json.dumps(build_report(include_records=True), ensure_ascii=False, indent=2)


def _render_family_evaluation(data_dir: Path, family: str | None = None) -> str:
    from nexora.family_evaluation import build_family_evaluation

    return json.dumps(
        build_family_evaluation(Path(data_dir) / "registry.sqlite3", family=family),
        ensure_ascii=False,
        indent=2,
    )


def create_read_only_server(data_dir: Path, port: int = 8765) -> ThreadingHTTPServer:
    """Create a loopback-only server; callers may use port 0 for ephemeral tests."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port_out_of_range")
    root = Path(data_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "NEXORA-ReadOnly/1"
        sys_version = ""

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _host_is_local(self) -> bool:
            header = self.headers.get("Host", "")
            hostname = urlsplit("//" + header).hostname
            return hostname in {"127.0.0.1", "localhost"}

        def do_GET(self) -> None:
            if not self._host_is_local():
                self._send(400, "application/json; charset=utf-8", b'{"error":"local_host_required"}')
                return
            path = urlsplit(self.path).path
            if path == "/":
                blocks = []
                for title, route in (
                    ("System overview", "/api/overview"),
                    ("Audit log", "/api/audit"),
                    ("Self-family proposals", "/api/proposals"),
                    ("Capability registry", "/api/capabilities"),
                    ("Local memory", "/api/memory"),
                    ("LiteRT-LM runtime and local models", "/api/runtime"),
                    ("Self-capability catalogue and source gaps", "/api/self-capabilities"),
                    ("Capability family evidence evaluation", "/api/family-evaluation"),
                ):
                    content = VIEWS[route](root)
                    blocks.append(
                        "<section><h2>" + escape(title) + "</h2><pre>" +
                        escape(content) + "</pre><p><a href=\"" + route +
                        "\">View read-only JSON endpoint</a></p></section>"
                    )
                page = (
                    "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                    "<title>NEXORA Sentinel — Read Only</title><body>"
                    "<h1>NEXORA SENTINEL</h1><p>Local read-only dashboard · L0 default</p>"
                    + "".join(blocks) +
                    "<footer>GET-only diagnostics. No control or execution endpoints.</footer>"
                    "</body></html>"
                )
                self._send(200, "text/html; charset=utf-8", page.encode("utf-8"))
                return
            if path == "/api/family-evaluation":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("family", [])
                if len(values) > 1:
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"at_most_one_family_query_parameter_allowed"}')
                    return
                try:
                    content = _render_family_evaluation(root, values[0] if values else None)
                    self._send(200, "application/json; charset=utf-8", content.encode("utf-8"))
                except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            if path == "/api/evidence-evaluation":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("capability_id", [])
                if len(values) != 1 or not values[0].isdigit():
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"one_capability_id_query_parameter_required"}')
                    return
                database = root / "registry.sqlite3"
                if not database.is_file():
                    self._send(404, "application/json; charset=utf-8",
                               b'{"error":"evidence_ledger_not_found"}')
                    return
                try:
                    from nexora.capability_evaluation import evaluate_from_ledger
                    result = evaluate_from_ledger(database, int(values[0]))
                    payload = json.dumps(
                        {"read_only": True, "view": result},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
                except (OSError, ValueError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            view = VIEWS.get(path)
            if view is None:
                self._send(404, "application/json; charset=utf-8", b'{"error":"not_found"}')
                return
            payload = json.dumps(
                {"read_only": True, "view": view(root)},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", payload)

        def do_POST(self) -> None:
            self._send(405, "application/json; charset=utf-8", b'{"error":"method_not_allowed"}')

        def do_PUT(self) -> None:
            self.do_POST()

        def do_PATCH(self) -> None:
            self.do_POST()

        def do_DELETE(self) -> None:
            self.do_POST()

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def run_read_only_web_dashboard(data_dir: Path, port: int = 8765) -> int:
    """Serve the dashboard on 127.0.0.1 only until interrupted."""
    server = create_read_only_server(data_dir, port)
    try:
        print(f"NEXORA read-only dashboard: http://127.0.0.1:{server.server_port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
