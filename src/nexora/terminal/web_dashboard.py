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
from urllib.parse import urlsplit

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
