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
    "/api/maturity-report": lambda root: _render_maturity_report(root),
    "/api/lifecycle-history": lambda root: _render_lifecycle_history(root),
    "/api/evidence-freshness": lambda root: _render_evidence_freshness(root),
    "/api/evidence-provenance": lambda root: _render_evidence_provenance(root),
    "/api/recovery-readiness": lambda root: _render_recovery_readiness(root),
    "/api/recovery-history": lambda root: _render_recovery_history(root),
    "/api/governance": lambda root: _render_governance(),
    "/api/spec-status": lambda root: _render_spec_status(),
    "/api/settings-policy": lambda root: _render_settings_policy(),
    "/api/sandbox-readiness": lambda root: _render_sandbox_readiness(),
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



def _render_lifecycle_history(data_dir: Path, capability_id: int | None = None) -> str:
    from nexora.lifecycle_history import build_lifecycle_history

    database = Path(data_dir) / "registry.sqlite3"
    if not database.is_file():
        return json.dumps({"status": "NOT_CONFIGURED", "read_only": True})
    return json.dumps(
        build_lifecycle_history(
            database,
            capability_id=capability_id,
        ),
        ensure_ascii=False,
        indent=2,
    )


def _render_evidence_provenance(data_dir: Path, capability_id: int | None = None) -> str:
    from nexora.evidence_provenance import build_provenance_report

    database = Path(data_dir) / "registry.sqlite3"
    if not database.is_file():
        return json.dumps({"status": "NOT_CONFIGURED", "read_only": True})
    return json.dumps(
        build_provenance_report(database, capability_id=capability_id),
        ensure_ascii=False,
        indent=2,
    )


def _render_evidence_freshness(data_dir: Path, capability_id: int | None = None) -> str:
    from nexora.evidence_freshness import build_freshness_report

    database = Path(data_dir) / "registry.sqlite3"
    if not database.is_file():
        return json.dumps({"status": "NOT_CONFIGURED", "read_only": True})
    return json.dumps(
        build_freshness_report(database, capability_id=capability_id),
        ensure_ascii=False,
        indent=2,
    )


def _render_maturity_report(data_dir: Path, capability_id: int | None = None) -> str:
    from nexora.maturity_report import build_maturity_report

    return json.dumps(
        build_maturity_report(
            Path(data_dir) / "registry.sqlite3",
            capability_id=capability_id,
        ),
        ensure_ascii=False,
        indent=2,
    )


def _render_sandbox_readiness() -> str:
    from nexora.sandbox_readiness import inspect_sandbox_readiness

    return json.dumps(inspect_sandbox_readiness(), ensure_ascii=False, indent=2)


def _render_governance() -> str:
    from nexora.governance.validation import build_governance_report

    return json.dumps(build_governance_report(), ensure_ascii=False, indent=2)


def _render_spec_status() -> str:
    from nexora.readiness import build_spec_status

    return json.dumps(build_spec_status(), ensure_ascii=False, indent=2)


def _render_settings_policy() -> str:
    from nexora.readiness import build_settings_policy_status

    return json.dumps(build_settings_policy_status(), ensure_ascii=False, indent=2)


def _render_recovery_readiness(data_dir: Path) -> str:
    from nexora.recovery_readiness import RecoverySettings, build_recovery_readiness

    config = Path("config/recovery.json")
    settings = RecoverySettings.load(config) if config.is_file() else RecoverySettings().validate()
    backup_key = Path(settings.trusted_public_key) if settings.trusted_public_key else None
    report = build_recovery_readiness(
        Path(settings.backup_directory), trusted_public_key=backup_key,
        retention_days=settings.retention_days, keep_latest=settings.keep_latest,
        max_backup_age_hours=settings.max_backup_age_hours,
        min_verified_points=settings.min_verified_points,
        history_log=Path(settings.history_log),
        witness_receipt_log=Path(settings.witness_receipt_log),
        trusted_witness_public_key=Path(settings.witness_public_key),
    )
    return json.dumps(report, ensure_ascii=False, indent=2)


def _render_recovery_history(data_dir: Path) -> str:
    from nexora.recovery_history import RecoveryHistoryError, read_recovery_history
    from nexora.recovery_readiness import RecoverySettings

    config = Path("config/recovery.json")
    settings = RecoverySettings.load(config) if config.is_file() else RecoverySettings().validate()
    history = Path(settings.history_log)
    receipts = Path(settings.witness_receipt_log)
    public_key = Path(settings.witness_public_key)
    history_lock = history.with_name(history.name + ".lock")
    receipt_lock = receipts.with_name(receipts.name + ".lock")
    if not history.is_file() or not receipts.is_file() or not public_key.is_file():
        return json.dumps({"configured": False, "status": "NOT_CONFIGURED", "read_only": True})
    if not history_lock.is_file() or not receipt_lock.is_file():
        return json.dumps({"configured": True, "status": "LOCK_STATE_NOT_INITIALIZED", "read_only": True})
    try:
        return json.dumps(read_recovery_history(
            history, receipts, trusted_witness_public_key=public_key,
        ), ensure_ascii=False, indent=2)
    except (RecoveryHistoryError, OSError, ValueError) as exc:
        return json.dumps({"valid": False, "error": type(exc).__name__, "read_only": True})



def _render_settings(settings_path: Path) -> str:
    """Render validated settings without exposing a mutation endpoint."""
    from nexora.settings_manager import settings_report

    try:
        return json.dumps(settings_report(settings_path), ensure_ascii=False, indent=2)
    except (OSError, ValueError, TypeError) as exc:
        return json.dumps({
            "valid": False,
            "error": type(exc).__name__,
            "execution_enabled": False,
            "policy_mutation_enabled": False,
            "read_only": True,
        }, ensure_ascii=False, indent=2)



def create_read_only_server(data_dir: Path, port: int = 8765, *, settings_path: Path | None = None) -> ThreadingHTTPServer:
    """Create a loopback-only server; callers may use port 0 for ephemeral tests."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port_out_of_range")
    root = Path(data_dir)
    settings_file = Path(settings_path) if settings_path is not None else Path("config/settings.yaml")

    class Handler(BaseHTTPRequestHandler):
        server_version = "NEXORA-ReadOnly/1"
        sys_version = ""

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
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
                    ("Settings and safety controls — read only", "/api/settings"),
                    ("Audit log", "/api/audit"),
                    ("Self-family proposals", "/api/proposals"),
                    ("Capability registry", "/api/capabilities"),
                    ("Local memory", "/api/memory"),
                    ("LiteRT-LM runtime and local models", "/api/runtime"),
                    ("Self-capability catalogue and source gaps", "/api/self-capabilities"),
                    ("Capability family evidence evaluation", "/api/family-evaluation"),
                    ("Capability maturity and L0-L4 source gaps", "/api/maturity-report"),
                    ("Lifecycle history and structural regression diagnostics", "/api/lifecycle-history"),
                    ("Evidence freshness and operator-declared expiry", "/api/evidence-freshness"),
                    ("Evidence provenance and source revision declarations", "/api/evidence-provenance"),
                    ("Recovery readiness (trust anchor required for verification)", "/api/recovery-readiness"),
                    ("Witnessed recovery simulation history", "/api/recovery-history"),
                    ("Capability governance validation", "/api/governance"),
                    ("STA-264 specification completeness", "/api/spec-status"),
                    ("Settings authorization and rollback readiness", "/api/settings-policy"),
                    ("OS sandbox readiness (preflight only)", "/api/sandbox-readiness"),
                ):
                    content = (
                        _render_settings(settings_file)
                        if route == "/api/settings"
                        else VIEWS[route](root)
                    )
                    blocks.append(
                        "<section class=\"panel\"><h2>" + escape(title) + "</h2><pre>" +
                        escape(content) + "</pre><p><a href=\"" + route +
                        "\">View read-only JSON endpoint</a></p></section>"
                    )
                page = (
                    "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                    "<title>NEXORA Sentinel — Read Only</title><style>"
                    ":root{color-scheme:dark;font-family:Inter,Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5edf8}"
                    "body{margin:0;background:radial-gradient(circle at top left,#172b45,#0b1220 52%);min-height:100vh}"
                    "main{max-width:1180px;margin:auto;padding:32px 20px 56px}"
                    "header{padding:24px;border:1px solid #26384f;border-radius:18px;background:#101c2d;margin-bottom:22px}"
                    "h1{font-size:clamp(25px,4vw,38px);margin:0 0 8px;letter-spacing:.04em}"
                    ".sub{color:#9fb2c9;margin:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:16px}"
                    ".panel{min-width:0;padding:18px;border:1px solid #26384f;border-radius:16px;background:#101c2d;box-shadow:0 8px 24px #0003}"
                    "h2{font-size:16px;margin:0 0 12px;color:#b8d5f7}pre{white-space:pre-wrap;overflow-wrap:anywhere;"
                    "font:13px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;color:#d4dfed;margin:0 0 14px}"
                    "a{color:#7cc4ff;text-decoration:none}a:hover{text-decoration:underline}"
                    "footer{margin-top:22px;color:#8ea2bb;font-size:12px}"
                    "@media(max-width:520px){main{padding:16px 12px 32px}.panel{padding:14px}}"
                    "</style></head><body><main><header>"
                    "<h1>NEXORA SENTINEL</h1><p class=\"sub\">Local safety console · read-only diagnostics · L0 default</p>"
                    "</header><div class=\"grid\">"
                    + "".join(blocks) +
                    "</div><footer>GET-only diagnostics. No control or execution endpoints. Settings changes are preview-only.</footer>"
                    "</main></body></html>"
                )
                self._send(200, "text/html; charset=utf-8", page.encode("utf-8"))
                return
            if path == "/api/settings":
                payload = json.dumps(
                    {"read_only": True, "view": _render_settings(settings_file)},
                    ensure_ascii=False, separators=(",", ":"),
                ).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", payload)
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
                    payload = json.dumps(
                        {"read_only": True, "view": content},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
                except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            if path == "/api/lifecycle-history":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("capability_id", [])
                if len(values) > 1 or (
                    values and (not values[0].isdigit() or not 1 <= int(values[0]) <= 264)
                ):
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"invalid_capability_id_query_parameter"}')
                    return
                try:
                    capability_id = int(values[0]) if values else None
                    content = _render_lifecycle_history(root, capability_id)
                    payload = json.dumps(
                        {"read_only": True, "view": content},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
                except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            if path == "/api/evidence-freshness":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("capability_id", [])
                if len(values) > 1 or (
                    values and (not values[0].isdigit() or not 1 <= int(values[0]) <= 264)
                ):
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"invalid_capability_id_query_parameter"}')
                    return
                try:
                    capability_id = int(values[0]) if values else None
                    content = _render_evidence_freshness(root, capability_id)
                    payload = json.dumps(
                        {"read_only": True, "view": content},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
                except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            if path == "/api/evidence-provenance":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("capability_id", [])
                if len(values) > 1 or (
                    values and (not values[0].isdigit() or not 1 <= int(values[0]) <= 264)
                ):
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"invalid_capability_id_query_parameter"}')
                    return
                try:
                    capability_id = int(values[0]) if values else None
                    content = _render_evidence_provenance(root, capability_id)
                    payload = json.dumps(
                        {"read_only": True, "view": content},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
                except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as exc:
                    self._send(500, "application/json; charset=utf-8",
                               json.dumps({"error": type(exc).__name__}).encode("utf-8"))
                return
            if path == "/api/maturity-report":
                query = parse_qs(urlsplit(self.path).query)
                values = query.get("capability_id", [])
                if len(values) > 1 or (values and (not values[0].isdigit() or not 1 <= int(values[0]) <= 264)):
                    self._send(400, "application/json; charset=utf-8",
                               b'{"error":"invalid_capability_id_query_parameter"}')
                    return
                try:
                    capability_id = int(values[0]) if values else None
                    content = _render_maturity_report(root, capability_id)
                    payload = json.dumps(
                        {"read_only": True, "view": content},
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")
                    self._send(200, "application/json; charset=utf-8", payload)
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
