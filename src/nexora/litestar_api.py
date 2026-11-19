"""Optional Litestar read-only local control plane.

This application exposes diagnostics only. It has no mutation handlers, no
execution route, no remote binding option, and no authentication bypass for
network-facing deployments. The supported launcher binds to IPv4 loopback.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


class ControlPlaneError(RuntimeError):
    """Raised when the optional local API cannot be started safely."""


def _response(view: dict[str, Any]) -> dict[str, Any]:
    """Add explicit capability boundaries to every API response."""
    return {
        "api_version": "v1",
        "read_only": True,
        "controls": {
            "settings_mutation_enabled": False,
            "policy_mutation_enabled": False,
            "capability_promotion_enabled": False,
            "tool_execution_enabled": False,
            "network_egress_enabled": False,
        },
        "view": view,
    }


def create_litestar_app(
    data_dir: Path = Path("data"),
    *,
    settings_path: Path = Path("config/settings.yaml"),
):
    """Build a GET-only Litestar app; does not initialize local storage.

    The returned ASGI app is useful for embedding and testing. Production
    launching should use run_litestar_api, which hard-binds to loopback.
    """
    try:
        from litestar import Litestar, get
    except ImportError as exc:
        raise ControlPlaneError(
            "Litestar is optional; install nexora-sentinel[control-plane]"
        ) from exc

    root = Path(data_dir)
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        root_metadata = None
    except OSError as exc:
        raise ControlPlaneError("control_plane_data_dir_unreadable") from exc
    if root_metadata is not None and (
        root.is_symlink() or not root.is_dir()
    ):
        raise ControlPlaneError("control_plane_data_dir_must_be_real_directory")
    root = root.absolute()
    settings_file = Path(settings_path)

    @get(path="/healthz", sync_to_thread=True)
    def health() -> dict[str, Any]:
        return _response({
            "status": "OK",
            "service": "NEXORA-SENTINEL",
            "mode": "READ_ONLY_DIAGNOSTICS",
        })

    @get(path="/api/v1/status", sync_to_thread=True)
    def status() -> dict[str, Any]:
        from nexora.diagnostics import build_doctor_report

        try:
            report = build_doctor_report(root, settings_path=settings_file)
        except (OSError, ValueError, TypeError, RuntimeError, KeyError):
            report = {
                "status": "ATTENTION_REQUIRED",
                "checks": {},
                "blocking_checks": ["diagnostics_unavailable"],
            }
        return _response(report)

    @get(path="/api/v1/specification", sync_to_thread=True)
    def specification() -> dict[str, Any]:
        from nexora.readiness import build_spec_status

        try:
            report = build_spec_status()
        except (OSError, ValueError, TypeError, KeyError):
            report = {
                "status": "INVALID",
                "blockers": [{"id": "specification_report_unavailable", "status": "BLOCKED"}],
            }
        return _response(report)

    @get(path="/api/v1/specification/validation", sync_to_thread=True)
    def specification_validation() -> dict[str, Any]:
        from nexora.spec_validation import validate_specification

        try:
            report = validate_specification()
        except (OSError, ValueError, TypeError, KeyError):
            report = {
                "status": "INVALID",
                "valid": False,
                "complete": False,
                "errors": [{"artifact": "specification", "code": "validation_unavailable"}],
            }
        return _response(report)

    @get(path="/api/v1/capabilities", sync_to_thread=True)
    def capabilities() -> dict[str, Any]:
        from nexora.self_capability_report import build_report

        try:
            report = build_report(include_records=False)
        except (OSError, ValueError, TypeError, KeyError):
            report = {
                "status": "INVALID",
                "error": "capability_catalogue_unavailable",
                "execution_enabled": False,
            }
        return _response(report)

    @get(path="/api/v1/proposals", sync_to_thread=True)
    def proposals() -> dict[str, Any]:
        from nexora.proposals import ProposalReadError, read_proposals

        try:
            report = read_proposals(root / "registry.sqlite3", limit=100)
        except (ProposalReadError, OSError, ValueError, TypeError):
            report = {
                "status": "INVALID",
                "count": 0,
                "proposals": [],
                "execution_enabled": False,
            }
        return _response(report)

    @get(path="/api/v1/proposals/{proposal_id:str}", sync_to_thread=True)
    def proposal_detail(proposal_id: str) -> dict[str, Any]:
        from nexora.proposals import ProposalReadError, read_proposals

        try:
            report = read_proposals(
                root / "registry.sqlite3",
                proposal_id=proposal_id,
                limit=1,
            )
        except (ProposalReadError, OSError, ValueError, TypeError):
            report = {
                "status": "INVALID",
                "count": 0,
                "proposals": [],
                "execution_enabled": False,
            }
        return _response(report)

    return Litestar(
        route_handlers=[
            health,
            status,
            specification,
            specification_validation,
            capabilities,
            proposals,
            proposal_detail,
        ],
        allowed_hosts=["127.0.0.1", "localhost"],
        debug=False,
        request_max_body_size=64 * 1024,
    )


def run_litestar_api(
    data_dir: Path = Path("data"),
    *,
    settings_path: Path = Path("config/settings.yaml"),
    port: int = 8765,
) -> None:
    """Serve the diagnostics API on 127.0.0.1 only."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ControlPlaneError("control_plane_port_out_of_range")
    try:
        import uvicorn
    except ImportError as exc:
        raise ControlPlaneError(
            "Uvicorn is optional; install nexora-sentinel[control-plane]"
        ) from exc

    app = create_litestar_app(data_dir, settings_path=settings_path)
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        access_log=False,
        server_header=False,
        date_header=False,
    )
