"""Explicit, isolated safety self-tests."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from nexora.oversight.kill_switch import KillSwitch


def run_kill_switch_self_test() -> dict[str, Any]:
    """Exercise marker clear/engage/restart/clear using a disposable temp directory."""
    checks: dict[str, bool] = {}
    try:
        with TemporaryDirectory(prefix="nexora-kill-switch-test-") as directory:
            marker = Path(directory) / "KILL"
            initial = KillSwitch(marker)
            checks["initial_state_clear"] = not initial.is_engaged()
            initial.engage("nexora-isolated-self-test")
            checks["engage_creates_marker"] = marker.is_file()
            checks["engaged_state_detected"] = initial.is_engaged()
            checks["restart_preserves_engaged_state"] = KillSwitch(marker).is_engaged()
            KillSwitch(marker).clear()
            checks["clear_removes_marker"] = not marker.exists()
            checks["clear_state_detected_after_restart"] = not KillSwitch(marker).is_engaged()
        return {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks,
            "production_marker_touched": False,
            "temporary_workspace_cleaned": True,
            "execution_enabled": False,
            "read_only_production_state": True,
            "note": (
                "This validates local marker lifecycle only. It does not test process "
                "termination, external workers, runtime freeze, recovery authorization, "
                "or physical-device behavior."
            ),
        }
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "FAIL",
            "checks": checks,
            "error": type(exc).__name__,
            "production_marker_touched": False,
            "execution_enabled": False,
            "read_only_production_state": True,
        }
