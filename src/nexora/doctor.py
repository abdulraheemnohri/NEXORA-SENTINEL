"""Read-only aggregate diagnostics for NEXORA-SENTINEL."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
from pathlib import Path
from typing import Any

from nexora._oversight_impl import GENESIS, canonical
from nexora.readiness import build_settings_policy_status, build_spec_status
from nexora.sandbox_readiness import inspect_sandbox_readiness
from nexora.settings_manager import settings_report


def _file_state(path: Path) -> tuple[str, dict[str, Any]]:
    """Return existence/type metadata without creating or following a symlink."""
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return "NOT_INITIALIZED", {"path": str(path), "present": False}
    except OSError as exc:
        return "UNREADABLE", {"path": str(path), "present": None, "error": type(exc).__name__}
    if stat.S_ISLNK(info.st_mode):
        return "INVALID", {"path": str(path), "present": True, "reason": "symlink_refused"}
    if not stat.S_ISREG(info.st_mode):
        return "INVALID", {"path": str(path), "present": True, "reason": "not_regular_file"}
    return "PRESENT", {"path": str(path), "present": True, "size_bytes": info.st_size}


def _verify_audit_file(path: Path) -> dict[str, Any]:
    state, metadata = _file_state(path)
    if state != "PRESENT":
        return {"status": state, "valid": None, **metadata, "read_only": True}
    previous = GENESIS
    count = 0
    try:
        with path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    return {
                        "status": "INVALID", "valid": False, "entries": count,
                        "reason": f"invalid_json_line:{number}", **metadata, "read_only": True,
                    }
                if not isinstance(row, dict):
                    return {
                        "status": "INVALID", "valid": False, "entries": count,
                        "reason": f"audit_record_not_object:{number}", **metadata, "read_only": True,
                    }
                body = {key: value for key, value in row.items() if key != "hash"}
                expected = hashlib.sha256((previous + canonical(body)).encode()).hexdigest()
                if row.get("previous_hash") != previous or row.get("hash") != expected:
                    return {
                        "status": "INVALID", "valid": False, "entries": count,
                        "reason": f"hash_chain_mismatch:{number}", **metadata, "read_only": True,
                    }
                count += 1
                previous = expected
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        return {
            "status": "UNREADABLE", "valid": None, "entries": count,
            "reason": type(exc).__name__, **metadata, "read_only": True,
        }
    return {
        "status": "VALID", "valid": True, "entries": count,
        "head_hash": previous, **metadata, "read_only": True,
    }


def _inspect_kill_marker(path: Path) -> dict[str, Any]:
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return {"status": "CLEAR", "engaged": False, "marker_present": False, "read_only": True}
    except (OSError, ValueError) as exc:
        return {
            "status": "ENGAGED_FAIL_CLOSED", "engaged": True,
            "marker_present": None, "error": type(exc).__name__, "read_only": True,
        }
    return {
        "status": "ENGAGED", "engaged": True, "marker_present": True,
        "marker_is_symlink": stat.S_ISLNK(info.st_mode), "read_only": True,
    }


def _inspect_registry_database(path: Path) -> dict[str, Any]:
    state, metadata = _file_state(path)
    if state != "PRESENT":
        return {"status": state, **metadata, "read_only": True}
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
            integrity = result[0] if result else "NO_RESULT"
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        return {
            "status": "INVALID", "integrity": "CHECK_FAILED",
            "error": type(exc).__name__, **metadata, "read_only": True,
        }
    return {
        "status": "VALID" if integrity == "ok" else "INVALID",
        "integrity": integrity, **metadata, "read_only": True,
    }


def build_doctor_report(
    data_dir: Path = Path("data"),
    *,
    settings_path: Path = Path("config/settings.yaml"),
    settings_policy_path: Path | None = None,
) -> dict[str, Any]:
    """Inspect current state without initializing databases or changing policy."""
    root = Path(data_dir)
    audit = _verify_audit_file(root / "audit.jsonl")
    kill = _inspect_kill_marker(root / "KILL")
    registry = _inspect_registry_database(root / "registry.sqlite3")

    try:
        settings = settings_report(settings_path)
        settings_check = {
            "status": "VALID", "valid": True,
            "autonomy_level": settings["settings"]["autonomy_level"],
            "execution_enabled": False, "read_only": True,
        }
    except (OSError, ValueError, TypeError) as exc:
        settings_check = {
            "status": "INVALID", "valid": False,
            "error": type(exc).__name__, "execution_enabled": False, "read_only": True,
        }

    try:
        policy = build_settings_policy_status(
            settings_policy_path or Path("config/settings_authorization.json")
        )
    except (OSError, ValueError, TypeError) as exc:
        policy = {
            "status": "INVALID", "error": type(exc).__name__,
            "settings_mutation_enabled": False,
        }

    try:
        specification = build_spec_status(settings_policy_path=(
            settings_policy_path or Path("config/settings_authorization.json")
        ))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        specification = {
            "status": "INVALID", "error": type(exc).__name__,
            "controls": {"execution_enabled": False, "settings_mutation_enabled": False},
        }

    sandbox = inspect_sandbox_readiness()
    checks = {
        "audit_log": audit,
        "kill_switch": kill,
        "registry_database": registry,
        "settings": settings_check,
        "settings_authorization": policy,
        "specification": {
            "status": specification["status"],
            "blockers": specification.get("blockers", []),
            "read_only": True,
        },
        "sandbox": {
            "status": sandbox["status"],
            "blockers": sandbox["blockers"],
            "execution_enabled": False,
            "read_only": True,
        },
    }

    critical = []
    warnings = []
    if audit["status"] in {"INVALID", "UNREADABLE"}:
        critical.append("audit_log")
    if registry["status"] == "INVALID":
        critical.append("registry_database")
    if settings_check["status"] == "INVALID":
        critical.append("settings")
    if kill["engaged"]:
        warnings.append("kill_switch_engaged")
    for name in ("audit_log", "registry_database"):
        if checks[name]["status"] == "NOT_INITIALIZED":
            warnings.append(f"{name}_not_initialized")
    if specification["status"] != "READY_FOR_INDEPENDENT_REVIEW":
        warnings.append("specification_blockers_present")
    if policy["status"] != "POLICY_APPROVED":
        warnings.append("settings_authorization_not_approved")
    if sandbox["status"] != "READY":
        warnings.append("sandbox_not_qualified")

    overall = "CRITICAL" if critical else ("BLOCKED" if warnings else "HEALTHY")
    return {
        "schema_version": 1,
        "status": overall,
        "read_only": True,
        "data_directory": str(root),
        "checks": checks,
        "critical_failures": critical,
        "warnings": sorted(set(warnings)),
        "controls": {
            "storage_created": False,
            "settings_mutated": False,
            "policy_mutated": False,
            "execution_enabled": False,
            "autonomy_increased": False,
            "network_probed": False,
        },
        "note": (
            "This report performs local read-only checks. Missing setup, unqualified "
            "sandbox isolation, incomplete source specifications, unknown matrix "
            "relationships and unapproved settings policy are reported as blockers."
        ),
    }
