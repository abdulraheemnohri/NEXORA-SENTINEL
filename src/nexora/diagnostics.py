"""Read-only environment and subsystem diagnostics."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

from nexora._oversight_impl import GENESIS, KillSwitch, canonical


def collect(data_dir: Path) -> dict:
    """Collect host facts without creating the requested data directory."""
    path = Path(data_dir)
    probe = path if path.exists() else path.parent
    if not probe.exists():
        probe = Path.home()
    usage = shutil.disk_usage(probe)
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "data_dir_exists": path.exists(),
        "data_dir": str(path),
        "disk_total_bytes": usage.total,
        "disk_free_bytes": usage.free,
        "pid": os.getpid(),
        "network_access": "not_probed",
    }


def _audit_report(path: Path) -> dict[str, Any]:
    """Verify a hash-chained audit file without constructing its mutating facade."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"status": "NOT_CONFIGURED", "valid": None, "entries": 0}
    if path.is_symlink() or not path.is_file():
        return {"status": "UNSAFE_PATH", "valid": False, "entries": 0}
    previous = GENESIS
    count = 0
    try:
        with path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError(f"audit_record_not_object:{number}")
                body = {key: value for key, value in item.items() if key != "hash"}
                expected = hashlib.sha256((previous + canonical(body)).encode("utf-8")).hexdigest()
                if item.get("previous_hash") != previous or item.get("hash") != expected:
                    return {
                        "status": "INVALID",
                        "valid": False,
                        "entries": count,
                        "invalid_line": number,
                    }
                if item.get("sequence") != count + 1:
                    return {
                        "status": "INVALID",
                        "valid": False,
                        "entries": count,
                        "invalid_line": number,
                    }
                previous = expected
                count += 1
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return {"status": "INVALID", "valid": False, "entries": count}
    return {"status": "VALID", "valid": True, "entries": count, "head_hash": previous}


def _memory_report(path: Path) -> dict[str, Any]:
    """Verify local memory provenance using SQLite read-only mode only."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"status": "NOT_CONFIGURED", "records": 0, "provenance_valid": None}
    if path.is_symlink() or not path.is_file():
        return {"status": "UNSAFE_PATH", "records": 0, "provenance_valid": False}
    connection = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"memory_records", "memory_events"}.issubset(tables):
            return {"status": "SCHEMA_UNAVAILABLE", "records": 0, "provenance_valid": None}
        rows = connection.execute(
            "SELECT id,content,sha256 FROM memory_records ORDER BY id"
        ).fetchall()
        invalid = [
            int(row[0]) for row in rows
            if hashlib.sha256(str(row[1]).encode("utf-8")).hexdigest() != row[2]
        ]
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok" or invalid:
            return {
                "status": "INVALID",
                "records": len(rows),
                "provenance_valid": False,
                "invalid_memory_ids": invalid,
                "sqlite_integrity": integrity,
            }
        return {
            "status": "VALID",
            "records": len(rows),
            "provenance_valid": True,
            "sqlite_integrity": integrity,
        }
    except (OSError, sqlite3.Error, ValueError):
        return {"status": "UNVERIFIED", "records": 0, "provenance_valid": None}
    finally:
        if connection is not None:
            connection.close()


def build_doctor_report(
    data_dir: Path,
    *,
    settings_path: Path = Path("config/system.yaml"),
) -> dict[str, Any]:
    """Inspect local components without creating files, enabling features, or executing tools."""
    root = Path(data_dir)
    checks: dict[str, Any] = {}
    checks["host"] = {"status": "PASS", **collect(root)}

    stop = KillSwitch(root / "KILL")
    engaged = stop.is_engaged()
    checks["kill_switch"] = {
        "status": "ENGAGED" if engaged else "CLEAR",
        "engaged": engaged,
        "path": str(root / "KILL"),
        "read_only": True,
    }

    checks["audit"] = _audit_report(root / "audit.jsonl")
    checks["memory"] = _memory_report(root / "memory.sqlite3")

    settings_error = None
    try:
        from nexora.settings_manager import settings_report
        settings = settings_report(settings_path)
        checks["settings"] = {
            "status": "VALID",
            "source": settings["source"],
            "autonomy_level": settings["settings"]["autonomy_level"],
            "scheduler_enabled": settings["settings"]["scheduler_enabled"],
            "sandbox_enabled": settings["settings"]["sandbox_enabled"],
            "network_enabled": settings["settings"]["network_enabled"],
        }
    except (OSError, ValueError, TypeError) as exc:
        settings_error = type(exc).__name__
        checks["settings"] = {
            "status": "INVALID",
            "error": settings_error,
            "execution_enabled": False,
        }

    try:
        from nexora.readiness import build_spec_status
        spec = build_spec_status()
        checks["specification"] = {
            "status": spec["status"],
            "blocker_count": len(spec["blockers"]),
            "blockers": [item["id"] for item in spec["blockers"]],
            "read_only": True,
        }
    except (OSError, ValueError, TypeError, KeyError) as exc:
        checks["specification"] = {
            "status": "INVALID",
            "error": type(exc).__name__,
            "read_only": True,
        }

    database = root / "registry.sqlite3"
    if not database.exists():
        checks["registry"] = {"status": "NOT_CONFIGURED", "read_only": True}
    elif database.is_symlink() or not database.is_file():
        checks["registry"] = {"status": "UNSAFE_PATH", "read_only": True}
    else:
        try:
            from nexora.lifecycle_history import build_lifecycle_history
            history = build_lifecycle_history(database)
            checks["registry"] = {
                "status": history.get("status", "UNVERIFIED"),
                "event_count": history.get("event_count", 0),
                "read_only": True,
            }
        except (OSError, ValueError, TypeError, sqlite3.Error):
            checks["registry"] = {"status": "INVALID", "read_only": True}

    try:
        from nexora.intelligence.litertlm import runtime_status
        runtime = runtime_status()
        checks["runtime"] = {
            "status": "AVAILABLE" if runtime["installed"] else "NOT_INSTALLED",
            "enabled": runtime["runtime_enabled"],
            "model_count": len(runtime["models"]),
            "network_downloads_enabled": runtime["network_downloads_enabled"],
            "read_only": True,
        }
    except (OSError, ValueError, TypeError, RuntimeError):
        checks["runtime"] = {"status": "UNVERIFIED", "read_only": True}

    try:
        from nexora.sandbox_readiness import inspect_sandbox_readiness
        sandbox = inspect_sandbox_readiness()
        checks["sandbox"] = {
            "status": sandbox["status"],
            "backend": sandbox["backend"],
            "execution_enabled": False,
            "execution_authorized": False,
            "read_only": True,
        }
    except (OSError, ValueError, TypeError, RuntimeError):
        checks["sandbox"] = {
            "status": "UNVERIFIED",
            "execution_enabled": False,
            "execution_authorized": False,
            "read_only": True,
        }

    blocking = [
        name for name, item in checks.items()
        if item["status"] in {"INVALID", "UNSAFE_PATH", "UNVERIFIED"}
    ]
    expected_gaps = [
        name for name, item in checks.items()
        if item["status"] in {
            "NOT_CONFIGURED", "NOT_INSTALLED", "UNAVAILABLE", "UNPOPULATED_BLOCKING", "BLOCKED"
        }
    ]
    if blocking:
        overall = "ATTENTION_REQUIRED"
    elif expected_gaps or engaged:
        overall = "DEGRADED"
    else:
        overall = "HEALTHY"

    return {
        "schema_version": 1,
        "status": overall,
        "checks": checks,
        "blocking_checks": blocking,
        "known_gaps": expected_gaps,
        "safety": {
            "read_only": True,
            "execution_enabled": False,
            "policy_mutation_enabled": False,
            "settings_mutation_enabled": False,
            "autonomy_increase_enabled": False,
            "network_probed": False,
            "data_directory_created": False,
        },
        "note": (
            "Doctor is a diagnostic report, not a readiness grant. Missing "
            "components and unverified controls remain visible; no subsystem "
            "is initialized, repaired, enabled, or executed."
        ),
    }
