"""Recovery-point ranking, retention proposals, and isolated restore simulation."""
from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nexora.backup import BackupError, restore_backup
from nexora.backup_inventory import build_backup_inventory


class RecoveryPlanningError(ValueError):
    """Raised when recovery planning inputs are unsafe or invalid."""


def build_recovery_plan(
    directory: Path,
    *,
    trusted_public_key: Path,
    retention_days: int = 30,
    keep_latest: int = 3,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Rank only cryptographically verified points and propose, never perform, retention."""
    if retention_days < 1 or keep_latest < 1:
        raise RecoveryPlanningError("retention_days_and_keep_latest_must_be_positive")
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise RecoveryPlanningError("recovery_clock_must_be_timezone_aware")
    inventory = build_backup_inventory(
        directory, trusted_public_key=trusted_public_key, now=instant,
    )
    valid: list[dict[str, Any]] = []
    for entry in inventory["entries"]:
        if entry.get("status") != "VALID":
            continue
        valid.append({
            **entry,
            "recovery_point_time": entry.get("created_at") or entry["modified_at"],
            "time_source": "signed_manifest" if entry.get("created_at") else "filesystem_mtime_fallback",
        })
    valid.sort(key=lambda item: (item["recovery_point_time"], item["name"]), reverse=True)
    cutoff = instant - timedelta(days=retention_days)
    proposals = []
    for index, item in enumerate(valid):
        timestamp = datetime.fromisoformat(item["recovery_point_time"])
        keep_reasons = []
        if index < keep_latest:
            keep_reasons.append("within_keep_latest")
        if timestamp >= cutoff:
            keep_reasons.append("within_retention_window")
        proposals.append({
            "name": item["name"],
            "sha256": item["sha256"],
            "decision": "KEEP" if keep_reasons else "REVIEW_FOR_RETENTION",
            "reasons": keep_reasons or ["older_than_retention_window_and_outside_keep_latest"],
            "deletion_performed": False,
        })
    return {
        "read_only": True,
        "valid_recovery_points": len(valid),
        "recovery_points": valid,
        "retention": {
            "retention_days": retention_days,
            "keep_latest": keep_latest,
            "cutoff": cutoff.isoformat(),
            "proposals": proposals,
            "automatic_deletion": False,
        },
        "unusable_artifacts": [
            item for item in inventory["entries"] if item.get("status") != "VALID"
        ],
        "safety": {
            "automatic_restore": False,
            "automatic_delete": False,
            "live_database_replacement": False,
        },
    }


def simulate_recovery(
    backup: Path,
    *,
    trusted_public_key: Path,
    confirm: bool = False,
) -> dict[str, Any]:
    """Restore into an isolated temporary directory and remove the simulation afterward."""
    if not confirm:
        raise RecoveryPlanningError("explicit_simulation_confirmation_required")
    backup = Path(backup)
    if backup.is_symlink() or not backup.is_file():
        raise RecoveryPlanningError("recovery_backup_must_be_a_regular_file")
    try:
        with tempfile.TemporaryDirectory(prefix="nexora-recovery-simulation-") as temporary:
            destination = Path(temporary) / "simulation.sqlite3"
            result = restore_backup(
                backup, destination, trusted_public_key=trusted_public_key,
            )
            if not destination.is_file():
                raise RecoveryPlanningError("simulation_restore_output_missing")
            return {
                "simulation": "PASSED",
                "backup": backup.name,
                "verified_sha256": result.get("sha256"),
                "integrity": result["integrity"],
                "user_version": result["user_version"],
                "table_count": len(result["tables"]),
                "temporary_output_removed": True,
                "live_database_touched": False,
                "persistent_restore_created": False,
            }
    except BackupError:
        raise
    except OSError as exc:
        raise RecoveryPlanningError("recovery_simulation_failed") from exc


__all__ = ["RecoveryPlanningError", "build_recovery_plan", "simulate_recovery"]
