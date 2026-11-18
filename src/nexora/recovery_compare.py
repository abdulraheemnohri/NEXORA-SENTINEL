"""Read-only, cryptographically verified recovery-point comparison."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nexora.backup import BackupError, verify_backup


class RecoveryComparisonError(ValueError):
    """Raised when recovery points cannot be safely compared."""


def compare_recovery_points(
    older_backup: Path,
    newer_backup: Path,
    *,
    trusted_public_key: Path,
) -> dict[str, Any]:
    """Compare verified SQLite schema metadata; never expose row data or mutate backups."""
    older_path, newer_path = Path(older_backup), Path(newer_backup)
    if older_path.is_symlink() or newer_path.is_symlink():
        raise RecoveryComparisonError("recovery_point_symlink_refused")
    if older_path.resolve() == newer_path.resolve():
        raise RecoveryComparisonError("recovery_points_must_be_distinct")
    try:
        older = verify_backup(older_path, trusted_public_key=trusted_public_key)
        newer = verify_backup(newer_path, trusted_public_key=trusted_public_key)
    except (BackupError, OSError, ValueError) as exc:
        raise RecoveryComparisonError(f"recovery_point_verification_failed:{type(exc).__name__}") from exc
    old_tables, new_tables = set(older["tables"]), set(newer["tables"])
    return {
        "valid": True,
        "read_only": True,
        "older": {
            "name": older_path.name,
            "sha256": older["sha256"],
            "created_at": older.get("created_at"),
            "user_version": older["user_version"],
            "table_count": len(old_tables),
            "integrity": older["integrity"],
        },
        "newer": {
            "name": newer_path.name,
            "sha256": newer["sha256"],
            "created_at": newer.get("created_at"),
            "user_version": newer["user_version"],
            "table_count": len(new_tables),
            "integrity": newer["integrity"],
        },
        "schema_comparison": {
            "same_schema": old_tables == new_tables and older["user_version"] == newer["user_version"],
            "same_user_version": older["user_version"] == newer["user_version"],
            "tables_added": sorted(new_tables - old_tables),
            "tables_removed": sorted(old_tables - new_tables),
            "migration_version_delta": newer["user_version"] - older["user_version"],
        },
        "data_equality_checked": False,
        "safety": {
            "backup_modified": False,
            "restore_performed": False,
            "live_database_touched": False,
        },
    }


__all__ = ["RecoveryComparisonError", "compare_recovery_points"]
