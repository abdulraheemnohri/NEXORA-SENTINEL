"""Backup-first migration orchestration with non-destructive recovery copies."""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from nexora.backup import BackupError, create_backup, restore_backup, verify_backup
from nexora.storage.migrations.runner import Migration, apply_migrations


@dataclass(frozen=True)
class MigrationReport:
    database: str
    previous_version: int
    current_version: int
    backup: str
    backup_sha256: str


class MigrationRecoveryError(RuntimeError):
    """Migration failed; verified recovery copy is available at recovery_copy."""

    def __init__(self, reason: str, *, backup: Path, recovery_copy: Path):
        super().__init__(reason)
        self.backup = backup
        self.recovery_copy = recovery_copy


def migrate_with_backup(
    database: Path,
    migrations: Mapping[int, Migration],
    *,
    signing_key: Path,
    trusted_public_key: Path,
    backup_path: Path,
    recovery_copy_path: Path,
) -> MigrationReport:
    """Back up and verify before migration; on failure restore to a new path.

    This function deliberately never overwrites the original database. A failed
    migration rolls back transactionally. A separately restored recovery copy is
    retained for inspection or an operator-controlled recovery procedure.
    """
    database = Path(database)
    backup_path = Path(backup_path)
    recovery_copy_path = Path(recovery_copy_path)
    if not database.is_file():
        raise FileNotFoundError("migration_database_not_found")
    if database.resolve() in {backup_path.resolve(), recovery_copy_path.resolve()}:
        raise ValueError("migration_artifact_must_not_equal_database")
    if backup_path.resolve() == recovery_copy_path.resolve():
        raise ValueError("backup_and_recovery_paths_must_differ")

    backup_manifest = create_backup(database, backup_path, signing_key=signing_key)
    verified = verify_backup(backup_path, trusted_public_key=trusted_public_key)
    if verified["sha256"] != backup_manifest["sha256"]:
        raise RuntimeError("migration_backup_verification_mismatch")

    with sqlite3.connect(database, timeout=10) as connection:
        previous = int(connection.execute("PRAGMA user_version").fetchone()[0])
        try:
            current = apply_migrations(connection, migrations)
        except Exception as exc:
            try:
                restore_backup(
                    backup_path, recovery_copy_path,
                    trusted_public_key=trusted_public_key,
                )
            except (BackupError, OSError, sqlite3.Error, ValueError) as recovery_exc:
                raise MigrationRecoveryError(
                    f"migration_failed_and_recovery_copy_failed:{type(recovery_exc).__name__}",
                    backup=backup_path, recovery_copy=recovery_copy_path,
                ) from exc
            raise MigrationRecoveryError(
                f"migration_failed:{type(exc).__name__}",
                backup=backup_path, recovery_copy=recovery_copy_path,
            ) from exc

    return MigrationReport(
        database=str(database),
        previous_version=previous,
        current_version=current,
        backup=str(backup_path),
        backup_sha256=verified["sha256"],
    )
