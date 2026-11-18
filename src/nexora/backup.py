"""Consistent SQLite backup, verification and non-destructive restore.

Backups use SQLite's online backup API, so committed WAL contents are included.
The adjacent manifest is an integrity aid, not an authenticated signature.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1
MANIFEST_SUFFIX = ".manifest.json"


class BackupError(RuntimeError):
    """Raised when a backup cannot be safely created, verified or restored."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_path(backup: Path) -> Path:
    return backup.with_name(backup.name + MANIFEST_SUFFIX)


def _publish_no_replace(source: Path, destination: Path) -> None:
    """Atomically publish a same-filesystem file without clobbering a target."""
    try:
        os.link(source, destination)
        source.unlink()
    except FileExistsError as exc:
        raise BackupError("destination_exists") from exc
    except OSError as exc:
        raise BackupError("atomic_no_replace_publish_unavailable") from exc


def _inspect(database: Path) -> dict[str, Any]:
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            check = db.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise BackupError("sqlite_integrity_check_failed")
            tables = sorted(row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ))
            version = db.execute("PRAGMA user_version").fetchone()[0]
            return {"integrity": check, "user_version": version, "tables": tables}
    except sqlite3.Error as exc:
        raise BackupError("sqlite_database_unreadable") from exc


def create_backup(source: Path, destination: Path) -> dict[str, Any]:
    """Create a new consistent snapshot and manifest; never overwrite."""
    source, destination = Path(source), Path(destination)
    if not source.is_file():
        raise BackupError("source_database_not_found")
    manifest_path = _manifest_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or manifest_path.exists():
        raise BackupError("backup_destination_exists")
    fd, temporary_name = tempfile.mkstemp(prefix=".nexora-backup-", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    temporary_manifest = temporary.with_name(temporary.name + MANIFEST_SUFFIX)
    published_database = False
    try:
        with sqlite3.connect(source, timeout=10) as src, sqlite3.connect(temporary) as dst:
            src.backup(dst, pages=256, sleep=0.01)
        inspected = _inspect(temporary)
        manifest = {
            "format_version": FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "sha256": _sha256(temporary),
            "bytes": temporary.stat().st_size,
            **inspected,
        }
        temporary_manifest.write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        os.chmod(temporary_manifest, 0o600)
        _publish_no_replace(temporary, destination)
        published_database = True
        _publish_no_replace(temporary_manifest, manifest_path)
        return manifest
    except Exception:
        temporary.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)
        if published_database and not manifest_path.exists():
            destination.unlink(missing_ok=True)
        raise


def verify_backup(backup: Path) -> dict[str, Any]:
    backup = Path(backup)
    manifest_path = _manifest_path(backup)
    if not backup.is_file() or not manifest_path.is_file():
        raise BackupError("backup_or_manifest_missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("backup_manifest_invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("format_version") != FORMAT_VERSION:
        raise BackupError("backup_format_unsupported")
    if manifest.get("sha256") != _sha256(backup):
        raise BackupError("backup_hash_mismatch")
    if manifest.get("bytes") != backup.stat().st_size:
        raise BackupError("backup_size_mismatch")
    actual = _inspect(backup)
    for key in ("integrity", "user_version", "tables"):
        if manifest.get(key) != actual[key]:
            raise BackupError("backup_manifest_metadata_mismatch")
    return {"valid": True, "sha256": manifest["sha256"], **actual}


def restore_backup(backup: Path, destination: Path) -> dict[str, Any]:
    """Restore a verified backup to a new path without replacing existing data."""
    backup, destination = Path(backup), Path(destination)
    verified = verify_backup(backup)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise BackupError("restore_destination_exists")
    fd, temporary_name = tempfile.mkstemp(prefix=".nexora-restore-", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with sqlite3.connect(f"file:{backup}?mode=ro", uri=True) as src, sqlite3.connect(temporary) as dst:
            src.backup(dst, pages=256, sleep=0.01)
        restored = _inspect(temporary)
        expected = {key: verified[key] for key in ("integrity", "user_version", "tables")}
        if restored != expected:
            raise BackupError("restored_database_validation_failed")
        os.chmod(temporary, 0o600)
        try:
            _publish_no_replace(temporary, destination)
        except BackupError as exc:
            if str(exc) == "destination_exists":
                raise BackupError("restore_destination_exists") from exc
            raise
        return {"restored": True, "destination": str(destination), **restored}
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
