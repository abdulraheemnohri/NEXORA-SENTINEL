"""Read-only inventory and integrity assessment for one backup directory."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexora.backup import MANIFEST_SUFFIX, BackupError, verify_backup


class BackupInventoryError(ValueError):
    """Raised when an inventory scope cannot be safely inspected."""


def build_backup_inventory(directory: Path, *, trusted_public_key: Path | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Inspect direct children only; never create, modify, delete, or restore files."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise BackupInventoryError("backup_inventory_directory_not_found_or_unsafe")
    root = root.resolve(strict=True)
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise BackupInventoryError("inventory_clock_must_be_timezone_aware")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_symlink():
            entries.append({"name": path.name, "status": "UNSAFE_SYMLINK", "action": "manual_review"})
            continue
        if not path.is_file():
            continue
        if path.name.endswith(MANIFEST_SUFFIX):
            backup = path.with_name(path.name[:-len(MANIFEST_SUFFIX)])
            if backup.is_file() and not backup.is_symlink():
                continue
            entries.append({"name": path.name, "status": "ORPHAN_MANIFEST", "bytes": path.stat().st_size, "action": "preserve_and_review"})
            continue
        if not path.name.endswith((".sqlite3", ".db")):
            continue
        manifest = path.with_name(path.name + MANIFEST_SUFFIX)
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, UTC)
        row: dict[str, Any] = {"name": path.name, "bytes": stat.st_size, "modified_at": modified.isoformat(), "age_seconds": max(0, int((instant - modified).total_seconds()))}
        if not manifest.is_file() or manifest.is_symlink():
            row.update(status="ORPHAN_DATABASE", action="preserve_and_review")
        elif trusted_public_key is None:
            row.update(status="TRUST_ANCHOR_REQUIRED", action="verify_with_independent_key")
        else:
            try:
                verified = verify_backup(path, trusted_public_key=trusted_public_key)
            except (BackupError, OSError, ValueError) as exc:
                row.update(status="INVALID", reason=str(exc)[:160], action="preserve_and_review")
            else:
                row.update(status="VALID", sha256=verified["sha256"], signer_fingerprint=verified["signer_fingerprint"], created_at=verified.get("created_at"), user_version=verified["user_version"], table_count=len(verified["tables"]), action="eligible_for_recovery_simulation")
        entries.append(row)
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {"read_only": True, "scope": str(root), "trusted_key_supplied": trusted_public_key is not None, "entry_count": len(entries), "counts": counts, "entries": entries, "policy": {"automatic_restore": False, "automatic_delete": False, "retention_deletion": False, "live_database_replacement": False}}

__all__ = ["BackupInventoryError", "build_backup_inventory"]
