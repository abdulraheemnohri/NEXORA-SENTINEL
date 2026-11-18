"""Consistent SQLite backup, verification and non-destructive restore."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

FORMAT_VERSION = 2
MANIFEST_SUFFIX = ".manifest.json"


class BackupError(RuntimeError):
    """Raised when a backup cannot be safely created, verified or restored."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def signing_key_fingerprint(signing_key: Ed25519PrivateKey | Path) -> str:
    """Return the public fingerprint for a private signing key without exposing key material."""
    return _fingerprint(_load_private(signing_key).public_key())


def _manifest_path(backup: Path) -> Path:
    return backup.with_name(backup.name + MANIFEST_SUFFIX)


def _load_private(key: Ed25519PrivateKey | Path) -> Ed25519PrivateKey:
    if isinstance(key, Ed25519PrivateKey):
        return key
    try:
        if os.name == "posix" and Path(key).stat().st_mode & 0o077:
            raise BackupError("backup_private_key_permissions_too_open")
        loaded = serialization.load_pem_private_key(Path(key).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise BackupError("backup_private_key_invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise BackupError("backup_ed25519_key_required")
    return loaded


def _load_public(key: Ed25519PublicKey | Path) -> Ed25519PublicKey:
    if isinstance(key, Ed25519PublicKey):
        return key
    try:
        loaded = serialization.load_pem_public_key(Path(key).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise BackupError("trusted_backup_public_key_invalid") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise BackupError("trusted_backup_ed25519_key_required")
    return loaded


def generate_backup_signing_key(private_path: Path, public_path: Path) -> str:
    """Create a non-overwriting Ed25519 key pair; public key is the trust anchor."""
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.exists() or public_path.exists():
        raise BackupError("backup_signing_key_exists")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_data = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_data = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    created_private = False
    try:
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created_private = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(private_data)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(public_data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if created_private:
            private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return _fingerprint(key.public_key())


def _publish_no_replace(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
        source.unlink()
    except FileExistsError as exc:
        raise BackupError("destination_exists") from exc
    except OSError as exc:
        raise BackupError("atomic_no_replace_publish_unavailable") from exc


def _set_delete_journal_mode(connection: sqlite3.Connection) -> None:
    """Publish portable standalone snapshots, not databases dependent on WAL sidecars."""
    try:
        mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
    except sqlite3.Error as exc:
        raise BackupError("sqlite_journal_mode_normalization_failed") from exc
    if str(mode).lower() != "delete":
        raise BackupError("sqlite_journal_mode_normalization_failed")


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


def create_backup(
    source: Path, destination: Path, *, signing_key: Ed25519PrivateKey | Path,
) -> dict[str, Any]:
    """Create a signed online snapshot. The caller controls the trusted private key."""
    source, destination = Path(source), Path(destination)
    if not source.is_file():
        raise BackupError("source_database_not_found")
    _inspect(source)
    signer = _load_private(signing_key)
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
            _set_delete_journal_mode(dst)
        manifest = {
            "format_version": FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "sha256": _sha256(temporary),
            "bytes": temporary.stat().st_size,
            **_inspect(temporary),
            "signer_fingerprint": _fingerprint(signer.public_key()),
        }
        manifest["signature"] = base64.b64encode(signer.sign(_canonical(manifest))).decode("ascii")
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


def verify_backup(
    backup: Path, *, trusted_public_key: Ed25519PublicKey | Path,
) -> dict[str, Any]:
    """Verify content, SQLite integrity and a signature against an external trust pin."""
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
    signature_text = manifest.pop("signature", None)
    if not isinstance(signature_text, str):
        raise BackupError("backup_signature_missing")
    public = _load_public(trusted_public_key)
    if manifest.get("signer_fingerprint") != _fingerprint(public):
        raise BackupError("backup_signer_not_trusted")
    try:
        public.verify(base64.b64decode(signature_text, validate=True), _canonical(manifest))
    except Exception as exc:
        raise BackupError("backup_signature_invalid") from exc
    if manifest.get("sha256") != _sha256(backup):
        raise BackupError("backup_hash_mismatch")
    if manifest.get("bytes") != backup.stat().st_size:
        raise BackupError("backup_size_mismatch")
    actual = _inspect(backup)
    for key in ("integrity", "user_version", "tables"):
        if manifest.get(key) != actual[key]:
            raise BackupError("backup_manifest_metadata_mismatch")
    return {
        "valid": True, "sha256": manifest["sha256"],
        "signer_fingerprint": manifest["signer_fingerprint"],
        "created_at": manifest.get("created_at"), **actual,
    }


def restore_backup(
    backup: Path, destination: Path, *, trusted_public_key: Ed25519PublicKey | Path,
) -> dict[str, Any]:
    """Restore a signature-verified backup to a new path without replacing data."""
    backup, destination = Path(backup), Path(destination)
    verified = verify_backup(backup, trusted_public_key=trusted_public_key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise BackupError("restore_destination_exists")
    fd, temporary_name = tempfile.mkstemp(prefix=".nexora-restore-", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with sqlite3.connect(f"file:{backup}?mode=ro", uri=True) as src, sqlite3.connect(temporary) as dst:
            src.backup(dst, pages=256, sleep=0.01)
            _set_delete_journal_mode(dst)
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
