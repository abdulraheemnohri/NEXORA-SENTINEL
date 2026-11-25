"""Consistent SQLite backup, verification and non-destructive restore."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexora.file_lock import open_regular_file

FORMAT_VERSION = 2
MANIFEST_SUFFIX = ".manifest.json"


class BackupError(RuntimeError):
    """Raised when a backup cannot be safely created, verified or restored."""


@contextmanager
def _database_connection(database: str | Path, **kwargs: Any):
    """Provide transaction semantics and always close the underlying OS handle.

    sqlite3.Connection.__exit__ commits or rolls back; it does not close the
    connection. Explicit close is required before temporary files can be
    removed on Windows.
    """
    connection = sqlite3.connect(database, **kwargs)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


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


def _assert_path_matches_descriptor(
    path: Path, descriptor: int, error_code: str,
) -> None:
    """Require a pathname to still identify the already-open regular file."""
    try:
        current = Path(path).lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise BackupError(error_code) from exc
    if not stat.S_ISREG(current.st_mode) or (
        current.st_dev != opened.st_dev
        or (current.st_ino and opened.st_ino and current.st_ino != opened.st_ino)
    ):
        raise BackupError(error_code)


def _path_occupied(path: Path) -> bool:
    """Detect every existing leaf, including dangling symlinks."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _sha256_descriptor(descriptor: int) -> str:
    """Hash an already-open descriptor without reopening its pathname."""
    digest = hashlib.sha256()
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.lseek(descriptor, position, os.SEEK_SET)
    return digest.hexdigest()


def _unlink_if_same_file(path: Path, descriptor: int) -> None:
    """Remove a published leaf only while it still names our open inode."""
    try:
        current = path.lstat()
        opened = os.fstat(descriptor)
    except OSError:
        return
    if (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == opened.st_dev
        and (not current.st_ino or not opened.st_ino or current.st_ino == opened.st_ino)
    ):
        path.unlink(missing_ok=True)


def _inspect(database: Path) -> dict[str, Any]:
    try:
        with _database_connection(f"file:{database}?mode=ro", uri=True) as db:
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
    """Create a signed online snapshot using checked source and private staging files."""
    source, destination = Path(source), Path(destination)
    manifest_path = _manifest_path(destination)
    source_fd: int | None = None
    database_fd: int | None = None
    manifest_fd: int | None = None
    staging_dir: Path | None = None
    published_database = False
    published_manifest = False
    succeeded = False

    try:
        try:
            source_fd = open_regular_file(source, os.O_RDONLY)
        except FileNotFoundError as exc:
            raise BackupError("source_database_not_found") from exc
        except OSError as exc:
            raise BackupError("source_database_unsafe") from exc

        _assert_path_matches_descriptor(source, source_fd, "source_database_changed")
        _inspect(source)
        _assert_path_matches_descriptor(source, source_fd, "source_database_changed")
        signer = _load_private(signing_key)

        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            parent_stat = destination.parent.lstat()
        except OSError as exc:
            raise BackupError("backup_destination_parent_unsafe") from exc
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise BackupError("backup_destination_parent_unsafe")
        if _path_occupied(destination) or _path_occupied(manifest_path):
            raise BackupError("backup_destination_exists")

        # mkdtemp creates a private staging directory (0700 on POSIX).
        staging_dir = Path(tempfile.mkdtemp(
            prefix=".nexora-backup-stage-", dir=destination.parent,
        ))
        temporary = staging_dir / "database.sqlite3"
        temporary_manifest = staging_dir / "manifest.json"

        database_flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            database_flags |= os.O_NOFOLLOW
        database_fd = os.open(temporary, database_flags, 0o600)
        _assert_path_matches_descriptor(
            temporary, database_fd, "backup_temporary_database_changed",
        )

        # The stdlib sqlite3 API accepts paths rather than existing file
        # descriptors. Keep a checked source descriptor open and verify its
        # identity immediately before/after each SQLite pathname operation.
        source_uri = f"file:{source}?mode=ro"
        with _database_connection(source_uri, timeout=10, uri=True) as src, (
            _database_connection(temporary, timeout=10) as dst
        ):
            _assert_path_matches_descriptor(
                source, source_fd, "source_database_changed",
            )
            src.backup(dst, pages=256, sleep=0.01)
            _set_delete_journal_mode(dst)

        _assert_path_matches_descriptor(source, source_fd, "source_database_changed")
        _assert_path_matches_descriptor(
            temporary, database_fd, "backup_temporary_database_changed",
        )
        os.fsync(database_fd)
        if hasattr(os, "fchmod"):
            os.fchmod(database_fd, 0o600)
        else:
            os.chmod(temporary, 0o600)

        digest = _sha256_descriptor(database_fd)
        byte_count = os.fstat(database_fd).st_size
        snapshot_metadata = _inspect(temporary)
        _assert_path_matches_descriptor(
            temporary, database_fd, "backup_temporary_database_changed",
        )
        manifest = {
            "format_version": FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "sha256": digest,
            "bytes": byte_count,
            **snapshot_metadata,
            "signer_fingerprint": _fingerprint(signer.public_key()),
        }
        manifest["signature"] = base64.b64encode(
            signer.sign(_canonical(manifest))
        ).decode("ascii")

        manifest_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            manifest_flags |= os.O_NOFOLLOW
        manifest_fd = os.open(temporary_manifest, manifest_flags, 0o600)
        with os.fdopen(os.dup(manifest_fd), "w", encoding="utf-8") as stream:
            stream.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        _assert_path_matches_descriptor(
            temporary_manifest, manifest_fd, "backup_temporary_manifest_changed",
        )
        _assert_path_matches_descriptor(
            temporary, database_fd, "backup_temporary_database_changed",
        )
        _publish_no_replace(temporary, destination)
        published_database = True
        _assert_path_matches_descriptor(
            destination, database_fd, "backup_published_database_changed",
        )
        _publish_no_replace(temporary_manifest, manifest_path)
        published_manifest = True
        _assert_path_matches_descriptor(
            manifest_path, manifest_fd, "backup_published_manifest_changed",
        )
        succeeded = True
        return manifest
    except (OSError, sqlite3.Error) as exc:
        raise BackupError("backup_creation_failed") from exc
    finally:
        if not succeeded:
            if published_manifest and manifest_fd is not None:
                _unlink_if_same_file(manifest_path, manifest_fd)
            if published_database and database_fd is not None:
                _unlink_if_same_file(destination, database_fd)
        for descriptor in (manifest_fd, database_fd, source_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)


@contextmanager
def _verified_backup_snapshot(
    backup: Path, *, trusted_public_key: Ed25519PublicKey | Path,
):
    """Yield one private, verified snapshot for both validation and restore.

    The backup and manifest are opened as checked regular files. The database
    bytes are copied from that already-open descriptor into a private temporary
    file, then the signed digest, byte count and SQLite metadata are verified
    against that copy. Callers consume this exact snapshot; they never reopen
    the original backup pathname after verification.
    """
    backup = Path(backup)
    manifest_path = _manifest_path(backup)
    manifest_fd: int | None = None
    backup_fd: int | None = None
    snapshot_fd: int | None = None
    snapshot: Path | None = None

    try:
        try:
            manifest_fd = open_regular_file(manifest_path, os.O_RDONLY)
            backup_fd = open_regular_file(backup, os.O_RDONLY)
        except FileNotFoundError as exc:
            raise BackupError("backup_or_manifest_missing") from exc
        except OSError as exc:
            raise BackupError("backup_or_manifest_unsafe") from exc

        manifest_stream = os.fdopen(manifest_fd, "r", encoding="utf-8")
        manifest_fd = None
        with manifest_stream as stream:
            if os.fstat(stream.fileno()).st_size > 1024 * 1024:
                raise BackupError("backup_manifest_too_large")
            try:
                manifest_text = stream.read(1024 * 1024 + 1)
                if len(manifest_text.encode("utf-8")) > 1024 * 1024:
                    raise BackupError("backup_manifest_too_large")
                manifest = json.loads(manifest_text)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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

        snapshot_fd, snapshot_name = tempfile.mkstemp(
            prefix=".nexora-verified-backup-", suffix=".sqlite3",
        )
        snapshot = Path(snapshot_name)
        source_stream = os.fdopen(backup_fd, "rb")
        backup_fd = None
        with source_stream as source:
            snapshot_stream = os.fdopen(snapshot_fd, "wb")
            snapshot_fd = None
            with snapshot_stream as destination:
                digest = hashlib.sha256()
                byte_count = 0
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    byte_count += len(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())

        if not isinstance(manifest.get("sha256"), str) or manifest["sha256"] != digest.hexdigest():
            raise BackupError("backup_hash_mismatch")
        if type(manifest.get("bytes")) is not int or manifest["bytes"] != byte_count:
            raise BackupError("backup_size_mismatch")

        actual = _inspect(snapshot)
        for key in ("integrity", "user_version", "tables"):
            if manifest.get(key) != actual[key]:
                raise BackupError("backup_manifest_metadata_mismatch")
        verified = {
            "valid": True,
            "sha256": manifest["sha256"],
            "signer_fingerprint": manifest["signer_fingerprint"],
            "created_at": manifest.get("created_at"),
            **actual,
        }
    except BackupError:
        if snapshot is not None:
            snapshot.unlink(missing_ok=True)
        raise
    except (OSError, sqlite3.Error, UnicodeError) as exc:
        if snapshot is not None:
            snapshot.unlink(missing_ok=True)
        raise BackupError("backup_snapshot_unreadable") from exc
    except Exception:
        if snapshot is not None:
            snapshot.unlink(missing_ok=True)
        raise
    finally:
        for descriptor in (manifest_fd, backup_fd, snapshot_fd):
            if descriptor is not None:
                os.close(descriptor)

    try:
        yield snapshot, verified
    finally:
        if snapshot is not None:
            snapshot.unlink(missing_ok=True)


def verify_backup(
    backup: Path, *, trusted_public_key: Ed25519PublicKey | Path,
) -> dict[str, Any]:
    """Verify a signed backup using one checked, private database snapshot."""
    with _verified_backup_snapshot(
        backup, trusted_public_key=trusted_public_key,
    ) as (_, verified):
        return verified


def restore_backup(
    backup: Path, destination: Path, *, trusted_public_key: Ed25519PublicKey | Path,
) -> dict[str, Any]:
    """Restore from the exact verified snapshot without replacing existing data."""
    destination = Path(destination)
    with _verified_backup_snapshot(
        backup, trusted_public_key=trusted_public_key,
    ) as (verified_snapshot, verified):
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise BackupError("restore_destination_exists")

        fd, temporary_name = tempfile.mkstemp(
            prefix=".nexora-restore-", dir=destination.parent,
        )
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with _database_connection(
                f"file:{verified_snapshot}?mode=ro", uri=True,
            ) as src, _database_connection(temporary) as dst:
                src.backup(dst, pages=256, sleep=0.01)
                _set_delete_journal_mode(dst)
            restored = _inspect(temporary)
            expected = {
                key: verified[key] for key in ("integrity", "user_version", "tables")
            }
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
