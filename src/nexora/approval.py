"""Ed25519 approval receipts with explicit trust pinning and replay protection.

A signature proves possession of a pinned key, not the real-world identity of its holder.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from nexora.file_lock import open_regular_file

SCHEMA_VERSION = 1
MAX_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 60
DEFAULT_KEY_LIFETIME_DAYS = 365
MAX_KEY_LIFETIME_DAYS = 730
MAX_APPROVAL_KEY_FILE_BYTES = 64 * 1024


class ApprovalError(RuntimeError):
    """Raised when an approval receipt or signing key is invalid."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _evidence_digest(evidence: list[str] | tuple[str, ...] | set[str]) -> str:
    if isinstance(evidence, str):
        raise ApprovalError("evidence_must_be_a_collection")
    values = sorted({item.strip() for item in evidence if isinstance(item, str) and item.strip()})
    if not values:
        raise ApprovalError("nonempty_evidence_required")
    return hashlib.sha256(_canonical({"evidence": values})).hexdigest()


def _ensure_key_output_absent(path: Path) -> None:
    """Reject every existing leaf, including dangling symlinks, without following it."""
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ApprovalError("key_output_path_invalid") from exc
    raise ApprovalError("key_output_already_exists")


def _assert_key_output_identity(path: Path, descriptor: int) -> None:
    """Reject an observed replacement of a key output while it was written."""
    try:
        current = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ApprovalError("key_output_path_changed") from exc
    same_identity = (
        current.st_dev == opened.st_dev
        and (
            not current.st_ino
            or not opened.st_ino
            or current.st_ino == opened.st_ino
        )
    )
    if (
        not stat.S_ISREG(current.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or not same_identity
    ):
        raise ApprovalError("key_output_path_changed")


def _write_new_key_file(path: Path, data: bytes, *, mode: int) -> None:
    """Exclusively create and write a key file through one checked descriptor.

    Failed writes are deliberately not cleaned up by pathname: a path may have
    been replaced after open, and unlink-by-name could delete that replacement.
    An incomplete output is left in place for explicit operator inspection.
    """
    try:
        descriptor = open_regular_file(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode,
        )
    except FileExistsError as exc:
        raise ApprovalError("key_output_already_exists") from exc
    except (OSError, ValueError) as exc:
        raise ApprovalError("key_output_path_invalid") from exc

    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("key file write made no progress")
            remaining = remaining[written:]
        if os.name == "posix" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        _assert_key_output_identity(path, descriptor)
    except ApprovalError:
        raise
    except OSError as exc:
        raise ApprovalError("key_output_write_failed") from exc
    finally:
        os.close(descriptor)


def generate_signing_key(private_path: Path, *, overwrite: bool = False) -> str:
    """Create a new unencrypted PKCS8 Ed25519 key without replacing any file.

    The overwrite flag is retained for API compatibility but is rejected. Use
    a new key path and the audited trust-rotation process instead of replacing
    a key in place.
    """
    if overwrite:
        raise ApprovalError("key_overwrite_disabled_use_new_path")
    path = Path(private_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_key_output_absent(path)
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_new_key_file(path, data, mode=0o600)
    return public_key_fingerprint(key.public_key())


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Generate a dedicated keypair using exclusive descriptor-bound outputs.

    The public file is published first. If a later private-file write fails,
    an orphaned public file may remain; it is harmless and is not removed by a
    pathname cleanup that could race with an unrelated replacement.
    """
    private_destination = Path(private_path)
    public_destination = Path(public_path)
    private_name = os.path.normcase(
        os.path.abspath(os.path.normpath(os.fspath(private_destination)))
    )
    public_name = os.path.normcase(
        os.path.abspath(os.path.normpath(os.fspath(public_destination)))
    )
    if private_name == public_name:
        raise ApprovalError("key_paths_must_be_different")

    private_destination.parent.mkdir(parents=True, exist_ok=True)
    public_destination.parent.mkdir(parents=True, exist_ok=True)
    _ensure_key_output_absent(private_destination)
    _ensure_key_output_absent(public_destination)

    key = Ed25519PrivateKey.generate()
    private_data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_data = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Publish the non-secret half first so a collision cannot leave an orphaned
    # private key behind. Both files are independently created without replace.
    _write_new_key_file(public_destination, public_data, mode=0o644)
    _write_new_key_file(private_destination, private_data, mode=0o600)
    return public_key_fingerprint(key.public_key())


def _read_key_file(path: Path, *, private: bool) -> bytes:
    """Read bounded key material from one checked descriptor.

    The descriptor remains authoritative for the read. A final identity and
    metadata check rejects observed path replacement or in-place modification.
    """
    key_path = Path(path)
    kind = "private" if private else "public"
    try:
        descriptor = open_regular_file(key_path, os.O_RDONLY)
    except (OSError, ValueError) as exc:
        raise ApprovalError(f"{kind}_key_unreadable_or_invalid") from exc

    try:
        before = os.fstat(descriptor)
        if private and os.name == "posix" and before.st_mode & 0o077:
            raise ApprovalError("private_key_permissions_too_open")
        if before.st_size > MAX_APPROVAL_KEY_FILE_BYTES:
            raise ApprovalError(f"{kind}_key_file_too_large")

        content = bytearray()
        while len(content) <= MAX_APPROVAL_KEY_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_APPROVAL_KEY_FILE_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_APPROVAL_KEY_FILE_BYTES:
            raise ApprovalError(f"{kind}_key_file_too_large")

        after = os.fstat(descriptor)
        same_inode = (
            before.st_dev == after.st_dev
            and (
                not before.st_ino
                or not after.st_ino
                or before.st_ino == after.st_ino
            )
        )
        unchanged = (
            same_inode
            and before.st_size == after.st_size
            and before.st_mode == after.st_mode
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
        )
        if not unchanged:
            raise ApprovalError(f"{kind}_key_changed_during_read")

        try:
            current = key_path.lstat()
        except OSError as exc:
            raise ApprovalError(f"{kind}_key_path_changed") from exc
        path_matches = (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == after.st_dev
            and (
                not current.st_ino
                or not after.st_ino
                or current.st_ino == after.st_ino
            )
        )
        if not path_matches:
            raise ApprovalError(f"{kind}_key_path_changed")
        return bytes(content)
    except ApprovalError:
        raise
    except OSError as exc:
        raise ApprovalError(f"{kind}_key_unreadable_or_invalid") from exc
    finally:
        os.close(descriptor)


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(_read_key_file(path, private=False))
    except (ValueError, TypeError) as exc:
        raise ApprovalError("public_key_unreadable_or_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ApprovalError("ed25519_public_key_required")
    return key


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a private key from a checked descriptor with restrictive POSIX permissions."""
    try:
        key = serialization.load_pem_private_key(
            _read_key_file(path, private=True),
            password=None,
        )
    except (ValueError, TypeError) as exc:
        raise ApprovalError("private_key_unreadable_or_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApprovalError("ed25519_private_key_required")
    return key

def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key_bytes(key)).hexdigest()


def create_receipt(
    private_key: Ed25519PrivateKey,
    *,
    capability_id: int,
    transition: str,
    evidence: list[str] | tuple[str, ...] | set[str],
    approver_id: str,
    ttl_seconds: int = MAX_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(capability_id, int) or isinstance(capability_id, bool) or not 1 <= capability_id <= 264:
        raise ApprovalError("capability_id_out_of_range")
    if transition not in {"APPROVED", "ENABLED", "REVOKE", "ROLLBACK"}:
        raise ApprovalError("unsupported_approval_transition")
    if not isinstance(approver_id, str) or not approver_id.strip():
        raise ApprovalError("approver_id_required")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ApprovalError("receipt_ttl_out_of_range")
    issued = int(time.time()) if now is None else int(now)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "capability_id": capability_id,
        "transition": transition,
        "evidence_sha256": _evidence_digest(evidence),
        "approver_id": approver_id.strip()[:256],
        "issued_at": issued,
        "expires_at": issued + ttl_seconds,
        "nonce": secrets.token_urlsafe(24),
        "key_fingerprint": public_key_fingerprint(private_key.public_key()),
    }
    signature = private_key.sign(_canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


class ApprovalReceiptStore:
    """SQLite trust pins and one-time receipt consumption; no key is trusted implicitly."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS trusted_signing_keys (
                    fingerprint TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    label TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    enrolled_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consumed_approval_receipts (
                    nonce TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    capability_id INTEGER NOT NULL,
                    transition TEXT NOT NULL,
                    consumed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS signing_key_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL CHECK(event_type IN ('ENROLLED','ROTATED','REVOKED')),
                    fingerprint TEXT NOT NULL,
                    related_fingerprint TEXT,
                    reason TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS signing_key_events_no_update
                BEFORE UPDATE ON signing_key_events BEGIN
                    SELECT RAISE(ABORT, 'signing key history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS signing_key_events_no_delete
                BEFORE DELETE ON signing_key_events BEGIN
                    SELECT RAISE(ABORT, 'signing key history is append-only');
                END;
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(trusted_signing_keys)")}
            for name, definition in (
                ("revoked_at", "INTEGER"),
                ("revoked_reason", "TEXT"),
                ("replaced_by", "TEXT"),
                ("expires_at", "INTEGER"),
            ):
                if name not in columns:
                    db.execute(f"ALTER TABLE trusted_signing_keys ADD COLUMN {name} {definition}")
            db.execute(
                "UPDATE trusted_signing_keys SET expires_at=enrolled_at+? WHERE expires_at IS NULL",
                (DEFAULT_KEY_LIFETIME_DAYS * 86400,),
            )

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def enroll_key(
        self, public_key: Ed25519PublicKey, *, label: str,
        validity_days: int = DEFAULT_KEY_LIFETIME_DAYS, now: int | None = None,
    ) -> str:
        if not isinstance(public_key, Ed25519PublicKey):
            raise ApprovalError("ed25519_public_key_required")
        if not isinstance(label, str) or not label.strip():
            raise ApprovalError("key_label_required")
        if type(validity_days) is not int or not 1 <= validity_days <= MAX_KEY_LIFETIME_DAYS:
            raise ApprovalError("key_validity_days_out_of_range")
        fingerprint = public_key_fingerprint(public_key)
        with self._connect() as db:
            try:
                timestamp = int(time.time()) if now is None else int(now)
                expires_at = timestamp + validity_days * 86400
                db.execute(
                    "INSERT INTO trusted_signing_keys(fingerprint,public_key,label,active,enrolled_at,expires_at) VALUES(?,?,?,1,?,?)",
                    (fingerprint, public_key_bytes(public_key), label.strip()[:256], timestamp, expires_at),
                )
                db.execute(
                    """INSERT INTO signing_key_events
                       (event_type,fingerprint,related_fingerprint,reason,created_at)
                       VALUES('ENROLLED',?,NULL,?,?)""",
                    (fingerprint, "initial_trust_enrollment", timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalError("signing_key_already_enrolled") from exc
        return fingerprint

    def list_keys(self, *, include_revoked: bool = True) -> list[dict[str, Any]]:
        """List public trust metadata only; never return private key material."""
        query = (
            "SELECT fingerprint,label,active,enrolled_at,expires_at,revoked_at,revoked_reason,replaced_by "
            "FROM trusted_signing_keys"
        )
        if not include_revoked:
            query += " WHERE active=1"
        query += " ORDER BY enrolled_at,fingerprint"
        with self._connect() as db:
            return [dict(row) for row in db.execute(query).fetchall()]

    def rotate_key(
        self, old_fingerprint: str, new_public_key: Ed25519PublicKey,
        *, new_label: str, reason: str,
        validity_days: int = DEFAULT_KEY_LIFETIME_DAYS, now: int | None = None,
    ) -> str:
        """Atomically enroll replacement and revoke old key in one SQLite transaction."""
        if not isinstance(new_public_key, Ed25519PublicKey):
            raise ApprovalError("ed25519_public_key_required")
        if not isinstance(reason, str) or not reason.strip():
            raise ApprovalError("key_rotation_reason_required")
        if not isinstance(new_label, str) or not new_label.strip():
            raise ApprovalError("key_label_required")
        if type(validity_days) is not int or not 1 <= validity_days <= MAX_KEY_LIFETIME_DAYS:
            raise ApprovalError("key_validity_days_out_of_range")
        new_fingerprint = public_key_fingerprint(new_public_key)
        if new_fingerprint == old_fingerprint:
            raise ApprovalError("replacement_key_must_differ")
        timestamp = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT active FROM trusted_signing_keys WHERE fingerprint=?",
                (old_fingerprint,),
            ).fetchone()
            if old is None or old["active"] != 1:
                raise ApprovalError("active_signing_key_not_found")
            try:
                db.execute(
                    """INSERT INTO trusted_signing_keys
                       (fingerprint,public_key,label,active,enrolled_at,expires_at)
                       VALUES(?,?,?,1,?,?)""",
                    (new_fingerprint, public_key_bytes(new_public_key),
                     new_label.strip()[:256], timestamp, timestamp + validity_days * 86400),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalError("replacement_key_already_enrolled") from exc
            cursor = db.execute(
                """UPDATE trusted_signing_keys
                   SET active=0,revoked_at=?,revoked_reason=?,replaced_by=?
                   WHERE fingerprint=? AND active=1""",
                (timestamp, reason.strip()[:1000], new_fingerprint, old_fingerprint),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("active_signing_key_not_found")
            db.execute(
                """INSERT INTO signing_key_events
                   (event_type,fingerprint,related_fingerprint,reason,created_at)
                   VALUES('ROTATED',?,?,?,?)""",
                (old_fingerprint, new_fingerprint, reason.strip()[:1000], timestamp),
            )
        return new_fingerprint

    def revoke_key(self, fingerprint: str, *, reason: str = "operator_revocation") -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise ApprovalError("key_revocation_reason_required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE trusted_signing_keys
                   SET active=0,revoked_at=?,revoked_reason=?
                   WHERE fingerprint=? AND active=1""",
                (int(time.time()), reason.strip()[:1000], fingerprint),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("active_signing_key_not_found")
            db.execute(
                """INSERT INTO signing_key_events
                   (event_type,fingerprint,related_fingerprint,reason,created_at)
                   VALUES('REVOKED',?,NULL,?,?)""",
                (fingerprint, reason.strip()[:1000], int(time.time())),
            )

    def key_history(self, fingerprint: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as db:
            if fingerprint is None:
                rows = db.execute(
                    "SELECT * FROM signing_key_events ORDER BY event_id"
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM signing_key_events
                       WHERE fingerprint=? OR related_fingerprint=? ORDER BY event_id""",
                    (fingerprint, fingerprint),
                ).fetchall()
        return [dict(row) for row in rows]

        with self._connect() as db:
            cursor = db.execute(
                "UPDATE trusted_signing_keys SET active=0 WHERE fingerprint=? AND active=1",
                (fingerprint,),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("active_signing_key_not_found")

    def verify_and_consume_many(
        self,
        receipts: list[dict[str, Any]],
        *,
        capability_id: int,
        transition: str,
        evidence: list[str] | tuple[str, ...] | set[str],
        approver_ids: list[str],
        now: int | None = None,
        connection: sqlite3.Connection | None = None,
        minimum_approvals: int = 2,
        maximum_approvals: int = 5,
    ) -> list[dict[str, Any]]:
        """Verify distinct approvers and consume every receipt atomically."""
        if not isinstance(receipts, list) or not isinstance(approver_ids, list):
            raise ApprovalError("multi_approval_inputs_must_be_lists")
        if not isinstance(minimum_approvals, int) or not 2 <= minimum_approvals <= maximum_approvals <= 5:
            raise ApprovalError("multi_approval_threshold_invalid")
        if not minimum_approvals <= len(receipts) <= maximum_approvals:
            raise ApprovalError("multi_approval_threshold_not_met")
        if len(receipts) != len(approver_ids):
            raise ApprovalError("multi_approval_identity_count_mismatch")
        if any(not isinstance(item, str) or not item.strip() for item in approver_ids):
            raise ApprovalError("multi_approval_identity_required")
        normalized_ids = [item.strip() for item in approver_ids]
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ApprovalError("distinct_approvers_required")
        manager = self._connect() if connection is None else nullcontext(connection)
        with manager as db:
            if connection is None:
                db.execute("BEGIN IMMEDIATE")
            payloads = []
            fingerprints = set()
            for receipt, approver_id in zip(receipts, normalized_ids):
                payload = self.verify_and_consume(
                    receipt,
                    capability_id=capability_id,
                    transition=transition,
                    evidence=evidence,
                    approver_id=approver_id,
                    now=now,
                    connection=db,
                )
                fingerprint = payload["key_fingerprint"]
                if fingerprint in fingerprints:
                    raise ApprovalError("independent_signing_keys_required")
                fingerprints.add(fingerprint)
                payloads.append(payload)
        return payloads

    def verify_and_consume(
        self,
        receipt: dict[str, Any],
        *,
        capability_id: int,
        transition: str,
        evidence: list[str] | tuple[str, ...] | set[str],
        approver_id: str,
        now: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        try:
            payload = receipt["payload"]
            signature = base64.b64decode(receipt["signature"], validate=True)
            expected_fields = {
                "schema_version", "capability_id", "transition", "evidence_sha256",
                "approver_id", "issued_at", "expires_at", "nonce", "key_fingerprint",
            }
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                raise ApprovalError("receipt_payload_schema_invalid")
            if payload["schema_version"] != SCHEMA_VERSION:
                raise ApprovalError("receipt_schema_version_unsupported")
            if payload["capability_id"] != capability_id or payload["transition"] != transition:
                raise ApprovalError("receipt_scope_mismatch")
            if payload["approver_id"] != approver_id:
                raise ApprovalError("receipt_approver_mismatch")
            if payload["evidence_sha256"] != _evidence_digest(evidence):
                raise ApprovalError("receipt_evidence_mismatch")
            if not isinstance(payload["nonce"], str) or not payload["nonce"]:
                raise ApprovalError("receipt_nonce_invalid")
            issued, expires = payload["issued_at"], payload["expires_at"]
            if type(issued) is not int or type(expires) is not int or expires <= issued:
                raise ApprovalError("receipt_time_invalid")
            current = int(time.time()) if now is None else int(now)
            if issued > current + CLOCK_SKEW_SECONDS:
                raise ApprovalError("receipt_issued_in_future")
            if expires < current:
                raise ApprovalError("receipt_expired")
            if expires - issued > MAX_TTL_SECONDS:
                raise ApprovalError("receipt_ttl_exceeds_policy")
            fingerprint = payload["key_fingerprint"]
            manager = self._connect() if connection is None else nullcontext(connection)
            with manager as db:
                row = db.execute(
                    "SELECT public_key,expires_at FROM trusted_signing_keys WHERE fingerprint=? AND active=1",
                    (fingerprint,),
                ).fetchone()
                if row is None:
                    raise ApprovalError("signing_key_untrusted_or_revoked")
                if row["expires_at"] is None or current >= row["expires_at"]:
                    raise ApprovalError("signing_key_expired")
                key = Ed25519PublicKey.from_public_bytes(row["public_key"])
                if public_key_fingerprint(key) != fingerprint:
                    raise ApprovalError("trusted_key_fingerprint_corrupt")
                try:
                    key.verify(signature, _canonical(payload))
                except Exception as exc:
                    raise ApprovalError("receipt_signature_invalid") from exc
                if connection is None:
                    db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO consumed_approval_receipts(nonce,fingerprint,capability_id,transition,consumed_at) VALUES(?,?,?,?,?)",
                        (payload["nonce"], fingerprint, capability_id, transition, current),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ApprovalError("receipt_replay_denied") from exc
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ApprovalError):
                raise
            raise ApprovalError("receipt_format_invalid") from exc
        return dict(payload)
