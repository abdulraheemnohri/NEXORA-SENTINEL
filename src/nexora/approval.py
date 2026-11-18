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
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = 1
MAX_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 60


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


def generate_signing_key(private_path: Path, *, overwrite: bool = False) -> str:
    """Create an unencrypted PKCS8 Ed25519 key; caller must protect the file."""
    path = Path(private_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ApprovalError("private_key_already_exists")
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return public_key_fingerprint(key.public_key())


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a private key, refusing group/other-readable POSIX files."""
    key_path = Path(path)
    if os.name == "posix":
        mode = key_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ApprovalError("private_key_permissions_too_open")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
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
    if transition not in {"APPROVED", "ENABLED"}:
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
            ):
                if name not in columns:
                    db.execute(f"ALTER TABLE trusted_signing_keys ADD COLUMN {name} {definition}")

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def enroll_key(self, public_key: Ed25519PublicKey, *, label: str, now: int | None = None) -> str:
        if not isinstance(public_key, Ed25519PublicKey):
            raise ApprovalError("ed25519_public_key_required")
        if not isinstance(label, str) or not label.strip():
            raise ApprovalError("key_label_required")
        fingerprint = public_key_fingerprint(public_key)
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO trusted_signing_keys(fingerprint,public_key,label,active,enrolled_at) VALUES(?,?,?,1,?)",
                    (fingerprint, public_key_bytes(public_key), label.strip()[:256], int(time.time()) if now is None else int(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalError("signing_key_already_enrolled") from exc
        return fingerprint

    def list_keys(self, *, include_revoked: bool = True) -> list[dict[str, Any]]:
        """List public trust metadata only; never return private key material."""
        query = (
            "SELECT fingerprint,label,active,enrolled_at,revoked_at,revoked_reason,replaced_by "
            "FROM trusted_signing_keys"
        )
        if not include_revoked:
            query += " WHERE active=1"
        query += " ORDER BY enrolled_at,fingerprint"
        with self._connect() as db:
            return [dict(row) for row in db.execute(query).fetchall()]

    def rotate_key(
        self, old_fingerprint: str, new_public_key: Ed25519PublicKey,
        *, new_label: str, reason: str, now: int | None = None,
    ) -> str:
        """Atomically enroll replacement and revoke old key in one SQLite transaction."""
        if not isinstance(new_public_key, Ed25519PublicKey):
            raise ApprovalError("ed25519_public_key_required")
        if not isinstance(reason, str) or not reason.strip():
            raise ApprovalError("key_rotation_reason_required")
        if not isinstance(new_label, str) or not new_label.strip():
            raise ApprovalError("key_label_required")
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
                       (fingerprint,public_key,label,active,enrolled_at)
                       VALUES(?,?,?,1,?)""",
                    (new_fingerprint, public_key_bytes(new_public_key),
                     new_label.strip()[:256], timestamp),
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
                    "SELECT public_key FROM trusted_signing_keys WHERE fingerprint=? AND active=1",
                    (fingerprint,),
                ).fetchone()
                if row is None:
                    raise ApprovalError("signing_key_untrusted_or_revoked")
                key = Ed25519PublicKey.from_public_bytes(row[0])
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
