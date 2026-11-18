"""Emergency approval-key recovery using independently pinned recovery authorities.

Recovery authorizations are short-lived, operation-bound and single-use. This
module never stores private key material and never grants a recovery authority
the ability to approve ordinary capability transitions.
"""
from __future__ import annotations

import base64
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexora.approval import (
    DEFAULT_KEY_LIFETIME_DAYS,
    MAX_KEY_LIFETIME_DAYS,
    public_key_bytes,
    public_key_fingerprint,
)

RECOVERY_TTL_SECONDS = 600
RECOVERY_CLOCK_SKEW_SECONDS = 60
MIN_RECOVERY_AUTHORITIES = 2
MAX_RECOVERY_AUTHORITIES = 3


class EmergencyRecoveryError(RuntimeError):
    """Raised when an emergency key recovery is invalid or unsafe."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_recovery_authorization(
    private_key: Ed25519PrivateKey,
    *,
    authority_id: str,
    old_fingerprint: str,
    new_public_key: Ed25519PublicKey,
    new_label: str,
    reason: str,
    ttl_seconds: int = RECOVERY_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(authority_id, str) or not authority_id.strip():
        raise EmergencyRecoveryError("recovery_authority_id_required")
    if not isinstance(old_fingerprint, str) or len(old_fingerprint) != 64:
        raise EmergencyRecoveryError("old_fingerprint_invalid")
    if not isinstance(new_public_key, Ed25519PublicKey):
        raise EmergencyRecoveryError("replacement_ed25519_key_required")
    if not isinstance(new_label, str) or not new_label.strip():
        raise EmergencyRecoveryError("replacement_key_label_required")
    if not isinstance(reason, str) or not reason.strip():
        raise EmergencyRecoveryError("recovery_reason_required")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= RECOVERY_TTL_SECONDS:
        raise EmergencyRecoveryError("recovery_authorization_ttl_out_of_range")
    issued = int(time.time()) if now is None else int(now)
    replacement_pem = new_public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    payload = {
        "schema_version": 1,
        "action": "REPLACE_APPROVAL_KEY",
        "authority_id": authority_id.strip()[:256],
        "authority_fingerprint": public_key_fingerprint(private_key.public_key()),
        "old_fingerprint": old_fingerprint,
        "new_fingerprint": public_key_fingerprint(new_public_key),
        "new_public_key_pem": replacement_pem,
        "new_label": new_label.strip()[:256],
        "reason": reason.strip()[:1000],
        "issued_at": issued,
        "expires_at": issued + ttl_seconds,
        "nonce": secrets.token_urlsafe(24),
    }
    signature = private_key.sign(_canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


class EmergencyRecoveryStore:
    """Separate recovery-authority trust domain sharing the approval SQLite database."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS recovery_authorities (
                    fingerprint TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    authority_id TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    enrolled_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    revoked_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS consumed_recovery_authorizations (
                    nonce TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    consumed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS emergency_recovery_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL CHECK(event_type IN ('AUTHORITY_ENROLLED','AUTHORITY_REVOKED','KEY_RECOVERED')),
                    authority_fingerprint TEXT,
                    old_fingerprint TEXT,
                    new_fingerprint TEXT,
                    detail TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS emergency_recovery_events_no_update
                BEFORE UPDATE ON emergency_recovery_events BEGIN
                    SELECT RAISE(ABORT, 'emergency recovery history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS emergency_recovery_events_no_delete
                BEFORE DELETE ON emergency_recovery_events BEGIN
                    SELECT RAISE(ABORT, 'emergency recovery history is append-only');
                END;
            """)

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def enroll_authority(
        self,
        public_key: Ed25519PublicKey,
        *,
        authority_id: str,
        label: str,
        validity_days: int = DEFAULT_KEY_LIFETIME_DAYS,
        now: int | None = None,
    ) -> str:
        if not isinstance(public_key, Ed25519PublicKey):
            raise EmergencyRecoveryError("recovery_ed25519_key_required")
        if not isinstance(authority_id, str) or not authority_id.strip():
            raise EmergencyRecoveryError("recovery_authority_id_required")
        if not isinstance(label, str) or not label.strip():
            raise EmergencyRecoveryError("recovery_authority_label_required")
        if type(validity_days) is not int or not 1 <= validity_days <= MAX_KEY_LIFETIME_DAYS:
            raise EmergencyRecoveryError("recovery_authority_validity_out_of_range")
        fingerprint = public_key_fingerprint(public_key)
        timestamp = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            try:
                db.execute(
                    """INSERT INTO recovery_authorities
                       (fingerprint,public_key,authority_id,label,active,enrolled_at,expires_at)
                       VALUES(?,?,?,?,1,?,?)""",
                    (fingerprint, public_key_bytes(public_key), authority_id.strip()[:256],
                     label.strip()[:256], timestamp, timestamp + validity_days * 86400),
                )
                db.execute(
                    """INSERT INTO emergency_recovery_events
                       (event_type,authority_fingerprint,detail,created_at)
                       VALUES('AUTHORITY_ENROLLED',?,?,?)""",
                    (fingerprint, authority_id.strip()[:256], timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise EmergencyRecoveryError("recovery_authority_already_enrolled") from exc
        return fingerprint

    def list_authorities(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT fingerprint,authority_id,label,active,enrolled_at,expires_at,
                          revoked_at,revoked_reason
                   FROM recovery_authorities ORDER BY enrolled_at,fingerprint"""
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_authority(self, fingerprint: str, *, reason: str, now: int | None = None) -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise EmergencyRecoveryError("recovery_revocation_reason_required")
        timestamp = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE recovery_authorities SET active=0,revoked_at=?,revoked_reason=?
                   WHERE fingerprint=? AND active=1""",
                (timestamp, reason.strip()[:1000], fingerprint),
            )
            if cursor.rowcount != 1:
                raise EmergencyRecoveryError("active_recovery_authority_not_found")
            db.execute(
                """INSERT INTO emergency_recovery_events
                   (event_type,authority_fingerprint,detail,created_at)
                   VALUES('AUTHORITY_REVOKED',?,?,?)""",
                (fingerprint, reason.strip()[:1000], timestamp),
            )

    def recover_approval_key(
        self,
        *,
        old_fingerprint: str,
        new_public_key: Ed25519PublicKey,
        new_label: str,
        reason: str,
        authorizations: list[dict[str, Any]],
        now: int | None = None,
        validity_days: int = DEFAULT_KEY_LIFETIME_DAYS,
    ) -> str:
        if type(validity_days) is not int or not 1 <= validity_days <= MAX_KEY_LIFETIME_DAYS:
            raise EmergencyRecoveryError("replacement_key_validity_out_of_range")
        if not isinstance(new_public_key, Ed25519PublicKey):
            raise EmergencyRecoveryError("replacement_ed25519_key_required")
        if not isinstance(new_label, str) or not new_label.strip():
            raise EmergencyRecoveryError("replacement_key_label_required")
        if not isinstance(reason, str) or not reason.strip():
            raise EmergencyRecoveryError("recovery_reason_required")
        if not isinstance(authorizations, list) or not MIN_RECOVERY_AUTHORITIES <= len(authorizations) <= MAX_RECOVERY_AUTHORITIES:
            raise EmergencyRecoveryError("independent_recovery_authority_threshold_not_met")
        new_fingerprint = public_key_fingerprint(new_public_key)
        replacement_pem = new_public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        timestamp = int(time.time()) if now is None else int(now)
        normalized: list[tuple[dict[str, Any], str, str]] = []
        authority_ids: set[str] = set()
        authority_fingerprints: set[str] = set()
        nonces: set[str] = set()
        for authorization in authorizations:
            try:
                payload = authorization["payload"]
                signature = base64.b64decode(authorization["signature"], validate=True)
                expected = {
                    "schema_version", "action", "authority_id", "authority_fingerprint",
                    "old_fingerprint", "new_fingerprint", "new_public_key_pem", "new_label",
                    "reason", "issued_at", "expires_at", "nonce",
                }
                if not isinstance(payload, dict) or set(payload) != expected:
                    raise EmergencyRecoveryError("recovery_authorization_schema_invalid")
                if payload["schema_version"] != 1 or payload["action"] != "REPLACE_APPROVAL_KEY":
                    raise EmergencyRecoveryError("recovery_authorization_action_invalid")
                if (payload["old_fingerprint"] != old_fingerprint
                    or payload["new_fingerprint"] != new_fingerprint
                    or payload["new_public_key_pem"] != replacement_pem
                    or payload["new_label"] != new_label.strip()[:256]
                    or payload["reason"] != reason.strip()[:1000]):
                    raise EmergencyRecoveryError("recovery_authorization_scope_mismatch")
                issued, expires = payload["issued_at"], payload["expires_at"]
                if type(issued) is not int or type(expires) is not int or expires <= issued:
                    raise EmergencyRecoveryError("recovery_authorization_time_invalid")
                if issued > timestamp + RECOVERY_CLOCK_SKEW_SECONDS or expires <= timestamp:
                    raise EmergencyRecoveryError("recovery_authorization_expired_or_future")
                if expires - issued > RECOVERY_TTL_SECONDS:
                    raise EmergencyRecoveryError("recovery_authorization_ttl_exceeded")
                if payload["nonce"] in nonces:
                    raise EmergencyRecoveryError("distinct_recovery_authorizations_required")
                nonces.add(payload["nonce"])
                authority_id = payload["authority_id"]
                fingerprint = payload["authority_fingerprint"]
                if not isinstance(authority_id, str) or not authority_id.strip():
                    raise EmergencyRecoveryError("recovery_authority_id_invalid")
                if authority_id in authority_ids or fingerprint in authority_fingerprints:
                    raise EmergencyRecoveryError("independent_recovery_authorities_required")
                authority_ids.add(authority_id)
                authority_fingerprints.add(fingerprint)
                normalized.append((payload, fingerprint, signature))
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, EmergencyRecoveryError):
                    raise
                raise EmergencyRecoveryError("recovery_authorization_malformed") from exc

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT active FROM trusted_signing_keys WHERE fingerprint=?",
                (old_fingerprint,),
            ).fetchone()
            if old is None or old["active"] != 1:
                raise EmergencyRecoveryError("active_approval_key_not_found")
            if db.execute(
                "SELECT 1 FROM trusted_signing_keys WHERE fingerprint=?", (new_fingerprint,),
            ).fetchone():
                raise EmergencyRecoveryError("replacement_approval_key_already_enrolled")
            for payload, fingerprint, signature in normalized:
                authority = db.execute(
                    """SELECT public_key,active,expires_at FROM recovery_authorities
                       WHERE fingerprint=? AND authority_id=?""",
                    (fingerprint, payload["authority_id"]),
                ).fetchone()
                if authority is None or authority["active"] != 1:
                    raise EmergencyRecoveryError("recovery_authority_untrusted_or_revoked")
                if timestamp >= authority["expires_at"]:
                    raise EmergencyRecoveryError("recovery_authority_expired")
                public_key = Ed25519PublicKey.from_public_bytes(authority["public_key"])
                if public_key_fingerprint(public_key) != fingerprint:
                    raise EmergencyRecoveryError("recovery_authority_fingerprint_corrupt")
                try:
                    public_key.verify(signature, _canonical(payload))
                except Exception as exc:
                    raise EmergencyRecoveryError("recovery_authorization_signature_invalid") from exc
                try:
                    db.execute(
                        "INSERT INTO consumed_recovery_authorizations(nonce,fingerprint,consumed_at) VALUES(?,?,?)",
                        (payload["nonce"], fingerprint, timestamp),
                    )
                except sqlite3.IntegrityError as exc:
                    raise EmergencyRecoveryError("recovery_authorization_replay_denied") from exc

            db.execute(
                """INSERT INTO trusted_signing_keys
                   (fingerprint,public_key,label,active,enrolled_at,expires_at)
                   VALUES(?,?,?,1,?,?)""",
                (new_fingerprint, public_key_bytes(new_public_key), new_label.strip()[:256],
                 timestamp, timestamp + validity_days * 86400),
            )
            cursor = db.execute(
                """UPDATE trusted_signing_keys
                   SET active=0,revoked_at=?,revoked_reason=?,replaced_by=?
                   WHERE fingerprint=? AND active=1""",
                (timestamp, "emergency_recovery: " + reason.strip()[:900], new_fingerprint, old_fingerprint),
            )
            if cursor.rowcount != 1:
                raise EmergencyRecoveryError("active_approval_key_not_found")
            db.execute(
                """INSERT INTO signing_key_events
                   (event_type,fingerprint,related_fingerprint,reason,created_at)
                   VALUES('ROTATED',?,?,?,?)""",
                (old_fingerprint, new_fingerprint, "emergency_recovery: " + reason.strip()[:900], timestamp),
            )
            db.execute(
                """INSERT INTO emergency_recovery_events
                   (event_type,old_fingerprint,new_fingerprint,detail,created_at)
                   VALUES('KEY_RECOVERED',?,?,?,?)""",
                (old_fingerprint, new_fingerprint,
                 json.dumps({"reason": reason.strip()[:1000], "authorities": sorted(authority_ids)},
                            sort_keys=True, separators=(",", ":")), timestamp),
            )
        return new_fingerprint

    def history(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM emergency_recovery_events ORDER BY event_id"
            ).fetchall()]
