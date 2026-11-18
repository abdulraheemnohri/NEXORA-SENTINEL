"""Durable, fail-closed capability lifecycle registry.

SQLite state and immutable event history share transactions. Governance metadata
only: this module never invokes capability implementations or rolls software back.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from nexora.approval import ApprovalError, ApprovalReceiptStore
from nexora.lifecycle import validate_transition


class RegistryError(RuntimeError):
    """Raised when registry integrity or a requested operation is invalid."""


class CapabilityRegistry:
    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.approvals = ApprovalReceiptStore(self.database)

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = FULL")
        return db

    def _initialize(self):
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS capabilities (
                    capability_id INTEGER PRIMARY KEY CHECK(capability_id BETWEEN 1 AND 264),
                    name TEXT NOT NULL CHECK(length(trim(name)) > 0),
                    family TEXT NOT NULL CHECK(length(trim(family)) > 0),
                    state TEXT NOT NULL CHECK(state IN (
                        'SPECIFIED','REGISTERED','IMPLEMENTED','TESTED',
                        'SHADOWED','APPROVED','ENABLED'
                    )),
                    control_state TEXT NOT NULL DEFAULT 'ACTIVE'
                        CHECK(control_state IN ('ACTIVE','REVOKED')),
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capability_id INTEGER NOT NULL REFERENCES capabilities(capability_id),
                    previous_state TEXT,
                    requested_state TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    approver_id TEXT,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS revocation_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capability_id INTEGER NOT NULL REFERENCES capabilities(capability_id),
                    reason TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    approver_id TEXT NOT NULL,
                    signer_fingerprints_json TEXT NOT NULL DEFAULT '[]',
                    receipt_payloads_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS rollback_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capability_id INTEGER NOT NULL REFERENCES capabilities(capability_id),
                    from_release TEXT NOT NULL,
                    target_release TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    approver_id TEXT NOT NULL,
                    signer_fingerprints_json TEXT NOT NULL DEFAULT '[]',
                    receipt_payloads_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_update
                BEFORE UPDATE ON lifecycle_events BEGIN
                    SELECT RAISE(ABORT, 'lifecycle history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_delete
                BEFORE DELETE ON lifecycle_events BEGIN
                    SELECT RAISE(ABORT, 'lifecycle history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS revocation_events_no_update
                BEFORE UPDATE ON revocation_events BEGIN
                    SELECT RAISE(ABORT, 'revocation history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS revocation_events_no_delete
                BEFORE DELETE ON revocation_events BEGIN
                    SELECT RAISE(ABORT, 'revocation history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS rollback_events_no_update
                BEFORE UPDATE ON rollback_events BEGIN
                    SELECT RAISE(ABORT, 'rollback history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS rollback_events_no_delete
                BEFORE DELETE ON rollback_events BEGIN
                    SELECT RAISE(ABORT, 'rollback history is append-only');
                END;
            """)
            for table in ("revocation_events", "rollback_events"):
                event_columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                for name in ("signer_fingerprints_json", "receipt_payloads_json"):
                    if name not in event_columns:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {name} TEXT NOT NULL DEFAULT '[]'")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(capabilities)")}
            if "control_state" not in columns:
                db.execute(
                    "ALTER TABLE capabilities ADD COLUMN control_state TEXT NOT NULL DEFAULT 'ACTIVE'"
                )

    @staticmethod
    def _operator(approver_id: str | None) -> str:
        if not isinstance(approver_id, str) or not approver_id.strip():
            raise RegistryError("explicit_operator_identity_required")
        return approver_id.strip()[:256]

    @staticmethod
    def _evidence(evidence) -> list[str]:
        if isinstance(evidence, str):
            raise RegistryError("evidence_must_be_a_collection")
        try:
            values = sorted({item.strip() for item in evidence if isinstance(item, str) and item.strip()})
        except TypeError as exc:
            raise RegistryError("evidence_must_be_a_collection") from exc
        if not values:
            raise RegistryError("nonempty_evidence_required")
        return values

    def register(self, capability_id: int, name: str, family: str, *, source_record: bool):
        if not isinstance(capability_id, int) or isinstance(capability_id, bool) or not 1 <= capability_id <= 264:
            raise RegistryError("capability_id_out_of_range")
        if not isinstance(name, str) or not name.strip() or not isinstance(family, str) or not family.strip() or not source_record:
            raise RegistryError("valid_source_record_required")
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO capabilities(capability_id,name,family,state) VALUES(?,?,?,'SPECIFIED')",
                    (capability_id, name.strip(), family.strip()),
                )
                db.execute(
                    "INSERT INTO lifecycle_events(capability_id,previous_state,requested_state,evidence_json,reason) VALUES(?,NULL,'SPECIFIED',?,'source_record_registered')",
                    (capability_id, json.dumps(["source_record"], separators=(",", ":"))),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("duplicate_or_invalid_capability") from exc
        return self.get(capability_id)

    def transition(
        self, capability_id: int, requested_state: str, evidence, *,
        approver_id: str | None = None, approval_receipt: dict | None = None,
        approval_receipts: list[dict] | None = None,
        approver_ids: list[str] | None = None,
    ):
        supplied = self._evidence(evidence)
        operator = (
            self._operator(approver_id)
            if requested_state in {"APPROVED", "ENABLED"} and approval_receipts is None
            else None
        )
        if approval_receipts is not None:
            if approval_receipt is not None or approval_receipts == []:
                raise RegistryError("provide_one_approval_receipt_argument")
            if approver_ids is None or len(approver_ids) != len(approval_receipts):
                raise RegistryError("multi_approval_identity_count_mismatch")
            normalized_approvers = [self._operator(item) for item in approver_ids]
            if len(set(normalized_approvers)) != len(normalized_approvers):
                raise RegistryError("distinct_approvers_required")
        else:
            normalized_approvers = None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,control_state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            if row["control_state"] != "ACTIVE":
                raise RegistryError("revoked_capability_is_terminal")
            current = row["state"]
            decision = validate_transition(
                current, requested_state, supplied,
                human_approved=bool(operator or normalized_approvers),
            )
            if not decision.allowed:
                raise RegistryError(decision.reason)
            if requested_state in {"APPROVED", "ENABLED"}:
                try:
                    if requested_state == "ENABLED":
                        if approval_receipts is None:
                            raise RegistryError("two_independent_approvals_required_for_enabled")
                        self.approvals.verify_and_consume_many(
                            approval_receipts, capability_id=capability_id,
                            transition=requested_state, evidence=supplied,
                            approver_ids=normalized_approvers, connection=db,
                            minimum_approvals=2, maximum_approvals=5,
                        )
                        operator = ",".join(normalized_approvers)
                    elif approval_receipts is not None:
                        raise RegistryError("multi_approval_not_supported_for_approved_transition")
                    else:
                        if approval_receipt is None:
                            raise RegistryError("signed_approval_receipt_required")
                        self.approvals.verify_and_consume(
                            approval_receipt, capability_id=capability_id,
                            transition=requested_state, evidence=supplied,
                            approver_id=operator, connection=db,
                        )
                except ApprovalError as exc:
                    raise RegistryError(str(exc)) from exc
            if requested_state == current:
                return self.get(capability_id)
            db.execute(
                "UPDATE capabilities SET state=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE capability_id=?",
                (requested_state, capability_id),
            )
            db.execute(
                """INSERT INTO lifecycle_events(
                    capability_id,previous_state,requested_state,evidence_json,approver_id,reason
                ) VALUES(?,?,?,?,?,?)""",
                (capability_id, current, requested_state,
                 json.dumps(supplied, separators=(",", ":")), operator, decision.reason),
            )
        return self.get(capability_id)

    def revoke(
        self, capability_id: int, reason: str, evidence, *,
        approval_receipts: list[dict], approver_ids: list[str],
    ):
        """Immediately disable a capability after two independent signed approvals."""
        supplied = self._evidence(evidence)
        if not isinstance(reason, str) or not reason.strip():
            raise RegistryError("revocation_reason_required")
        if "revocation_basis" not in supplied or f"reason:{reason.strip()}" not in supplied:
            raise RegistryError("revocation_reason_and_basis_must_be_signed")
        if not isinstance(approval_receipts, list) or not isinstance(approver_ids, list):
            raise RegistryError("signed_multi_approval_required")
        normalized = [self._operator(item) for item in approver_ids]
        if len(set(normalized)) != len(normalized):
            raise RegistryError("distinct_approvers_required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT control_state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            if row["control_state"] == "REVOKED":
                raise RegistryError("already_revoked")
            try:
                payloads = self.approvals.verify_and_consume_many(
                    approval_receipts, capability_id=capability_id,
                    transition="REVOKE", evidence=supplied,
                    approver_ids=normalized, connection=db,
                    minimum_approvals=2, maximum_approvals=5,
                )
            except ApprovalError as exc:
                raise RegistryError(str(exc)) from exc
            db.execute(
                "UPDATE capabilities SET control_state='REVOKED',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE capability_id=? AND control_state='ACTIVE'",
                (capability_id,),
            )
            db.execute(
                """INSERT INTO revocation_events(
                    capability_id,reason,evidence_json,approver_id,
                    signer_fingerprints_json,receipt_payloads_json
                ) VALUES(?,?,?,?,?,?)""",
                (capability_id, reason.strip()[:1000],
                 json.dumps(supplied, separators=(",", ":")), ",".join(normalized),
                 json.dumps([p["key_fingerprint"] for p in payloads], separators=(",", ":")),
                 json.dumps([{"payload": payload, "signature": receipt["signature"]} for payload, receipt in zip(payloads, approval_receipts)], sort_keys=True, separators=(",", ":"))),
            )
        return self.get(capability_id)

    def record_rollback(
        self, capability_id: int, from_release: str, target_release: str,
        reason: str, evidence, *, approval_receipts: list[dict],
        approver_ids: list[str],
    ) -> dict:
        """Record a signed rollback authorization; never performs a software rollback."""
        supplied = self._evidence(evidence)
        required = {
            "rollback_plan", "validation_report", "human_approval",
            f"from_release:{from_release}", f"target_release:{target_release}",
            f"reason:{reason}",
        }
        if not required.issubset(supplied):
            raise RegistryError("rollback_metadata_must_be_signed")
        values = (from_release, target_release, reason)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise RegistryError("rollback_metadata_required")
        if from_release == target_release:
            raise RegistryError("rollback_target_must_differ")
        normalized = [self._operator(item) for item in approver_ids]
        if len(set(normalized)) != len(normalized):
            raise RegistryError("distinct_approvers_required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT control_state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            if row["control_state"] != "ACTIVE":
                raise RegistryError("revoked_capability_is_terminal")
            try:
                payloads = self.approvals.verify_and_consume_many(
                    approval_receipts, capability_id=capability_id,
                    transition="ROLLBACK", evidence=supplied,
                    approver_ids=normalized, connection=db,
                    minimum_approvals=2, maximum_approvals=5,
                )
            except ApprovalError as exc:
                raise RegistryError(str(exc)) from exc
            cursor = db.execute(
                """INSERT INTO rollback_events(
                    capability_id,from_release,target_release,reason,evidence_json,approver_id,
                    signer_fingerprints_json,receipt_payloads_json
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (capability_id, from_release.strip(), target_release.strip(), reason.strip(),
                 json.dumps(supplied, separators=(",", ":")), ",".join(normalized),
                 json.dumps([p["key_fingerprint"] for p in payloads], separators=(",", ":")),
                 json.dumps(payloads, sort_keys=True, separators=(",", ":"))),
            )
            row = db.execute(
                "SELECT * FROM rollback_events WHERE event_id=?", (cursor.lastrowid,)
            ).fetchone()
            result = dict(row)
        return result

    def get(self, capability_id: int) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM capabilities WHERE capability_id=?", (capability_id,)).fetchone()
            return dict(row) if row else None

    def history(self, capability_id: int) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM lifecycle_events WHERE capability_id=? ORDER BY event_id", (capability_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def revocation_history(self, capability_id: int) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM revocation_events WHERE capability_id=? ORDER BY event_id", (capability_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def rollback_history(self, capability_id: int) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM rollback_events WHERE capability_id=? ORDER BY event_id", (capability_id,)
            ).fetchall()
        return [dict(row) for row in rows]
