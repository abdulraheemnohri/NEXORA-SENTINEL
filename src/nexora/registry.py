"""Durable, fail-closed capability lifecycle registry.

SQLite state and immutable event history share transactions. Governance metadata
only: this module never invokes capability implementations or rolls software back.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from nexora.lifecycle import validate_transition


class RegistryError(RuntimeError):
    """Raised when registry integrity or a requested operation is invalid."""


class CapabilityRegistry:
    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

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

    def transition(self, capability_id: int, requested_state: str, evidence, *, approver_id: str | None = None):
        supplied = self._evidence(evidence)
        operator = self._operator(approver_id) if requested_state in {"APPROVED", "ENABLED"} else None
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
                human_approved=bool(operator),
            )
            if not decision.allowed:
                raise RegistryError(decision.reason)
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

    def revoke(self, capability_id: int, reason: str, evidence, *, approver_id: str):
        operator = self._operator(approver_id)
        supplied = self._evidence(evidence)
        if not isinstance(reason, str) or not reason.strip():
            raise RegistryError("revocation_reason_required")
        if "revocation_basis" not in supplied:
            raise RegistryError("revocation_basis_evidence_required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT control_state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            if row["control_state"] == "REVOKED":
                raise RegistryError("already_revoked")
            db.execute(
                "UPDATE capabilities SET control_state='REVOKED',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE capability_id=?",
                (capability_id,),
            )
            db.execute(
                "INSERT INTO revocation_events(capability_id,reason,evidence_json,approver_id) VALUES(?,?,?,?)",
                (capability_id, reason.strip(), json.dumps(supplied, separators=(",", ":")), operator),
            )
        return self.get(capability_id)

    def record_rollback(
        self, capability_id: int, from_release: str, target_release: str,
        reason: str, evidence, *, approver_id: str,
    ) -> dict:
        """Record a human-authorized rollback decision; does not perform rollback."""
        operator = self._operator(approver_id)
        supplied = self._evidence(evidence)
        required = {"rollback_plan", "validation_report", "human_approval"}
        if not required.issubset(supplied):
            raise RegistryError("rollback_evidence_incomplete")
        values = (from_release, target_release, reason)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise RegistryError("rollback_metadata_required")
        if from_release == target_release:
            raise RegistryError("rollback_target_must_differ")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT control_state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            if row["control_state"] != "ACTIVE":
                raise RegistryError("revoked_capability_is_terminal")
            cursor = db.execute(
                """INSERT INTO rollback_events(
                    capability_id,from_release,target_release,reason,evidence_json,approver_id
                ) VALUES(?,?,?,?,?,?)""",
                (capability_id, from_release.strip(), target_release.strip(), reason.strip(),
                 json.dumps(supplied, separators=(",", ":")), operator),
            )
            event_id = cursor.lastrowid
        return self.rollback_history(capability_id)[-1]

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
