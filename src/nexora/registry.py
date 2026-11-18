"""Durable, fail-closed capability lifecycle registry.

SQLite state and immutable transition history share one transaction. This module
tracks governance state only; it never invokes capability implementations.
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
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_update
                BEFORE UPDATE ON lifecycle_events BEGIN
                    SELECT RAISE(ABORT, 'lifecycle history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_delete
                BEFORE DELETE ON lifecycle_events BEGIN
                    SELECT RAISE(ABORT, 'lifecycle history is append-only');
                END;
            """)

    def register(self, capability_id: int, name: str, family: str, *, source_record: bool):
        if not isinstance(capability_id, int) or isinstance(capability_id, bool) or not 1 <= capability_id <= 264:
            raise RegistryError("capability_id_out_of_range")
        if not name.strip() or not family.strip() or not source_record:
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
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state FROM capabilities WHERE capability_id=?", (capability_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("unknown_capability_denied")
            current = row["state"]
            decision = validate_transition(
                current, requested_state, evidence,
                human_approved=bool(approver_id and approver_id.strip()),
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
                (
                    capability_id, current, requested_state,
                    json.dumps(sorted(set(evidence)), separators=(",", ":")),
                    approver_id.strip() if approver_id else None,
                    decision.reason,
                ),
            )
        return self.get(capability_id)

    def get(self, capability_id: int) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM capabilities WHERE capability_id=?", (capability_id,)).fetchone()
            return dict(row) if row else None

    def history(self, capability_id: int) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM lifecycle_events WHERE capability_id=? ORDER BY event_id",
                (capability_id,),
            ).fetchall()
        return [dict(row) for row in rows]
