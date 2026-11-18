"""Append-only, hash-chained capability evidence ledger.

Evidence records are attestations about externally stored artifacts. The ledger
never reads or executes those artifacts and never advances capability state.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexora.lifecycle import EVIDENCE_FOR

GENESIS = "0" * 64
EVIDENCE_TYPES = frozenset().union(*EVIDENCE_FOR.values())
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CURRENT_SCHEMA_VERSION = 2


class EvidenceError(RuntimeError):
    """Raised when an evidence record is invalid or the ledger is corrupt."""


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_body(row: sqlite3.Row) -> dict[str, Any]:
    """Return the version-specific signed/hash-bound record representation."""
    body = {
        "capability_id": row["capability_id"],
        "evidence_type": row["evidence_type"],
        "reference": row["reference"],
        "artifact_sha256": row["artifact_sha256"],
        "operator": row["operator"],
        "note": row["note"],
        "previous_hash": row["previous_hash"],
    }
    version = row["schema_version"]
    if version == 2:
        body.update({
            "schema_version": version,
            "sequence": row["sequence"],
            "created_at": row["created_at"],
        })
    elif version != 1:
        raise EvidenceError("unsupported_evidence_schema_version")
    return body


class EvidenceLedger:
    """Store externally verifiable evidence references in an append-only chain."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS capability_evidence (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    capability_id INTEGER NOT NULL CHECK(capability_id BETWEEN 1 AND 264),
                    evidence_type TEXT NOT NULL,
                    reference TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE
                );
            """)
            columns = {row["name"] for row in db.execute(
                "PRAGMA table_info(capability_evidence)"
            )}
            if "schema_version" not in columns:
                db.execute(
                    "ALTER TABLE capability_evidence ADD COLUMN "
                    "schema_version INTEGER NOT NULL DEFAULT 1"
                )
            db.executescript("""
                CREATE TRIGGER IF NOT EXISTS capability_evidence_no_update
                BEFORE UPDATE ON capability_evidence BEGIN
                    SELECT RAISE(ABORT, 'evidence ledger is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS capability_evidence_no_delete
                BEFORE DELETE ON capability_evidence BEGIN
                    SELECT RAISE(ABORT, 'evidence ledger is append-only');
                END;
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def add(self, capability_id: int, evidence_type: str, reference: str,
            artifact_sha256: str, operator: str, note: str = "") -> dict[str, Any]:
        if type(capability_id) is not int or not 1 <= capability_id <= 264:
            raise EvidenceError("capability_id_out_of_range")
        if evidence_type not in EVIDENCE_TYPES:
            raise EvidenceError("unsupported_evidence_type")
        for field, value in (("reference", reference), ("operator", operator)):
            if not isinstance(value, str) or not value.strip() or len(value) > 2048:
                raise EvidenceError(field + "_required_or_too_long")
        if not isinstance(artifact_sha256, str) or not _SHA256.fullmatch(artifact_sha256):
            raise EvidenceError("artifact_sha256_must_be_64_lowercase_hex")
        if not isinstance(note, str) or len(note) > 4000:
            raise EvidenceError("note_invalid_or_too_long")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            tail = db.execute(
                "SELECT record_hash FROM capability_evidence ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous = tail["record_hash"] if tail else GENESIS
            sequence_row = db.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence "
                "FROM capability_evidence"
            ).fetchone()
            sequence = sequence_row["next_sequence"]
            created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            )
            body = {
                "capability_id": capability_id,
                "evidence_type": evidence_type,
                "reference": reference.strip(),
                "artifact_sha256": artifact_sha256,
                "operator": operator.strip(),
                "note": note,
                "previous_hash": previous,
                "schema_version": _CURRENT_SCHEMA_VERSION,
                "sequence": sequence,
                "created_at": created_at,
            }
            digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
            db.execute(
                """INSERT INTO capability_evidence
                   (sequence,capability_id,evidence_type,reference,artifact_sha256,operator,note,
                    created_at,previous_hash,record_hash,schema_version)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (sequence, capability_id, evidence_type, reference.strip(), artifact_sha256,
                 operator.strip(), note, created_at, previous, digest, _CURRENT_SCHEMA_VERSION),
            )
        return {"sequence": sequence, **body, "record_hash": digest}

    def list(self, capability_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if capability_id is not None and (
            type(capability_id) is not int or not 1 <= capability_id <= 264
        ):
            raise EvidenceError("capability_id_out_of_range")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise EvidenceError("limit_out_of_range")
        with self._connect() as db:
            if capability_id is None:
                rows = db.execute(
                    "SELECT * FROM capability_evidence ORDER BY sequence DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM capability_evidence WHERE capability_id=?
                       ORDER BY sequence DESC LIMIT ?""", (capability_id, limit)
                ).fetchall()
        return [dict(row) for row in rows]

    def verify(self) -> dict[str, Any]:
        previous = GENESIS
        count = 0
        with self._connect() as db:
            rows = db.execute("SELECT * FROM capability_evidence ORDER BY sequence").fetchall()
        for row in rows:
            try:
                body = _record_body(row)
            except EvidenceError:
                return {"valid": False, "verified_records": count,
                        "failed_sequence": row["sequence"]}
            expected = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or row["record_hash"] != expected:
                return {"valid": False, "verified_records": count,
                        "failed_sequence": row["sequence"]}
            previous = expected
            count += 1
        return {"valid": True, "verified_records": count, "head_hash": previous}
