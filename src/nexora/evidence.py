"""Append-only, hash-chained capability evidence ledger.

Evidence records are attestations about externally stored artifacts. The ledger
never reads or executes those artifacts and never advances capability state.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexora.lifecycle import EVIDENCE_FOR

GENESIS = "0" * 64
EVIDENCE_TYPES = frozenset().union(*EVIDENCE_FOR.values())
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CURRENT_SCHEMA_VERSION = 4


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
    if version in (2, 3, 4):
        body.update({
            "schema_version": version,
            "sequence": row["sequence"],
            "created_at": row["created_at"],
        })
        if version >= 3:
            body["expires_at"] = row["expires_at"]
        if version == 4:
            body["source_uri"] = row["source_uri"]
            body["source_revision"] = row["source_revision"]
            body["collected_at"] = row["collected_at"]
    elif version != 1:
        raise EvidenceError("unsupported_evidence_schema_version")
    return body


def _verify_rows(rows: list[sqlite3.Row]) -> dict[str, Any]:
    """Verify a stable ordered snapshot of the complete evidence chain."""
    previous = GENESIS
    count = 0
    for row in rows:
        try:
            body = _record_body(row)
        except EvidenceError:
            return {
                "valid": False, "verified_records": count,
                "failed_sequence": row["sequence"],
            }
        expected = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        if row["previous_hash"] != previous or row["record_hash"] != expected:
            return {
                "valid": False, "verified_records": count,
                "failed_sequence": row["sequence"],
            }
        previous = expected
        count += 1
    return {"valid": True, "verified_records": count, "head_hash": previous}


class EvidenceLedger:
    """Store externally verifiable evidence references in an append-only chain."""

    def __init__(self, database: Path, *, readonly: bool = False):
        self.database = Path(database)
        self.readonly = readonly
        if readonly:
            if not self.database.is_file():
                raise EvidenceError("evidence_ledger_not_found")
            with self._connect() as db:
                columns = {row["name"] for row in db.execute(
                    "PRAGMA table_info(capability_evidence)"
                )}
                required = {
                    "sequence", "capability_id", "evidence_type", "reference",
                    "artifact_sha256", "operator", "note", "created_at",
                    "previous_hash", "record_hash", "schema_version",
                }
                if not columns:
                    raise EvidenceError("evidence_ledger_schema_missing")
                if not required.issubset(columns):
                    raise EvidenceError("evidence_ledger_schema_incomplete")
            return
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
            if "expires_at" not in columns:
                db.execute(
                    "ALTER TABLE capability_evidence ADD COLUMN expires_at TEXT"
                )
            for column in ("source_uri", "source_revision", "collected_at"):
                if column not in columns:
                    db.execute(
                        f"ALTER TABLE capability_evidence ADD COLUMN {column} TEXT"
                    )
            db.execute(
                "CREATE INDEX IF NOT EXISTS capability_evidence_capability_idx "
                "ON capability_evidence(capability_id, evidence_type)"
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
        if self.readonly:
            db = sqlite3.connect(
                self.database.resolve().as_uri() + "?mode=ro", uri=True, timeout=10
            )
            db.execute("PRAGMA query_only=ON")
        else:
            db = sqlite3.connect(self.database, timeout=10)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
        db.row_factory = sqlite3.Row
        return db

    def add(self, capability_id: int, evidence_type: str, reference: str,
            artifact_sha256: str, operator: str, note: str = "",
            expires_at: str | None = None, source_uri: str | None = None,
            source_revision: str | None = None,
            collected_at: str | None = None) -> dict[str, Any]:
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
        if expires_at is not None:
            if not isinstance(expires_at, str) or not expires_at.strip():
                raise EvidenceError("expires_at_invalid")
            try:
                parsed_expiry = datetime.fromisoformat(expires_at)
                if parsed_expiry.tzinfo is None or parsed_expiry.utcoffset() is None:
                    raise ValueError("timezone_required")
                expires_at = parsed_expiry.astimezone(UTC).isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
            except ValueError as exc:
                raise EvidenceError("expires_at_must_be_timezone_aware_iso8601") from exc
        for field, value, maximum in (
            ("source_uri", source_uri, 2048),
            ("source_revision", source_revision, 512),
        ):
            if value is not None and (
                not isinstance(value, str) or not value.strip() or len(value) > maximum
            ):
                raise EvidenceError(field + "_invalid")
            if value is not None:
                if any(ord(char) < 32 for char in value):
                    raise EvidenceError(field + "_contains_control_character")
        if collected_at is not None:
            if not isinstance(collected_at, str) or not collected_at.strip():
                raise EvidenceError("collected_at_invalid")
            try:
                parsed_collected = datetime.fromisoformat(collected_at)
                if parsed_collected.tzinfo is None or parsed_collected.utcoffset() is None:
                    raise ValueError("timezone_required")
                collected_at = parsed_collected.astimezone(UTC).isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
            except ValueError as exc:
                raise EvidenceError("collected_at_must_be_timezone_aware_iso8601") from exc
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing_rows = db.execute(
                "SELECT * FROM capability_evidence ORDER BY sequence"
            ).fetchall()
            integrity = _verify_rows(existing_rows)
            if not integrity["valid"]:
                raise EvidenceError(
                    "evidence_ledger_integrity_failure_before_append:"
                    + str(integrity["failed_sequence"])
                )
            tail = existing_rows[-1] if existing_rows else None
            previous = tail["record_hash"] if tail else GENESIS
            sequence_row = db.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence "
                "FROM capability_evidence"
            ).fetchone()
            sequence = sequence_row["next_sequence"]
            created_at = datetime.now(UTC).isoformat(timespec="microseconds").replace(
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
                "expires_at": expires_at,
                "source_uri": source_uri.strip() if source_uri is not None else None,
                "source_revision": source_revision.strip() if source_revision is not None else None,
                "collected_at": collected_at,
            }
            digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
            db.execute(
                """INSERT INTO capability_evidence
                   (sequence,capability_id,evidence_type,reference,artifact_sha256,operator,note,
                    created_at,previous_hash,record_hash,schema_version,expires_at,
                    source_uri,source_revision,collected_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sequence, capability_id, evidence_type, reference.strip(), artifact_sha256,
                 operator.strip(), note, created_at, previous, digest, _CURRENT_SCHEMA_VERSION,
                 expires_at, body["source_uri"], body["source_revision"], collected_at),
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

    def evidence_summary(self, capability_id: int) -> dict[str, Any]:
        """Return complete evidence coverage without a presentation-size limit.

        Callers must verify the hash chain before trusting this summary.
        """
        if type(capability_id) is not int or not 1 <= capability_id <= 264:
            raise EvidenceError("capability_id_out_of_range")
        with self._connect() as db:
            evidence_types = [
                row["evidence_type"] for row in db.execute(
                    """SELECT DISTINCT evidence_type FROM capability_evidence
                       WHERE capability_id=? ORDER BY evidence_type""",
                    (capability_id,),
                ).fetchall()
            ]
            count = db.execute(
                "SELECT COUNT(*) FROM capability_evidence WHERE capability_id=?",
                (capability_id,),
            ).fetchone()[0]
        return {
            "capability_id": capability_id,
            "record_count": count,
            "evidence_types": evidence_types,
        }

    def get_record(self, sequence: int, capability_id: int) -> dict[str, Any] | None:
        """Return one exact evidence row without a display-list limit."""
        if type(sequence) is not int or sequence < 1:
            raise EvidenceError("sequence_out_of_range")
        if type(capability_id) is not int or not 1 <= capability_id <= 264:
            raise EvidenceError("capability_id_out_of_range")
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM capability_evidence WHERE sequence=? AND capability_id=?",
                (sequence, capability_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def verify(self) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM capability_evidence ORDER BY sequence").fetchall()
        return _verify_rows(rows)
