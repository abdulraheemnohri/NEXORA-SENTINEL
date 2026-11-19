"""Durable, append-only storage for proposal-only self-family review records.

This store records proposals and human review outcomes. A review record is not a
cryptographic approval, lifecycle promotion, execution authorization, or identity
proof. Proposal execution remains disabled.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from nexora.self_families import SelfFamily, SelfFamilyProposal


class SelfFamilyStoreError(RuntimeError):
    """Raised when a self-family proposal cannot be safely stored or reviewed."""


class SelfFamilyProposalStore:
    """Persist immutable proposals and append-only review events in SQLite."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS self_family_proposals (
                    proposal_id TEXT PRIMARY KEY
                        CHECK(length(proposal_id)=24 AND proposal_id NOT GLOB '*[^0-9a-f]*'),
                    family TEXT NOT NULL,
                    summary TEXT NOT NULL CHECK(length(trim(summary)) > 0),
                    evidence_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL
                        CHECK(length(payload_sha256)=64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
                    execution TEXT NOT NULL DEFAULT 'DISABLED'
                        CHECK(execution='DISABLED'),
                    created_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS self_family_review_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id TEXT NOT NULL REFERENCES self_family_proposals(proposal_id),
                    decision TEXT NOT NULL CHECK(decision IN ('SUBMITTED','REVIEWED','REJECTED')),
                    operator_label TEXT,
                    evidence_json TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE INDEX IF NOT EXISTS self_family_review_by_proposal
                    ON self_family_review_events(proposal_id,event_id);
                CREATE TRIGGER IF NOT EXISTS self_family_proposals_no_update
                BEFORE UPDATE ON self_family_proposals BEGIN
                    SELECT RAISE(ABORT, 'self-family proposals are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS self_family_proposals_no_delete
                BEFORE DELETE ON self_family_proposals BEGIN
                    SELECT RAISE(ABORT, 'self-family proposals are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS self_family_review_no_update
                BEFORE UPDATE ON self_family_review_events BEGIN
                    SELECT RAISE(ABORT, 'self-family review history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS self_family_review_no_delete
                BEFORE DELETE ON self_family_review_events BEGIN
                    SELECT RAISE(ABORT, 'self-family review history is append-only');
                END;
            """)

    @staticmethod
    def _evidence(evidence: tuple[str, ...] | list[str]) -> list[str]:
        if isinstance(evidence, str) or not isinstance(evidence, (tuple, list)):
            raise SelfFamilyStoreError("review_evidence_must_be_a_collection")
        values = sorted({item.strip() for item in evidence if isinstance(item, str) and item.strip()})
        if len(values) != len(evidence) or not values:
            raise SelfFamilyStoreError("nonempty_valid_review_evidence_required")
        return values

    def submit(self, proposal: SelfFamilyProposal) -> dict[str, Any]:
        if not isinstance(proposal, SelfFamilyProposal):
            raise TypeError("self_family_proposal_required")
        if not isinstance(proposal.family, SelfFamily):
            raise SelfFamilyStoreError("unknown_self_family")
        if proposal.execution != "DISABLED":
            raise SelfFamilyStoreError("proposal_execution_must_remain_disabled")
        if proposal.status != "PENDING_HUMAN_REVIEW":
            raise SelfFamilyStoreError("proposal_must_be_pending_review")
        try:
            evidence_json = json.dumps(
                list(proposal.evidence), ensure_ascii=False, separators=(",", ":")
            )
            payload = (
                proposal.proposal_id, proposal.family.value, proposal.summary,
                evidence_json, proposal.payload_sha256,
            )
        except (TypeError, ValueError) as exc:
            raise SelfFamilyStoreError("proposal_serialization_failed") from exc

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT proposal_id,family,summary,evidence_json,payload_sha256,execution "
                "FROM self_family_proposals WHERE proposal_id=?",
                (proposal.proposal_id,),
            ).fetchone()
            if existing is not None:
                expected = (proposal.proposal_id, proposal.family.value, proposal.summary,
                            evidence_json, proposal.payload_sha256, "DISABLED")
                if tuple(existing) != expected:
                    raise SelfFamilyStoreError("proposal_id_content_collision")
                return self.get(proposal.proposal_id)
            db.execute(
                "INSERT INTO self_family_proposals"
                "(proposal_id,family,summary,evidence_json,payload_sha256) VALUES(?,?,?,?,?)",
                payload,
            )
            db.execute(
                "INSERT INTO self_family_review_events"
                "(proposal_id,decision,evidence_json,note) VALUES(?,'SUBMITTED',?,'proposal_created')",
                (proposal.proposal_id, evidence_json),
            )
        return self.get(proposal.proposal_id)

    def review(
        self,
        proposal_id: str,
        decision: str,
        *,
        operator_label: str,
        evidence: tuple[str, ...] | list[str],
        note: str = "",
    ) -> dict[str, Any]:
        if decision not in {"REVIEWED", "REJECTED"}:
            raise SelfFamilyStoreError("unsupported_review_decision")
        if not isinstance(proposal_id, str) or len(proposal_id) != 24:
            raise SelfFamilyStoreError("proposal_id_invalid")
        if not isinstance(operator_label, str) or not operator_label.strip():
            raise SelfFamilyStoreError("operator_label_required")
        if not isinstance(note, str):
            raise SelfFamilyStoreError("review_note_invalid")
        supplied = self._evidence(evidence)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT proposal_id FROM self_family_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise SelfFamilyStoreError("unknown_proposal_denied")
            signed_review_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='self_family_signed_reviews'"
            ).fetchone()
            if signed_review_table is not None:
                signed_review = db.execute(
                    "SELECT 1 FROM self_family_signed_reviews WHERE proposal_id=?",
                    (proposal_id,),
                ).fetchone()
                if signed_review is not None:
                    raise SelfFamilyStoreError("proposal_has_signed_review_record")
            latest = db.execute(
                "SELECT decision FROM self_family_review_events "
                "WHERE proposal_id=? ORDER BY event_id DESC LIMIT 1",
                (proposal_id,),
            ).fetchone()
            if latest is None or latest["decision"] != "SUBMITTED":
                raise SelfFamilyStoreError("proposal_already_reviewed")
            db.execute(
                "INSERT INTO self_family_review_events"
                "(proposal_id,decision,operator_label,evidence_json,note) VALUES(?,?,?,?,?)",
                (proposal_id, decision, operator_label.strip()[:256],
                 json.dumps(supplied, ensure_ascii=False, separators=(",", ":")), note.strip()),
            )
        return self.get(proposal_id)

    def get(self, proposal_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM self_family_proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return None
            events = db.execute(
                "SELECT * FROM self_family_review_events WHERE proposal_id=? ORDER BY event_id",
                (proposal_id,),
            ).fetchall()
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        result["status"] = events[-1]["decision"] if events else "UNKNOWN"
        result["execution"] = "DISABLED"
        result["review_history"] = [
            {**dict(event), "evidence": json.loads(event["evidence_json"])}
            for event in events
        ]
        return result

    def list(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("proposal_list_limit_out_of_range")
        with self._connect() as db:
            ids = db.execute(
                "SELECT proposal_id FROM self_family_proposals "
                "ORDER BY created_at DESC,proposal_id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self.get(row["proposal_id"]) for row in ids]
