from __future__ import annotations

import sqlite3

import pytest

from nexora.evidence import EvidenceError, EvidenceLedger

HASH = "a" * 64


def test_evidence_ledger_adds_and_verifies_chain(tmp_path):
    ledger = EvidenceLedger(tmp_path / "registry.sqlite3")
    first = ledger.add(85, "implementation_reference", "git:commit/abc", HASH, "operator-1")
    second = ledger.add(85, "test_report", "artifact://tests/42", "b" * 64, "operator-1")
    assert first["sequence"] == 1
    assert second["previous_hash"] == first["record_hash"]
    assert ledger.verify()["valid"] is True
    assert len(ledger.list(capability_id=85)) == 2


def test_evidence_ledger_rejects_invalid_digest_and_type(tmp_path):
    ledger = EvidenceLedger(tmp_path / "ledger.sqlite3")
    with pytest.raises(EvidenceError, match="artifact_sha256"):
        ledger.add(85, "implementation_reference", "ref", "bad", "operator")
    with pytest.raises(EvidenceError, match="unsupported_evidence_type"):
        ledger.add(85, "invented", "ref", HASH, "operator")


def test_evidence_ledger_is_append_only(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "implementation_reference", "ref", HASH, "operator")
    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE capability_evidence SET note='tampered' WHERE sequence=1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM capability_evidence WHERE sequence=1")


def test_evidence_ledger_detects_direct_database_tampering(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "implementation_reference", "ref", HASH, "operator")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute("UPDATE capability_evidence SET note='tampered' WHERE sequence=1")
    result = ledger.verify()
    assert result["valid"] is False
    assert result["failed_sequence"] == 1


def test_evidence_ledger_rejects_bad_limit(tmp_path):
    ledger = EvidenceLedger(tmp_path / "ledger.sqlite3")
    with pytest.raises(EvidenceError, match="limit_out_of_range"):
        ledger.list(limit=0)


def test_evidence_v2_binds_timestamp_and_sequence(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = EvidenceLedger(path)
    record = ledger.add(86, "test_report", "artifact://tests/86", HASH, "operator")
    assert record["schema_version"] == 2
    assert record["created_at"].endswith("Z")
    assert ledger.verify()["valid"] is True
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE capability_evidence SET created_at='2000-01-01T00:00:00Z' "
            "WHERE sequence=1"
        ) if False else None
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute(
            "UPDATE capability_evidence SET created_at='2000-01-01T00:00:00Z' "
            "WHERE sequence=1"
        )
    result = ledger.verify()
    assert result["valid"] is False
    assert result["failed_sequence"] == 1


def test_evidence_ledger_migrates_legacy_rows_without_rewriting_hashes(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    legacy_body = {
        "capability_id": 85,
        "evidence_type": "implementation_reference",
        "reference": "git:commit/legacy",
        "artifact_sha256": HASH,
        "operator": "operator",
        "note": "",
        "previous_hash": "0" * 64,
    }
    import hashlib
    import json

    legacy_hash = hashlib.sha256(
        json.dumps(legacy_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE capability_evidence (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                capability_id INTEGER NOT NULL,
                evidence_type TEXT NOT NULL,
                reference TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                operator TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE
            )
        """)
        db.execute(
            """INSERT INTO capability_evidence
               (sequence,capability_id,evidence_type,reference,artifact_sha256,operator,note,
                created_at,previous_hash,record_hash)
               VALUES(1,85,'implementation_reference','git:commit/legacy',?,?,?,'2026-01-01T00:00:00Z',?,?)""",
            (HASH, "operator", "", "0" * 64, legacy_hash),
        )
    ledger = EvidenceLedger(path)
    assert ledger.verify()["valid"] is True
    new = ledger.add(86, "test_report", "artifact://tests/86", "b" * 64, "operator")
    assert new["sequence"] == 2
    assert ledger.verify()["verified_records"] == 2
