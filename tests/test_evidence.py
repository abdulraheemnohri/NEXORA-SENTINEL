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
