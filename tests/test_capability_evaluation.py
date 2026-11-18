from __future__ import annotations

from nexora.capability_evaluation import (
    CapabilityEvaluationError,
    evaluate_capability,
    evaluate_from_ledger,
)
from nexora.evidence import EvidenceLedger


def test_evaluation_reports_missing_gates_without_promoting(tmp_path):
    ledger = EvidenceLedger(tmp_path / "registry.sqlite3")
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    report = evaluate_from_ledger(tmp_path / "registry.sqlite3", 85)
    assert report["assessment"] == "EVIDENCE_GAPS"
    assert report["stages"][0]["ready"] is True
    assert report["stages"][1]["ready"] is False
    assert "implementation_reference" in report["stages"][1]["missing_evidence"]
    assert report["lifecycle_changed"] is False
    assert report["execution_enabled"] is False


def test_evaluation_requires_human_authorization_separately():
    report = evaluate_capability(
        86,
        [
            {"capability_id": 86, "evidence_type": "human_approval"},
            {"capability_id": 86, "evidence_type": "rollback_plan"},
            {"capability_id": 86, "evidence_type": "monitoring_plan"},
        ],
        ledger_valid=True,
        human_approved=False,
    )
    enabled = next(stage for stage in report["stages"] if stage["state"] == "ENABLED")
    assert enabled["missing_evidence"] == []
    assert enabled["human_authorization_required"] is True
    assert enabled["ready"] is False


def test_invalid_ledger_blocks_all_gates(tmp_path):
    path = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(path)
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    with __import__("sqlite3").connect(path) as db:
        db.execute("DROP TRIGGER capability_evidence_no_update")
        db.execute("UPDATE capability_evidence SET note='tampered'")
    report = evaluate_from_ledger(path, 85)
    assert report["assessment"] == "BLOCKED_LEDGER_INTEGRITY"
    assert all(not stage["ready"] for stage in report["stages"])


def test_evaluation_rejects_invalid_capability_id():
    import pytest

    with pytest.raises(CapabilityEvaluationError):
        evaluate_capability(True, [], ledger_valid=True)
