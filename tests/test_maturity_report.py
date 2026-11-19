from __future__ import annotations

import json

import pytest

from nexora.evidence import EvidenceLedger
from nexora.maturity_report import MaturityReportError, build_maturity_report


def _catalog(path):
    path.write_text(json.dumps({"capabilities": [{
        "id": 85, "name": "Example capability", "family": "O",
        "family_name": "Example family", "status": "specified",
        "source": "source:addendum",
    }]}), encoding="utf-8")
    return path


def test_report_does_not_invent_l0_l4_or_promote(tmp_path):
    catalog = _catalog(tmp_path / "catalog.json")
    report = build_maturity_report(
        tmp_path / "missing.sqlite3", catalog_path=catalog,
    )
    assert report["maturity_scale"]["status"] == "UNDEFINED_SOURCE_GAP"
    assert report["maturity_scale"]["levels_assigned"] is False
    item = report["capabilities"][0]
    assert item["maturity_scale"]["assigned_level"] is None
    assert item["promotion"]["automatic_promotion"] is False
    assert item["promotion"]["execution_enabled"] is False
    assert report["lifecycle_changed"] is False


def test_report_uses_existing_lifecycle_evidence_gates(tmp_path):
    catalog = _catalog(tmp_path / "catalog.json")
    db = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(db)
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    report = build_maturity_report(db, catalog_path=catalog, capability_id=85)
    item = report["capabilities"][0]
    assert item["lifecycle_evidence"]["ledger_valid"] is True
    assert item["lifecycle_evidence"]["assessment"] == "EVIDENCE_GAPS"
    assert item["maturity_scale"]["status"] == "UNDEFINED_SOURCE_GAP"


def test_report_rejects_missing_source_record(tmp_path):
    catalog = _catalog(tmp_path / "catalog.json")
    with pytest.raises(MaturityReportError, match="capability_not_source_backed"):
        build_maturity_report(catalog_path=catalog, capability_id=86)


def test_report_fails_closed_on_corrupt_ledger(tmp_path):
    catalog = _catalog(tmp_path / "catalog.json")
    db = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(db)
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    import sqlite3
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER capability_evidence_no_update")
        conn.execute("UPDATE capability_evidence SET note='tampered'")
    report = build_maturity_report(db, catalog_path=catalog)
    assert report["ledger"]["status"] == "INVALID"
    assert report["capabilities"][0]["lifecycle_evidence"]["assessment"] == "BLOCKED_LEDGER_INTEGRITY"
