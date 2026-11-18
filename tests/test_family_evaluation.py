from __future__ import annotations

import json
import sqlite3

import pytest

from nexora.evidence import EVIDENCE_TYPES, EvidenceLedger
from nexora.family_evaluation import FamilyEvaluationError, build_family_evaluation


def _catalogue(path, rows):
    path.write_text(json.dumps({"capabilities": rows}), encoding="utf-8")
    return path


def _row(capability_id, family="O", name="Narrative"):
    return {
        "id": capability_id, "name": f"Capability {capability_id}",
        "family": family, "family_name": name, "status": "specified",
        "source": "test source",
    }


def test_family_report_groups_catalogue_and_exposes_missing_source_records(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [
        _row(85), _row(86), _row(91, "P", "Ethical"),
    ])
    result = build_family_evaluation(
        tmp_path / "missing.sqlite3", catalog_path=catalog,
    )
    assert result["catalogue"]["source_backed_capabilities"] == 3
    assert result["catalogue"]["missing_source_definition_count"] == 261
    assert len(result["families"]) == 40
    assert [item["family"] for item in result["families"] if item["source_backed_capabilities"]] == ["O", "P"]
    family_a = next(item for item in result["families"] if item["family"] == "A")
    assert family_a["catalogue_coverage"] == "NO_SOURCE_BACKED_RECORDS"
    assert family_a["evidence_assessment"] == "SOURCE_DEFINITIONS_NOT_PRESENT"
    assert family_a["family_name"] is None
    family_o = next(item for item in result["families"] if item["family"] == "O")
    assert family_o["source_backed_capabilities"] == 2
    assert family_o["evidence_assessment"] == "NOT_EVALUATED_NO_LEDGER"
    assert result["execution_enabled"] is False
    assert result["lifecycle_changed"] is False


def test_family_report_uses_verified_evidence_summary(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [_row(85), _row(86)])
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    result = build_family_evaluation(database, catalog_path=catalog, family="o")
    family = result["families"][0]
    first, second = family["capabilities"]
    assert family["evidence_assessment"] == "EVIDENCE_GAPS"
    assert first["evidence"]["evidence_records"] == 1
    assert "source_record" in first["evidence"]["evidence_types"]
    assert second["evidence"]["evidence_records"] == 0
    assert result["ledger"]["status"] == "VALID"


def test_family_report_blocks_corrupt_ledger(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [_row(85)])
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    ledger.add(85, "source_record", "spec:85", "a" * 64, "operator")
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER capability_evidence_no_update")
        connection.execute("UPDATE capability_evidence SET note='tampered'")
    result = build_family_evaluation(database, catalog_path=catalog)
    assert result["ledger"]["status"] == "INVALID"
    family_o = next(item for item in result["families"] if item["family"] == "O")
    assert family_o["evidence_assessment"] == "BLOCKED_LEDGER_INTEGRITY"


def test_family_report_rejects_unknown_family(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [{**_row(85), "family": "ZZ"}])
    with pytest.raises(FamilyEvaluationError, match="capability_family_unknown"):
        build_family_evaluation(catalog_path=catalog)



def test_family_report_separates_evidence_presence_from_authorization(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [_row(85)])
    database = tmp_path / "registry.sqlite3"
    ledger = EvidenceLedger(database)
    for index, evidence_type in enumerate(sorted(EVIDENCE_TYPES)):
        ledger.add(
            85, evidence_type, f"artifact:{evidence_type}",
            f"{index % 16:x}" * 64, "operator",
        )
    result = build_family_evaluation(database, catalog_path=catalog)
    family = next(item for item in result["families"] if item["family"] == "O")
    assert family["evidence_assessment"] == "EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION"
    assert (
        family["capabilities"][0]["evidence"]["assessment"]
        == "EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION"
    )
    assert result["capability_promotions_performed"] is False



def test_family_filter_reports_known_family_with_no_source_records(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [_row(85)])
    result = build_family_evaluation(catalog_path=catalog, family="a")
    assert result["filter"]["family"] == "A"
    assert result["families"] == [{
        "family": "A",
        "family_name": None,
        "catalogue_coverage": "NO_SOURCE_BACKED_RECORDS",
        "source_backed_capabilities": 0,
        "catalogue_status_counts": {},
        "evidence_assessment": "SOURCE_DEFINITIONS_NOT_PRESENT",
        "evidence_assessment_counts": {},
        "capabilities": [],
    }]


def test_family_filter_rejects_noncanonical_family(tmp_path):
    catalog = _catalogue(tmp_path / "catalog.json", [_row(85)])
    with pytest.raises(FamilyEvaluationError, match="family_filter_unknown"):
        build_family_evaluation(catalog_path=catalog, family="ZZ")
