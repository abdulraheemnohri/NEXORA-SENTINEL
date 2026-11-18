from __future__ import annotations

import json

import pytest

from nexora.self_capability_report import build_report


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_report_exposes_missing_ranges_without_fabricating_records(tmp_path):
    catalog = _write(tmp_path / "catalog.json", {
        "status": "partial_source_import",
        "capabilities": [{"id": 85, "name": "Self-Narrating", "family": "O",
            "family_name": "Narrative", "source": "Addendum III", "status": "specified"}],
        "cross_cutting_layers": ["Layer X"],
    })
    rules = _write(tmp_path / "rules.json", {"status": "partial_source_import",
        "rules": [{"id": 16, "title": "Narrative from truth", "text": "Audit-derived.",
                   "status": "specified"}]})
    matrix = _write(tmp_path / "matrix.json", {"dimensions": [264, 264],
        "status": "unpopulated", "unknown_relation_policy": "deny_or_require_human_review",
        "entries": []})
    report = build_report(catalog_path=catalog, rules_path=rules, matrix_path=matrix,
                          include_records=True)
    assert report["catalogue"]["source_backed_capabilities"] == 1
    assert report["catalogue"]["missing_capability_ids"][:2] == [1, 2]
    assert report["meta_rules"]["missing_rule_ids"][:2] == [1, 2]
    assert report["records"][0]["id"] == 85
    assert report["execution_enabled"] is False


def test_report_filters_family_case_insensitively(tmp_path):
    catalog = _write(tmp_path / "catalog.json", {"capabilities": [
        {"id": 85, "name": "A", "family": "O", "family_name": "Narrative",
         "source": "Addendum III", "status": "specified"},
        {"id": 86, "name": "B", "family": "P", "family_name": "Ethical",
         "source": "Addendum III", "status": "specified"}]})
    rules = _write(tmp_path / "rules.json", {"rules": []})
    matrix = _write(tmp_path / "matrix.json", {"entries": [], "dimensions": [264, 264]})
    report = build_report(catalog_path=catalog, rules_path=rules, matrix_path=matrix,
                          family="o", include_records=True)
    assert [item["id"] for item in report["records"]] == [85]


def test_report_rejects_duplicate_capability_ids(tmp_path):
    row = {"id": 85, "name": "A", "family": "O", "family_name": "Narrative",
           "source": "Addendum III", "status": "specified"}
    catalog = _write(tmp_path / "catalog.json", {"capabilities": [row, row]})
    rules = _write(tmp_path / "rules.json", {"rules": []})
    matrix = _write(tmp_path / "matrix.json", {"entries": []})
    with pytest.raises(ValueError, match="duplicate_capability_id"):
        build_report(catalog_path=catalog, rules_path=rules, matrix_path=matrix)


def test_report_rejects_duplicate_meta_rule_ids(tmp_path):
    row = {"id": 16, "title": "Rule", "text": "Text", "status": "specified"}
    catalog = _write(tmp_path / "catalog.json", {"capabilities": []})
    rules = _write(tmp_path / "rules.json", {"rules": [row, row]})
    matrix = _write(tmp_path / "matrix.json", {"entries": []})
    with pytest.raises(ValueError, match="duplicate_meta_rule_id"):
        build_report(catalog_path=catalog, rules_path=rules, matrix_path=matrix)
