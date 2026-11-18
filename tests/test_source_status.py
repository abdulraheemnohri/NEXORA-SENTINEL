import json

from nexora.source_status import build_source_status


def test_source_status_reports_missing_ids_without_inventing_records(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    catalog.write_text(json.dumps({
        "status": "partial_source_import",
        "capabilities": [{"id": 85, "name": "source-backed"}],
    }), encoding="utf-8")
    rules.write_text(json.dumps({
        "status": "partial_source_import",
        "rules": [{"id": 16, "title": "source-backed"}],
    }), encoding="utf-8")

    result = build_source_status(catalog, rules)

    assert result["status"] == "SOURCE_RECOVERY_REQUIRED"
    assert result["capabilities"]["missing_ids"][:3] == [1, 2, 3]
    assert result["capabilities"]["missing_ids"][-1] == 264
    assert result["meta_rules"]["missing_ids"] == list(range(1, 16))
    assert result["import_contract"]["automatic_import_performed"] is False
    assert result["execution_enabled"] is False
    assert result["policy_mutation_enabled"] is False


def test_source_status_rejects_non_list_records(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    catalog.write_text(json.dumps({"capabilities": {}}), encoding="utf-8")
    rules.write_text(json.dumps({"rules": []}), encoding="utf-8")

    import pytest
    with pytest.raises(ValueError, match="source_artifact_records_must_be_lists"):
        build_source_status(catalog, rules)


def test_source_status_rejects_duplicate_ids(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    catalog.write_text(json.dumps({
        "capabilities": [{"id": 85}, {"id": 85}],
    }), encoding="utf-8")
    rules.write_text(json.dumps({"rules": []}), encoding="utf-8")

    import pytest
    with pytest.raises(ValueError, match="capability_duplicate_id"):
        build_source_status(catalog, rules)
