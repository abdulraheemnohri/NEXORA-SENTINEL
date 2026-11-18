import json

import pytest

from nexora.source_import import SourceImportError, preview_source_import


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def test_capability_import_preview_is_sorted_and_read_only(tmp_path):
    catalog = tmp_path / "catalog.json"
    artifact = tmp_path / "candidate.json"
    _write(catalog, {"capabilities": [{"id": 85}]})
    _write(artifact, {"capabilities": [
        {"id": 2, "name": "Exact B", "family": "A", "family_name": "Alpha",
         "status": "specified", "source": "Original document"},
        {"id": 1, "name": "Exact A", "family": "A", "family_name": "Alpha",
         "status": "specified", "source": "Original document"},
    ]})

    result = preview_source_import(
        artifact, kind="capability", source_ref="Original document, section 2",
        catalog_path=catalog,
    )

    assert result["candidate_ids"] == [1, 2]
    assert result["status"] == "PREVIEW_READY"
    assert result["canonical_write_performed"] is False
    assert json.loads(catalog.read_text()) == {"capabilities": [{"id": 85}]}


def test_import_preview_rejects_existing_id_collision(tmp_path):
    catalog = tmp_path / "catalog.json"
    artifact = tmp_path / "candidate.json"
    _write(catalog, {"capabilities": [{"id": 85}]})
    _write(artifact, {"capabilities": [
        {"id": 85, "name": "Collision", "family": "A", "family_name": "Alpha",
         "status": "specified", "source": "Original"},
    ]})

    with pytest.raises(SourceImportError, match="existing_id_collision:85"):
        preview_source_import(
            artifact, kind="capability", source_ref="Original",
            catalog_path=catalog,
        )


def test_import_preview_rejects_duplicate_and_missing_provenance(tmp_path):
    catalog = tmp_path / "catalog.json"
    artifact = tmp_path / "candidate.json"
    _write(catalog, {"capabilities": []})
    row = {"id": 1, "name": "A", "family": "A", "family_name": "Alpha",
           "status": "specified", "source": "Original"}
    _write(artifact, {"capabilities": [row, row]})
    with pytest.raises(SourceImportError, match="duplicate_candidate_id:1"):
        preview_source_import(
            artifact, kind="capability", source_ref="Original",
            catalog_path=catalog,
        )
    with pytest.raises(SourceImportError, match="source_ref_required"):
        preview_source_import(
            artifact, kind="capability", source_ref=" ",
            catalog_path=catalog,
        )


def test_meta_rule_preview_checks_boolean_and_exact_fields(tmp_path):
    rules = tmp_path / "rules.json"
    artifact = tmp_path / "candidate.json"
    _write(rules, {"rules": [{"id": 16}]})
    _write(artifact, {"rules": [
        {"id": 1, "title": "Rule", "text": "Exact rule text",
         "status": "specified", "mutable_by_agent": "false"},
    ]})
    with pytest.raises(SourceImportError, match="mutable_flag_must_be_boolean"):
        preview_source_import(
            artifact, kind="meta-rule", source_ref="Original rules",
            rules_path=rules,
        )
