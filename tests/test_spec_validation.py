import json

import pytest

from nexora.spec_validation import validate_specification


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _artifacts(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    matrix = tmp_path / "matrix.json"
    precedence = tmp_path / "precedence.json"
    _write(
        catalog,
        {
            "schema_version": "1.1",
            "expected_capability_count": 264,
            "expected_family_count": 40,
            "status": "partial_source_import",
            "missing_ranges": ["2-264"],
            "capabilities": [
                {
                    "id": 1,
                    "name": "Source capability",
                    "family": "A",
                    "family_name": "Cognitive",
                    "status": "specified",
                    "source": "STA charter, section 3",
                }
            ],
        },
    )
    _write(
        rules,
        {
            "schema_version": "1.1",
            "expected_rule_count": 45,
            "status": "partial_source_import",
            "missing_rule_ranges": ["2-45"],
            "rules": [
                {
                    "id": 1,
                    "title": "Source rule",
                    "text": "Exact source text.",
                    "status": "specified",
                    "mutable_by_agent": False,
                }
            ],
        },
    )
    _write(
        matrix,
        {
            "schema_version": "1.1",
            "dimensions": [264, 264],
            "capability_id_range": [1, 264],
            "status": "unpopulated",
            "default_relation": "unknown",
            "unknown_relation_policy": "deny_or_require_human_review",
            "allowed_relations": [
                "reinforces",
                "conflicts",
                "subsumes",
                "depends_on",
                "composes_with",
                "preempts",
            ],
            "entries": [],
        },
    )
    _write(
        precedence,
        {
            "priority_order": [
                "SAFETY",
                "GOVERNANCE",
                "OPERATIONAL",
                "CONVENIENCE",
            ],
            "unknown_conflict": "BLOCK_AND_ESCALATE",
            "equal_priority_conflict": "BLOCK_AND_ESCALATE",
            "mutable_by_agent": False,
        },
    )
    return catalog, rules, matrix, precedence


def _validate(paths):
    catalog, rules, matrix, precedence = paths
    return validate_specification(
        catalog_path=catalog,
        rules_path=rules,
        matrix_path=matrix,
        precedence_path=precedence,
    )


def test_repository_sources_are_valid_but_incomplete():
    report = validate_specification()

    assert report["valid"] is True
    assert report["status"] == "VALID_PARTIAL_BLOCKED"
    assert report["complete"] is False
    assert report["artifacts"]["capability_catalogue"]["registered"] == 180
    assert report["artifacts"]["capability_catalogue"]["missing_ids"] == list(range(1, 85))
    assert report["artifacts"]["meta_rules"]["registered"] == 30
    assert report["artifacts"]["meta_rules"]["missing_ids"] == list(range(1, 16))
    assert report["artifacts"]["interaction_matrix"]["declared_pairs"] == 0
    assert report["artifacts"]["interaction_matrix"]["unknown_pairs"] == 264 * 264
    assert report["controls"]["read_only"] is True
    assert report["controls"]["source_mutation_enabled"] is False
    assert report["controls"]["execution_enabled"] is False


def test_minimal_partial_artifacts_validate_without_becoming_complete(tmp_path):
    report = _validate(_artifacts(tmp_path))

    assert report["valid"] is True
    assert report["status"] == "VALID_PARTIAL_BLOCKED"
    assert report["complete"] is False
    assert report["artifacts"]["capability_catalogue"]["missing_ranges"] == ["2-264"]
    assert report["artifacts"]["meta_rules"]["missing_ranges"] == ["2-45"]


def test_declared_missing_ranges_must_match_actual_missing_ids(tmp_path):
    paths = _artifacts(tmp_path)
    catalog_path = paths[0]
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["missing_ranges"] = ["3-264"]
    _write(catalog_path, catalog)

    report = _validate(paths)

    assert report["valid"] is False
    assert any(
        error["code"] == "declared_missing_ranges_do_not_match_records"
        for error in report["errors"]
    )


def test_meta_rules_must_remain_immutable_to_agent(tmp_path):
    paths = _artifacts(tmp_path)
    rules_path = paths[1]
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    rules["rules"][0]["mutable_by_agent"] = True
    _write(rules_path, rules)

    report = _validate(paths)

    assert report["valid"] is False
    assert any(
        error["code"] == "meta_rule_must_be_immutable_to_agent"
        for error in report["errors"]
    )


def test_matrix_entries_require_source_provenance_and_evidence_digest(tmp_path):
    paths = _artifacts(tmp_path)
    matrix_path = paths[2]
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["entries"] = [{"source": 1, "target": 1, "relation": "reinforces"}]
    _write(matrix_path, matrix)

    report = _validate(paths)

    assert report["valid"] is False
    codes = {error["code"] for error in report["errors"]}
    assert "interaction_source_reference_required" in codes
    assert "interaction_evidence_sha256_required" in codes


def test_matrix_relations_cannot_reference_missing_catalogue_records(tmp_path):
    paths = _artifacts(tmp_path)
    matrix_path = paths[2]
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["entries"] = [
        {
            "source": 1,
            "target": 2,
            "relation": "depends_on",
            "source_ref": "STA charter, section 8",
            "evidence_sha256": "a" * 64,
        }
    ]
    _write(matrix_path, matrix)

    report = _validate(paths)

    assert report["valid"] is False
    assert any(
        error["code"] == "relation_references_missing_capability"
        for error in report["errors"]
    )


def test_matrix_requires_exact_dimensions_and_fail_closed_unknown_policy(tmp_path):
    paths = _artifacts(tmp_path)
    matrix_path = paths[2]
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["dimensions"] = [263, 264]
    matrix["unknown_relation_policy"] = "allow"
    _write(matrix_path, matrix)

    report = _validate(paths)

    assert report["valid"] is False
    codes = {error["code"] for error in report["errors"]}
    assert "dimensions_must_be_264_by_264" in codes
    assert "unknown_relation_policy_must_fail_closed" in codes


def test_duplicate_json_keys_are_rejected(tmp_path):
    paths = list(_artifacts(tmp_path))
    paths[0].write_text(
        '{"expected_capability_count":264,"expected_capability_count":999,'
        '"expected_family_count":40,"status":"partial_source_import",'
        '"missing_ranges":["1-264"],"capabilities":[]}',
        encoding="utf-8",
    )

    report = _validate(tuple(paths))

    assert report["valid"] is False
    assert any(
        error["code"] == "duplicate_json_key:expected_capability_count"
        for error in report["errors"]
    )


def test_symlinked_specification_artifact_is_refused(tmp_path):
    paths = list(_artifacts(tmp_path))
    target = paths[0]
    link = tmp_path / "catalog-link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    paths[0] = link

    report = _validate(tuple(paths))

    assert report["valid"] is False
    assert any(
        error["code"] == "symlink_refused"
        and error["artifact"] == "capability_catalogue"
        for error in report["errors"]
    )


def test_spec_validate_cli_reports_structural_success_without_claiming_readiness(capsys):
    from nexora.cli import main

    result = main(["spec-validate"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["status"] == "VALID_PARTIAL_BLOCKED"
    assert payload["valid"] is True
    assert payload["complete"] is False
    assert payload["controls"]["execution_enabled"] is False
