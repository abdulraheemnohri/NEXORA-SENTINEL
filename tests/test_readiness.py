import json

import pytest

from nexora.readiness import build_settings_policy_status, build_spec_status


def _write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_settings_policy_status_never_treats_presence_as_approval(tmp_path):
    policy = tmp_path / "settings_authorization.json"
    _write(policy, {"approved": True, "allow_all": True})

    report = build_settings_policy_status(policy)

    assert report["status"] == "PRESENT_REQUIRES_INDEPENDENT_REVIEW"
    assert report["authorization"] == "NOT_EVALUATED"
    assert report["apply_supported"] is False
    assert report["settings_mutation_enabled"] is False
    assert report["rollback_supported"] is False


def test_settings_policy_status_lists_all_settings_as_unapproved(tmp_path):
    report = build_settings_policy_status(tmp_path / "missing.json")

    assert report["status"] == "POLICY_NOT_APPROVED"
    assert "autonomy_level" in report["settings_without_approved_authorization"]
    assert "network_enabled" in report["settings_without_approved_authorization"]
    assert report["missing_policy_controls"]
    assert len(report["proposed_settings_not_implemented"]) == 7


def test_settings_policy_rejects_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "policy.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="is_symlink"):
        build_settings_policy_status(link)


def test_spec_status_reports_missing_source_and_unknown_matrix(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    matrix = tmp_path / "matrix.json"
    precedence = tmp_path / "precedence.json"
    policy = tmp_path / "policy.json"
    _write(catalog, {
        "expected_capability_count": 264,
        "expected_family_count": 40,
        "status": "partial_source_import",
        "capabilities": [
            {"id": i, "name": f"Capability {i}", "family": "A",
             "family_name": "Alpha", "status": "specified", "source": "source"}
            for i in range(85, 265)
        ],
        "missing_ranges": ["1-84"],
    })
    _write(rules, {
        "expected_rule_count": 45,
        "rules": [
            {"id": i, "title": f"Rule {i}", "text": "Source text",
             "status": "specified", "mutable_by_agent": False}
            for i in range(16, 46)
        ],
        "missing_rule_ranges": ["1-15"],
    })
    _write(matrix, {
        "schema_version": "1.1", "dimensions": [264, 264],
        "capability_id_range": [1, 264], "status": "unpopulated",
        "default_relation": "unknown",
        "unknown_relation_policy": "deny_or_require_human_review",
        "allowed_relations": [
            "reinforces", "conflicts", "subsumes", "depends_on",
            "composes_with", "preempts",
        ],
        "entries": [],
    })
    _write(precedence, {
        "priority_order": ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"],
        "unknown_conflict": "BLOCK_AND_ESCALATE",
        "equal_priority_conflict": "BLOCK_AND_ESCALATE",
        "mutable_by_agent": False,
    })

    report = build_spec_status(catalog, rules, matrix, precedence, policy)

    assert report["status"] == "BLOCKED"
    assert report["source_recovery"]["capabilities"]["missing_ids"] == list(range(1, 85))
    assert report["source_recovery"]["meta_rules"]["missing_ids"] == list(range(1, 16))
    assert report["capability_catalogue"]["registered_capabilities"] == 180
    assert report["interaction_matrix"]["unknown_pairs"] == 264 * 264
    assert report["controls"]["execution_enabled"] is False
    assert report["controls"]["settings_mutation_enabled"] is False
    assert {item["id"] for item in report["blockers"]} == {
        "missing_capability_source", "missing_meta_rule_source",
        "interaction_matrix_unknown_pairs", "settings_authorization_and_rollback",
        "capability_family_coverage",
    }


def test_spec_status_does_not_grant_ready_from_complete_sources_if_policy_missing(tmp_path):
    catalog = tmp_path / "catalog.json"
    rules = tmp_path / "rules.json"
    matrix = tmp_path / "matrix.json"
    precedence = tmp_path / "precedence.json"
    _write(catalog, {
        "expected_capability_count": 264, "expected_family_count": 40,
        "status": "complete", "missing_ranges": [],
        "capabilities": [
            {"id": i, "name": f"Capability {i}", "family": "A",
             "family_name": "Alpha", "status": "specified", "source": "source"}
            for i in range(1, 265)
        ],
    })
    _write(rules, {
        "expected_rule_count": 45, "status": "complete", "missing_rule_ranges": [],
        "rules": [
            {"id": i, "title": f"Rule {i}", "text": "Source text",
             "status": "specified", "mutable_by_agent": False}
            for i in range(1, 46)
        ],
    })
    _write(matrix, {
        "schema_version": "1.1", "dimensions": [264, 264],
        "capability_id_range": [1, 264], "status": "unpopulated",
        "default_relation": "unknown",
        "unknown_relation_policy": "deny_or_require_human_review",
        "allowed_relations": [
            "reinforces", "conflicts", "subsumes", "depends_on",
            "composes_with", "preempts",
        ],
        "entries": [],
    })
    _write(precedence, {
        "priority_order": ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"],
        "unknown_conflict": "BLOCK_AND_ESCALATE",
        "equal_priority_conflict": "BLOCK_AND_ESCALATE",
        "mutable_by_agent": False,
    })

    report = build_spec_status(catalog, rules, matrix, precedence, tmp_path / "missing-policy.json")
    assert report["status"] == "BLOCKED"
    assert any(x["id"] == "settings_authorization_and_rollback" for x in report["blockers"])



def test_spec_status_cli_reports_blocked_without_mutation(tmp_path, capsys):
    from nexora.cli import main

    result = main(["spec-status"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 3
    assert payload["status"] == "BLOCKED"
    assert payload["controls"]["execution_enabled"] is False
    assert payload["controls"]["settings_mutation_enabled"] is False


def test_settings_policy_status_cli_is_read_only(tmp_path, capsys):
    from nexora.cli import main

    policy = tmp_path / "not-created.json"
    result = main(["settings", "policy-status", "--policy", str(policy)])
    payload = json.loads(capsys.readouterr().out)

    assert result == 3
    assert payload["status"] == "POLICY_NOT_APPROVED"
    assert not policy.exists()
