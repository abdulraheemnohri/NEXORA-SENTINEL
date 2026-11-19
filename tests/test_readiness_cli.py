import json

from nexora.cli import main


def test_spec_status_cli_returns_blocked_exit_code_without_mutation(tmp_path, capsys):
    result = main(["spec-status"])
    output = json.loads(capsys.readouterr().out)

    assert result == 3
    assert output["status"] == "BLOCKED"
    assert output["controls"]["execution_enabled"] is False
    assert output["controls"]["settings_mutation_enabled"] is False
    assert output["interaction_matrix"]["unknown_pairs"] == 264 * 264


def test_settings_policy_status_cli_is_review_only(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text('{"approved":true,"allow_all":true}', encoding="utf-8")

    result = main(["settings", "policy-status", "--policy", str(policy)])
    output = json.loads(capsys.readouterr().out)

    assert result == 3
    assert output["status"] == "PRESENT_REQUIRES_INDEPENDENT_REVIEW"
    assert output["authorization"] == "NOT_EVALUATED"
    assert output["settings_mutation_enabled"] is False
