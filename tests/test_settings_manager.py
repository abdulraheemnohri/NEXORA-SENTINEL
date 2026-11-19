from __future__ import annotations

import json

import pytest

from nexora.settings_manager import load_settings, settings_report


def test_missing_settings_use_safe_defaults_without_creating_file(tmp_path):
    path = tmp_path / "settings.yaml"
    settings, present = load_settings(path)
    assert present is False
    assert settings.autonomy_level == "L0"
    assert settings.scheduler_enabled is False
    assert settings.sandbox_enabled is False
    assert settings.network_enabled is False
    assert not path.exists()


def test_valid_settings_file_is_loaded_and_reported(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"autonomy_level": "L1", "max_actions_per_hour": 12}))
    report = settings_report(path)
    assert report["valid"] is True
    assert report["file_present"] is True
    assert report["settings"]["autonomy_level"] == "L1"
    assert report["settings"]["max_actions_per_hour"] == 12
    assert report["safety"]["execution_enabled"] is False


def test_invalid_existing_settings_fail_closed(tmp_path):
    path = tmp_path / "settings.yaml"
    path.write_text("autonomy_level: L2\n")
    with pytest.raises(ValueError, match="autonomy_level_must_be_L0_or_L1"):
        load_settings(path)


def test_unknown_setting_key_is_rejected(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"autonomy_level": "L0", "allow_shell": True}))
    with pytest.raises(ValueError, match="configuration_schema_invalid"):
        load_settings(path)


def test_settings_path_must_be_a_file(tmp_path):
    with pytest.raises(ValueError, match="settings_path_not_a_file"):
        load_settings(tmp_path)


def test_settings_diff_is_preview_only_and_reports_unknown_authorization(tmp_path):
    from nexora.settings_manager import settings_diff_report

    candidate = tmp_path / "candidate.json"
    Settings(max_actions_per_hour=41, autonomy_level="L1").save(candidate)
    report = settings_diff_report(tmp_path / "missing-current.yaml", candidate)

    assert report["status"] == "REVIEW_REQUIRED"
    assert report["authorization"] == "NOT_EVALUATED"
    assert report["reason"] == "per_setting_authorization_policy_not_defined"
    assert report["human_review_required"] is True
    assert report["apply_supported"] is False
    assert report["execution_enabled"] is False
    assert {item["setting"] for item in report["changes"]} == {
        "autonomy_level", "max_actions_per_hour"
    }
    assert not (tmp_path / "missing-current.yaml").exists()


def test_settings_diff_requires_existing_valid_candidate(tmp_path):
    from nexora.settings_manager import settings_diff_report

    with pytest.raises(ValueError, match="candidate_settings_file_required"):
        settings_diff_report(None, tmp_path / "missing.json")

    candidate = tmp_path / "invalid.json"
    candidate.write_text('{"allow_shell": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="configuration_schema_invalid"):
        settings_diff_report(None, candidate)


def test_settings_diff_identical_candidate_has_no_review_or_mutation(tmp_path):
    from nexora.settings_manager import settings_diff_report

    current = tmp_path / "current.json"
    candidate = tmp_path / "candidate.json"
    Settings().save(current)
    Settings().save(candidate)
    report = settings_diff_report(current, candidate)

    assert report["status"] == "NO_CHANGES"
    assert report["changed_count"] == 0
    assert report["human_review_required"] is False
    assert report["apply_supported"] is False
    assert current.read_bytes() == candidate.read_bytes()


def test_cli_settings_diff_returns_review_required_without_applying(tmp_path, capsys):
    from nexora.cli import main

    candidate = tmp_path / "candidate.json"
    Settings(autonomy_level="L1").save(candidate)
    result = main([
        "settings", "diff",
        "--config", str(tmp_path / "missing.json"),
        "--candidate", str(candidate),
    ])
    output = json.loads(capsys.readouterr().out)

    assert result == 3
    assert output["status"] == "REVIEW_REQUIRED"
    assert output["apply_supported"] is False
    assert not (tmp_path / "missing.json").exists()