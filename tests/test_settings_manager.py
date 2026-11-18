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
