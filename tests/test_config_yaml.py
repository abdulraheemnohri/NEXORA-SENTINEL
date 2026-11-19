from __future__ import annotations

import json
import os
import stat

import pytest

from nexora.config import Settings


def test_system_yaml_loads_conservative_defaults():
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "config" / "system.yaml"
    settings = Settings.load(path)
    assert settings.autonomy_level == "L0"
    assert not settings.scheduler_enabled
    assert not settings.sandbox_enabled
    assert not settings.network_enabled


def test_yaml_rejects_unknown_fields(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("autonomy_level: L0\nallow_everything: true\n")
    with pytest.raises(ValueError, match="configuration_schema_invalid"):
        Settings.load(path)


def test_yaml_save_round_trip(tmp_path):
    path = tmp_path / "settings.yaml"
    original = Settings().validate()
    original.save(path)
    assert Settings.load(path) == original


def test_save_replaces_existing_file_atomically_and_keeps_valid_json(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"autonomy_level": "L0"}), encoding="utf-8")
    updated = Settings(max_actions_per_hour=17)
    updated.save(path)
    assert Settings.load(path) == updated
    assert json.loads(path.read_text(encoding="utf-8"))["max_actions_per_hour"] == 17


def test_save_failure_preserves_previous_file_and_cleans_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    original = '{"autonomy_level": "L0"}\n'
    path.write_text(original, encoding="utf-8")

    def fail_replace(_source, _target):
        raise OSError("simulated_replace_failure")

    monkeypatch.setattr("nexora.config.os.replace", fail_replace)
    with pytest.raises(OSError, match="simulated_replace_failure"):
        Settings().save(path)

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".settings.json.*.tmp")) == []


def test_save_refuses_symlink_target_without_modifying_link_target(tmp_path):
    actual = tmp_path / "actual.json"
    actual.write_text('{"autonomy_level":"L0"}', encoding="utf-8")
    link = tmp_path / "settings.json"
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="settings_target_is_symlink"):
        Settings().save(link)
    assert link.is_symlink()
    assert actual.read_text(encoding="utf-8") == '{"autonomy_level":"L0"}'


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode assertion")
def test_save_creates_private_settings_file(tmp_path):
    path = tmp_path / "settings.json"
    Settings().save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_refuses_directory_target(tmp_path):
    target = tmp_path / "settings-dir"
    target.mkdir()
    with pytest.raises(ValueError, match="settings_target_not_a_file"):
        Settings().save(target)
