from pathlib import Path

import pytest

from nexora.config import Settings


def test_system_yaml_loads_conservative_defaults():
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
