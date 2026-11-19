import json

from nexora.cli import main


def test_doctor_cli_does_not_create_the_data_directory(tmp_path, capsys):
    data_dir = tmp_path / "missing-data"
    result = main(["--data-dir", str(data_dir), "doctor"])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] in {"DEGRADED", "ATTENTION_REQUIRED"}
    assert report["safety"]["read_only"] is True
    assert report["safety"]["data_directory_created"] is False
    assert report["safety"]["execution_enabled"] is False
    assert not data_dir.exists()


def test_kill_switch_test_cli_never_touches_production_marker(tmp_path, capsys):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    marker = data_dir / "KILL"
    marker.write_text("existing emergency stop\n", encoding="utf-8")

    result = main(["--data-dir", str(data_dir), "kill-switch-test"])
    report = json.loads(capsys.readouterr().out)

    assert result == 0
    assert report["status"] == "PASS"
    assert report["production_marker_touched"] is False
    assert marker.read_text(encoding="utf-8") == "existing emergency stop\n"
