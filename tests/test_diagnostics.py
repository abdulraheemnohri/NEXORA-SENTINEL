import hashlib
import json

from nexora.diagnostics import build_doctor_report


def test_doctor_does_not_create_data_directory_or_initialize_subsystems(tmp_path):
    data_dir = tmp_path / "not-created"

    report = build_doctor_report(data_dir)

    assert not data_dir.exists()
    assert report["status"] in {"DEGRADED", "ATTENTION_REQUIRED"}
    assert report["checks"]["audit"]["status"] == "NOT_CONFIGURED"
    assert report["checks"]["memory"]["status"] == "NOT_CONFIGURED"
    assert report["checks"]["registry"]["status"] == "NOT_CONFIGURED"
    assert report["safety"]["read_only"] is True
    assert report["safety"]["data_directory_created"] is False
    assert report["safety"]["execution_enabled"] is False
    assert report["safety"]["settings_mutation_enabled"] is False


def test_doctor_marks_corrupt_audit_chain_as_blocking_without_repair(tmp_path):
    data_dir = tmp_path / "existing-data"
    data_dir.mkdir()
    audit = data_dir / "audit.jsonl"
    original = '{"sequence":1,"event":"fake","payload":{},"previous_hash":"bad","hash":"bad"}\n'
    audit.write_text(original, encoding="utf-8")

    report = build_doctor_report(data_dir)

    assert report["status"] == "ATTENTION_REQUIRED"
    assert report["checks"]["audit"]["status"] == "INVALID"
    assert audit.read_text(encoding="utf-8") == original
    assert not (data_dir / "registry.sqlite3").exists()


def test_doctor_reports_kill_switch_without_clearing_it(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    marker = data_dir / "KILL"
    marker.write_text("operator stop\n", encoding="utf-8")

    report = build_doctor_report(data_dir)

    assert report["checks"]["kill_switch"]["status"] == "ENGAGED"
    assert report["checks"]["kill_switch"]["engaged"] is True
    assert marker.read_text(encoding="utf-8") == "operator stop\n"
    assert report["safety"]["execution_enabled"] is False


def test_doctor_cli_returns_report_without_creating_data_directory(tmp_path, capsys):
    from nexora.cli import main

    data_dir = tmp_path / "cli-doctor-data"
    result = main(["--data-dir", str(data_dir), "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 3
    assert payload["status"] in {"DEGRADED", "ATTENTION_REQUIRED"}
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["execution_enabled"] is False
    assert not data_dir.exists()


def test_doctor_rejects_boolean_audit_sequence_even_with_valid_hash(tmp_path):
    from nexora._oversight_impl import GENESIS, canonical

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    record = {
        "sequence": True,
        "event": "test.event",
        "payload": {},
        "previous_hash": GENESIS,
    }
    record["hash"] = hashlib.sha256(
        (GENESIS + canonical(record)).encode("utf-8")
    ).hexdigest()
    audit = data_dir / "audit.jsonl"
    audit.write_text(json.dumps(record) + "\\n", encoding="utf-8")

    report = build_doctor_report(data_dir)

    assert report["checks"]["audit"]["status"] == "INVALID"
    assert report["safety"]["execution_enabled"] is False
