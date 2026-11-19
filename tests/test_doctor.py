import json

from nexora._oversight_impl import AuditLog
from nexora.doctor import build_doctor_report
from nexora.self_tests import run_kill_switch_self_test


def test_doctor_is_read_only_and_does_not_initialize_storage(tmp_path):
    data_dir = tmp_path / "absent-data"
    report = build_doctor_report(data_dir)

    assert report["status"] == "BLOCKED"
    assert report["read_only"] is True
    assert report["checks"]["audit_log"]["status"] == "NOT_INITIALIZED"
    assert report["checks"]["registry_database"]["status"] == "NOT_INITIALIZED"
    assert report["controls"]["storage_created"] is False
    assert report["controls"]["execution_enabled"] is False
    assert not data_dir.exists()


def test_doctor_detects_audit_tampering(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log = AuditLog(data_dir / "audit.jsonl")
    log.append("test.event", {"value": 1})
    with (data_dir / "audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"tampered": True}) + "\n")

    report = build_doctor_report(data_dir)

    assert report["status"] == "CRITICAL"
    assert report["checks"]["audit_log"]["status"] == "INVALID"
    assert "audit_log" in report["critical_failures"]


def test_doctor_reports_kill_switch_without_clearing_it(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    marker = data_dir / "KILL"
    marker.write_text("operator stop\n", encoding="utf-8")

    report = build_doctor_report(data_dir)

    assert report["checks"]["kill_switch"]["status"] == "ENGAGED"
    assert report["checks"]["kill_switch"]["engaged"] is True
    assert marker.read_text(encoding="utf-8") == "operator stop\n"


def test_kill_switch_self_test_uses_temporary_marker_only():
    report = run_kill_switch_self_test()

    assert report["status"] == "PASS"
    assert all(report["checks"].values())
    assert report["production_marker_touched"] is False
    assert report["temporary_workspace_cleaned"] is True
    assert report["execution_enabled"] is False
