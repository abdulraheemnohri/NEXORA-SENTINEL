import json

from nexora._oversight_impl import AuditLog
from nexora.cli import main


def test_audit_search_cli_filters_without_mutating_log(tmp_path, capsys):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log_path = data_dir / "audit.jsonl"
    log = AuditLog(log_path)
    log.append("proposal.created", {"id": "a"})
    log.append("policy.denied", {"reason": "unknown"})
    original = log_path.read_bytes()

    result = main([
        "--data-dir", str(data_dir), "audit-search",
        "--event", "proposal.created",
    ])
    report = json.loads(capsys.readouterr().out)

    assert result == 0
    assert report["valid"] is True
    assert report["matched_entries"] == 1
    assert report["results"][0]["event"] == "proposal.created"
    assert log_path.read_bytes() == original


def test_audit_search_cli_missing_log_does_not_create_storage(tmp_path, capsys):
    data_dir = tmp_path / "missing-data"
    result = main(["--data-dir", str(data_dir), "audit-search"])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] == "NOT_CONFIGURED"
    assert not data_dir.exists()
