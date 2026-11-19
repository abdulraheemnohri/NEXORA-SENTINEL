import json

import pytest

from nexora._oversight_impl import AuditLog
from nexora.audit_search import AuditSearchError, search_audit_log


def test_search_filters_verified_records_by_event_payload_and_sequence(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("proposal.created", {"proposal_id": "P-1"})
    log.append("policy.denied", {"reason": "unknown"})
    log.append("proposal.created", {"proposal_id": "P-2"})
    original = path.read_bytes()

    report = search_audit_log(
        path,
        event="proposal.created",
        contains="P-2",
        from_sequence=3,
        to_sequence=3,
    )

    assert report["status"] == "VALID"
    assert report["valid"] is True
    assert report["entries_verified"] == 3
    assert report["matched_entries"] == 1
    assert report["results"][0]["sequence"] == 3
    assert report["results"][0]["payload"]["proposal_id"] == "P-2"
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert path.read_bytes() == original


def test_search_limit_reports_truncation_without_skipping_chain_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for sequence in range(1, 6):
        log.append("event", {"index": sequence})

    report = search_audit_log(path, event="event", limit=2)

    assert report["entries_verified"] == 5
    assert report["matched_entries"] == 5
    assert len(report["results"]) == 2
    assert report["truncated"] is True


def test_search_missing_file_is_not_created(tmp_path):
    path = tmp_path / "missing" / "audit.jsonl"

    report = search_audit_log(path)

    assert report["status"] == "NOT_CONFIGURED"
    assert report["valid"] is None
    assert report["results"] == []
    assert not path.parent.exists()


def test_search_rejects_tampered_chain_without_returning_partial_matches(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("event", {"index": 1})
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "sequence": 2, "event": "event", "payload": {},
            "previous_hash": "0" * 64, "hash": "f" * 64,
        }) + "\n")

    with pytest.raises(AuditSearchError, match="audit_chain_integrity_failed"):
        search_audit_log(path)


def test_search_rejects_symlink_including_dangling_target(tmp_path):
    path = tmp_path / "audit.jsonl"
    target = tmp_path / "missing-target.jsonl"
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(AuditSearchError, match="audit_log_symlink_refused"):
        search_audit_log(path)


@pytest.mark.parametrize("kwargs", [
    {"limit": 0},
    {"limit": 501},
    {"from_sequence": 0},
    {"to_sequence": -1},
    {"from_sequence": 4, "to_sequence": 2},
    {"event": " "},
    {"contains": " "},
])
def test_search_rejects_invalid_filters(tmp_path, kwargs):
    with pytest.raises(AuditSearchError):
        search_audit_log(tmp_path / "missing.jsonl", **kwargs)


def test_search_rejects_boolean_sequence_even_when_hash_is_consistent(tmp_path):
    import hashlib

    from nexora._oversight_impl import GENESIS, canonical

    path = tmp_path / "audit.jsonl"
    record = {
        "sequence": True,
        "event": "event",
        "payload": {},
        "previous_hash": GENESIS,
    }
    record["hash"] = hashlib.sha256(
        (GENESIS + canonical(record)).encode("utf-8")
    ).hexdigest()
    path.write_text(json.dumps(record) + "\\n", encoding="utf-8")

    with pytest.raises(AuditSearchError, match="audit_chain_integrity_failed"):
        search_audit_log(path)
