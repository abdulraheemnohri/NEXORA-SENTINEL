import json

import pytest

from nexora._oversight_impl import AuditLog
from nexora.audit_search import AuditSearchError, search_audit_log


def test_audit_search_verifies_chain_and_filters(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("proposal.created", {"proposal": "a"})
    log.append("policy.decision", {"allowed": False, "reason": "unknown"})
    log.append("proposal.reviewed", {"proposal": "a"})

    report = search_audit_log(
        path, event="proposal.created", from_sequence=1, to_sequence=2
    )

    assert report["valid"] is True
    assert report["total_entries"] == 3
    assert report["matched_entries"] == 1
    assert report["results"][0]["sequence"] == 1
    assert report["read_only"] is True


def test_audit_search_text_filter_and_limit(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for index in range(4):
        log.append("task.completed", {"name": f"build-{index}"})

    report = search_audit_log(path, contains="BUILD", limit=2)

    assert report["matched_entries"] == 4
    assert report["returned_entries"] == 2
    assert [row["sequence"] for row in report["results"]] == [3, 4]


def test_audit_search_refuses_tampered_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("task.completed", {"name": "safe"})
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"sequence": 2, "event": "forged"}) + "\n")

    with pytest.raises(AuditSearchError, match="hash_chain_invalid"):
        search_audit_log(path)


def test_audit_search_refuses_symlink_path(tmp_path):
    target = tmp_path / "real.jsonl"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(AuditSearchError, match="path_unsafe"):
        search_audit_log(link)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"event": ""}, "event_filter_invalid"),
        ({"limit": 0}, "limit_out_of_range"),
        ({"from_sequence": 0}, "from_sequence_must_be_positive"),
        ({"from_sequence": 5, "to_sequence": 4}, "sequence_range_invalid"),
    ],
)
def test_audit_search_rejects_invalid_filters(tmp_path, kwargs, message):
    with pytest.raises(AuditSearchError, match=message):
        search_audit_log(tmp_path / "missing.jsonl", **kwargs)
