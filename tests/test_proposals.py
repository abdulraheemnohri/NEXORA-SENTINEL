import json

import pytest

from nexora.proposals import ProposalReadError, read_proposals
from nexora.self_families import SelfFamily, SelfFamilyManager
from nexora.self_family_store import SelfFamilyProposalStore


def _proposal():
    return SelfFamilyManager().propose(
        SelfFamily.OBSERVATION,
        "Inspect current audit state",
        evidence=("source:operator-supplied",),
    )


def test_read_proposals_missing_database_does_not_create_it(tmp_path):
    database = tmp_path / "missing" / "registry.sqlite3"

    report = read_proposals(database)

    assert report["status"] == "NOT_CONFIGURED"
    assert report["proposals"] == []
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert not database.parent.exists()


def test_read_proposals_lists_pending_proposal_without_mutation(tmp_path):
    database = tmp_path / "registry.sqlite3"
    store = SelfFamilyProposalStore(database)
    store.submit(_proposal())
    original = database.read_bytes()

    report = read_proposals(database)

    assert report["status"] == "VALID"
    assert report["count"] == 1
    proposal = report["proposals"][0]
    assert proposal["review_state"] == "SUBMITTED"
    assert proposal["execution"] == "DISABLED"
    assert proposal["authorization"] == "NOT_GRANTED"
    assert proposal["payload_digest_status"] == "RECORDED_NOT_RECOMPUTED"
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert database.read_bytes() == original


def test_read_proposals_review_label_is_not_execution_authorization(tmp_path):
    database = tmp_path / "registry.sqlite3"
    store = SelfFamilyProposalStore(database)
    proposal = store.submit(_proposal())
    store.review(
        proposal["proposal_id"],
        "REVIEWED",
        operator_label="local operator",
        evidence=("review:human-check",),
        note="Reviewed for completeness only",
    )

    report = read_proposals(database, proposal_id=proposal["proposal_id"])
    item = report["proposals"][0]

    assert item["review_state"] == "REVIEWED"
    assert item["authorization"] == "NOT_GRANTED"
    assert item["execution"] == "DISABLED"
    assert report["approval_authorization_granted"] is False


def test_read_proposals_refuses_symlink_database(tmp_path):
    target = tmp_path / "registry.sqlite3"
    store = SelfFamilyProposalStore(target)
    store.submit(_proposal())
    link = tmp_path / "linked.sqlite3"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(ProposalReadError, match="symlink_refused"):
        read_proposals(link)


def test_read_proposals_rejects_invalid_identifier_and_limit(tmp_path):
    database = tmp_path / "registry.sqlite3"
    with pytest.raises(ProposalReadError, match="proposal_id_invalid"):
        read_proposals(database, proposal_id="../../outside")
    with pytest.raises(ProposalReadError, match="limit_out_of_range"):
        read_proposals(database, limit=0)


def test_proposals_cli_list_and_show_are_read_only(tmp_path, capsys):
    import sqlite3

    from nexora.cli import main

    database = tmp_path / "registry.sqlite3"
    store = SelfFamilyProposalStore(database)
    proposal = store.submit(_proposal())

    def snapshot():
        with sqlite3.connect(database) as connection:
            schema = connection.execute(
                "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
            proposals = connection.execute(
                "SELECT proposal_id,family,summary,evidence_json,payload_sha256,execution "
                "FROM self_family_proposals ORDER BY proposal_id"
            ).fetchall()
            history = connection.execute(
                "SELECT proposal_id,decision,operator_label,evidence_json,note "
                "FROM self_family_review_events ORDER BY event_id"
            ).fetchall()
        return schema, proposals, history

    original = snapshot()
    result = main([
        "proposals", "list", "--database", str(database),
    ])
    listing = json.loads(capsys.readouterr().out)
    assert result == 0
    assert listing["proposals"][0]["proposal_id"] == proposal["proposal_id"]

    result = main([
        "proposals", "show", proposal["proposal_id"],
        "--database", str(database),
    ])
    detail = json.loads(capsys.readouterr().out)
    assert result == 0
    assert detail["proposal"]["execution"] == "DISABLED"
    assert detail["proposal"]["authorization"] == "NOT_GRANTED"
    assert snapshot() == original


def test_proposals_cli_missing_store_does_not_create_data_directory(tmp_path, capsys):
    data_dir = tmp_path / "missing-data"
    result = __import__("nexora.cli", fromlist=["main"]).main([
        "--data-dir", str(data_dir), "proposals", "list",
    ])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] == "NOT_CONFIGURED"
    assert not data_dir.exists()
