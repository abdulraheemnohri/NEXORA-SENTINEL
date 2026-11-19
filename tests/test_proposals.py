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
    from nexora.cli import main

    database = tmp_path / "registry.sqlite3"
    store = SelfFamilyProposalStore(database)
    proposal = store.submit(_proposal())
    original = database.read_bytes()

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
    assert database.read_bytes() == original


def test_proposals_cli_missing_store_does_not_create_data_directory(tmp_path, capsys):
    data_dir = tmp_path / "missing-data"
    result = __import__("nexora.cli", fromlist=["main"]).main([
        "--data-dir", str(data_dir), "proposals", "list",
    ])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] == "NOT_CONFIGURED"
    assert not data_dir.exists()



def _signed_review_fixture(tmp_path):
    from nexora.approval import ApprovalReceiptStore, generate_keypair, load_public_key

    database = tmp_path / "registry.sqlite3"
    proposal = SelfFamilyProposalStore(database).submit(_proposal())
    trust = ApprovalReceiptStore(database)
    reviewers = []
    for index in range(2):
        private_path = tmp_path / f"reviewer-{index + 1}" / "private.pem"
        public_path = tmp_path / f"reviewer-{index + 1}" / "public.pem"
        generate_keypair(private_path, public_path)
        trust.enroll_key(load_public_key(public_path), label=f"reviewer-{index + 1}")
        reviewers.append((private_path, f"reviewer-{index + 1}"))
    return database, proposal, reviewers


def _review_receipts(database, proposal, reviewers, *, decision="REVIEWED", evidence=None):
    from nexora.proposal_review import create_proposal_review_receipt

    evidence = evidence or ["review:source-check", "review:safety-check"]
    return [
        create_proposal_review_receipt(
            database,
            proposal["proposal_id"],
            private_path,
            decision=decision,
            evidence=evidence,
            approver_id=approver_id,
        )
        for private_path, approver_id in reviewers
    ]


def test_signed_proposal_review_requires_two_distinct_enrolled_reviewers(tmp_path):
    from nexora.proposal_review import record_signed_proposal_review
    from nexora.proposals import read_proposals

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    receipts = _review_receipts(database, proposal, reviewers)
    result = record_signed_proposal_review(database, proposal["proposal_id"], receipts)
    item = read_proposals(database, proposal_id=proposal["proposal_id"])["proposals"][0]

    assert result["status"] == "VERIFIED_AND_RECORDED"
    assert result["lifecycle_approval_granted"] is False
    assert result["authorization"] == "NOT_GRANTED"
    assert result["execution_enabled"] is False
    assert item["signed_review"]["status"] == "VERIFIED"
    assert item["signed_review"]["decision"] == "REVIEWED"
    assert item["signed_review"]["signer_count"] == 2
    assert item["authorization"] == "NOT_GRANTED"
    assert item["execution"] == "DISABLED"


def test_signed_proposal_review_rejects_one_reviewer_and_untrusted_key(tmp_path):
    from nexora.approval import generate_keypair
    from nexora.proposal_review import (
        ProposalReviewError,
        create_proposal_review_receipt,
        record_signed_proposal_review,
    )

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    one = _review_receipts(database, proposal, reviewers[:1])
    with pytest.raises(ProposalReviewError, match="threshold_not_met"):
        record_signed_proposal_review(database, proposal["proposal_id"], one)

    untrusted_private = tmp_path / "untrusted.pem"
    untrusted_public = tmp_path / "untrusted.pub.pem"
    generate_keypair(untrusted_private, untrusted_public)
    unknown = create_proposal_review_receipt(
        database, proposal["proposal_id"], untrusted_private,
        decision="REVIEWED", evidence=["review:check"], approver_id="untrusted",
    )
    trusted = create_proposal_review_receipt(
        database, proposal["proposal_id"], reviewers[0][0],
        decision="REVIEWED", evidence=["review:check"], approver_id=reviewers[0][1],
    )
    with pytest.raises(ProposalReviewError, match="untrusted"):
        record_signed_proposal_review(database, proposal["proposal_id"], [trusted, unknown])


def test_signed_proposal_review_rejects_repeated_signer_and_reviewer_id(tmp_path):
    from nexora.proposal_review import (
        ProposalReviewError,
        create_proposal_review_receipt,
        record_signed_proposal_review,
    )

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    same_key_receipts = [
        create_proposal_review_receipt(
            database, proposal["proposal_id"], reviewers[0][0],
            decision="REVIEWED", evidence=["review:check"], approver_id=reviewers[0][1],
        )
        for _ in range(2)
    ]
    with pytest.raises(ProposalReviewError, match="independent_proposal_review_keys"):
        record_signed_proposal_review(database, proposal["proposal_id"], same_key_receipts)

    duplicate_id_receipts = [
        create_proposal_review_receipt(
            database, proposal["proposal_id"], reviewers[index][0],
            decision="REVIEWED", evidence=["review:other"], approver_id="same-operator",
        )
        for index in range(2)
    ]
    with pytest.raises(ProposalReviewError, match="distinct_proposal_review_approvers"):
        record_signed_proposal_review(database, proposal["proposal_id"], duplicate_id_receipts)


def test_signed_proposal_review_rejects_disagreeing_decision_or_evidence(tmp_path):
    from nexora.proposal_review import ProposalReviewError, record_signed_proposal_review

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    reviewed = _review_receipts(database, proposal, reviewers[:1], decision="REVIEWED")
    rejected = _review_receipts(database, proposal, reviewers[1:], decision="REJECTED")
    with pytest.raises(ProposalReviewError, match="attestations_disagree"):
        record_signed_proposal_review(database, proposal["proposal_id"], reviewed + rejected)


def test_signed_proposal_review_rejects_tampering_and_duplicate_record(tmp_path):
    from nexora.proposal_review import ProposalReviewError, record_signed_proposal_review
    from nexora.proposals import read_proposals

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    receipts = _review_receipts(database, proposal, reviewers)
    tampered = json.loads(json.dumps(receipts[0]))
    tampered["payload"]["decision"] = "REJECTED"
    with pytest.raises(ProposalReviewError, match="signature_invalid"):
        record_signed_proposal_review(database, proposal["proposal_id"], [tampered, receipts[1]])

    record_signed_proposal_review(database, proposal["proposal_id"], receipts)
    with pytest.raises(ProposalReviewError, match="already_recorded"):
        record_signed_proposal_review(database, proposal["proposal_id"], receipts)

    item = read_proposals(database, proposal_id=proposal["proposal_id"])["proposals"][0]
    assert item["signed_review"]["status"] == "VERIFIED"


def test_signed_proposal_review_receipt_creation_does_not_modify_database(tmp_path):
    from nexora.proposal_review import create_proposal_review_receipt

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    before = database.read_bytes()
    create_proposal_review_receipt(
        database, proposal["proposal_id"], reviewers[0][0],
        decision="REVIEWED", evidence=["review:check"], approver_id=reviewers[0][1],
    )
    assert database.read_bytes() == before


def test_signed_proposal_review_rejects_receipt_for_another_proposal(tmp_path):
    from nexora.proposal_review import ProposalReviewError, record_signed_proposal_review

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    receipts = _review_receipts(database, proposal, reviewers)
    second = SelfFamilyProposalStore(database).submit(_proposal())
    with pytest.raises(ProposalReviewError, match="scope_mismatch"):
        record_signed_proposal_review(database, second["proposal_id"], receipts)


def test_signed_review_storage_triggers_prevent_update_and_delete(tmp_path):
    import sqlite3

    from nexora.proposal_review import record_signed_proposal_review

    database, proposal, reviewers = _signed_review_fixture(tmp_path)
    receipts = _review_receipts(database, proposal, reviewers)
    record_signed_proposal_review(database, proposal["proposal_id"], receipts)

    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE self_family_signed_reviews SET decision='REJECTED' WHERE proposal_id=?",
                (proposal["proposal_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM self_family_signed_reviews WHERE proposal_id=?",
                (proposal["proposal_id"],),
            )
    finally:
        connection.close()


def test_proposals_cli_signed_review_sign_and_record(tmp_path, capsys):
    from nexora.approval import ApprovalReceiptStore, generate_keypair, load_public_key
    from nexora.cli import main

    database = tmp_path / "registry.sqlite3"
    proposal = SelfFamilyProposalStore(database).submit(_proposal())
    trust = ApprovalReceiptStore(database)
    signed_files = []
    for index in range(2):
        private = tmp_path / f"reviewer-{index}" / "private.pem"
        public = tmp_path / f"reviewer-{index}" / "public.pem"
        generate_keypair(private, public)
        trust.enroll_key(load_public_key(public), label=f"reviewer-{index}")
        output = tmp_path / f"review-{index}.json"
        signed_files.append((private, output, f"reviewer-{index}"))

    for private, output, approver_id in signed_files:
        result = main([
            "proposals", "review-sign", proposal["proposal_id"],
            "--database", str(database),
            "--private-key", str(private),
            "--decision", "REVIEWED",
            "--evidence", "review:source", "review:safety",
            "--approver-id", approver_id,
            "--output", str(output),
            "--confirm",
        ])
        created = json.loads(capsys.readouterr().out)
        assert result == 0
        assert created["database_modified"] is False
        assert created["execution_enabled"] is False

    result = main([
        "proposals", "review-record", proposal["proposal_id"],
        "--database", str(database),
        "--receipt", str(signed_files[0][1]), str(signed_files[1][1]),
        "--confirm",
    ])
    stored = json.loads(capsys.readouterr().out)
    assert result == 0
    assert stored["status"] == "VERIFIED_AND_RECORDED"
    assert stored["lifecycle_approval_granted"] is False
    assert stored["execution_enabled"] is False

    result = main([
        "proposals", "show", proposal["proposal_id"],
        "--database", str(database),
    ])
    shown = json.loads(capsys.readouterr().out)
    assert result == 0
    assert shown["proposal"]["signed_review"]["status"] == "VERIFIED"
