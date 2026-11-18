import sqlite3

import pytest

from nexora.self_families import SelfFamily, SelfFamilyManager, SelfFamilySettings
from nexora.self_family_store import SelfFamilyProposalStore, SelfFamilyStoreError


def _proposal():
    manager = SelfFamilyManager(SelfFamilySettings(evolution_enabled=True))
    return manager.propose(
        SelfFamily.EVOLUTION,
        "Prepare diagnostics refactor",
        evidence=("issue:17",),
        payload={"scope": "diagnostics"},
    )


def test_submit_persists_proposal_and_submission_event(tmp_path):
    path = tmp_path / "proposals.sqlite3"
    proposal = _proposal()
    stored = SelfFamilyProposalStore(path).submit(proposal)
    assert stored["proposal_id"] == proposal.proposal_id
    assert stored["status"] == "SUBMITTED"
    assert stored["execution"] == "DISABLED"
    assert stored["review_history"][0]["decision"] == "SUBMITTED"


def test_submit_is_idempotent_but_rejects_id_collision(tmp_path):
    store = SelfFamilyProposalStore(tmp_path / "proposals.sqlite3")
    proposal = _proposal()
    store.submit(proposal)
    assert store.submit(proposal)["proposal_id"] == proposal.proposal_id


def test_review_is_append_only_and_never_authorizes_execution(tmp_path):
    store = SelfFamilyProposalStore(tmp_path / "proposals.sqlite3")
    proposal = _proposal()
    store.submit(proposal)
    reviewed = store.review(
        proposal.proposal_id, "REVIEWED", operator_label="operator-1",
        evidence=("review:complete",), note="Reviewed; no execution approval.",
    )
    assert reviewed["status"] == "REVIEWED"
    assert reviewed["execution"] == "DISABLED"
    assert len(reviewed["review_history"]) == 2
    with pytest.raises(SelfFamilyStoreError, match="already_reviewed"):
        store.review(
            proposal.proposal_id, "REJECTED", operator_label="operator-1",
            evidence=("review:second",),
        )


def test_rejected_proposal_is_terminal_for_review(tmp_path):
    store = SelfFamilyProposalStore(tmp_path / "proposals.sqlite3")
    proposal = _proposal()
    store.submit(proposal)
    rejected = store.review(
        proposal.proposal_id, "REJECTED", operator_label="operator-2",
        evidence=("risk:unresolved",),
    )
    assert rejected["status"] == "REJECTED"
    assert rejected["execution"] == "DISABLED"


def test_proposal_and_review_events_cannot_be_updated_or_deleted(tmp_path):
    path = tmp_path / "proposals.sqlite3"
    store = SelfFamilyProposalStore(path)
    proposal = _proposal()
    store.submit(proposal)
    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute(
                "UPDATE self_family_proposals SET summary='tampered' WHERE proposal_id=?",
                (proposal.proposal_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM self_family_review_events")
