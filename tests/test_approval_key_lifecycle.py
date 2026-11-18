import sqlite3

import pytest

from nexora.approval import (
    ApprovalError,
    ApprovalReceiptStore,
    generate_keypair,
    load_private_key,
    load_public_key,
)


def _keypair(tmp_path, label):
    private = tmp_path / f"{label}-private.pem"
    public = tmp_path / f"{label}-public.pem"
    generate_keypair(private, public)
    return private, public


def test_keypair_permissions_and_no_overwrite(tmp_path):
    private, public = _keypair(tmp_path, "first")
    assert load_public_key(public)
    assert load_private_key(private)
    assert private.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ApprovalError, match="already_exists"):
        generate_keypair(private, public)


def test_key_enrollment_rotation_and_revocation_are_audited(tmp_path):
    _old_private, old_public = _keypair(tmp_path, "old")
    _new_private, new_public = _keypair(tmp_path, "new")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    old_fingerprint = store.enroll_key(load_public_key(old_public), label="primary", now=10)
    new_fingerprint = store.rotate_key(
        old_fingerprint, load_public_key(new_public),
        new_label="replacement", reason="scheduled rotation", now=20,
    )

    keys = {item["fingerprint"]: item for item in store.list_keys()}
    assert keys[old_fingerprint]["active"] == 0
    assert keys[old_fingerprint]["revoked_at"] == 20
    assert keys[old_fingerprint]["replaced_by"] == new_fingerprint
    assert keys[new_fingerprint]["active"] == 1
    assert [item["event_type"] for item in store.key_history()] == [
        "ENROLLED", "ROTATED",
    ]

    store.revoke_key(new_fingerprint, reason="key suspected compromised")
    assert store.list_keys(include_revoked=False) == []
    assert [item["event_type"] for item in store.key_history()] == [
        "ENROLLED", "ROTATED", "REVOKED",
    ]


def test_failed_rotation_keeps_old_key_active(tmp_path):
    _, old_public = _keypair(tmp_path, "old")
    _, new_public = _keypair(tmp_path, "new")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    old_fingerprint = store.enroll_key(load_public_key(old_public), label="primary")
    with pytest.raises(ApprovalError, match="rotation_reason_required"):
        store.rotate_key(
            old_fingerprint, load_public_key(new_public),
            new_label="replacement", reason="",
        )
    keys = {item["fingerprint"]: item for item in store.list_keys()}
    assert keys[old_fingerprint]["active"] == 1
    assert len(keys) == 1
    assert [item["event_type"] for item in store.key_history()] == ["ENROLLED"]


def test_revoked_key_cannot_authorize_new_transition(tmp_path):
    from nexora.approval import create_receipt

    old_private, old_public = _keypair(tmp_path, "old")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    fingerprint = store.enroll_key(load_public_key(old_public), label="approver")
    evidence = ["human_approval"]
    receipt = create_receipt(
        load_private_key(old_private), capability_id=12, transition="APPROVED",
        evidence=evidence, approver_id="operator-1", now=100,
    )
    store.revoke_key(fingerprint, reason="operator requested revocation")
    with pytest.raises(ApprovalError, match="untrusted_or_revoked"):
        store.verify_and_consume(
            receipt, capability_id=12, transition="APPROVED",
            evidence=evidence, approver_id="operator-1", now=101,
        )


def test_key_history_is_append_only(tmp_path):
    _, public = _keypair(tmp_path, "first")
    database = tmp_path / "approvals.sqlite3"
    store = ApprovalReceiptStore(database)
    store.enroll_key(load_public_key(public), label="operator")
    with sqlite3.connect(database) as db, pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM signing_key_events")
