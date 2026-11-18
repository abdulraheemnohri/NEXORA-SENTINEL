import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.approval import (
    ApprovalError,
    ApprovalReceiptStore,
    create_receipt,
)


def _receipt(private, *, now):
    return create_receipt(
        private,
        capability_id=7,
        transition="APPROVED",
        evidence=["human_approval"],
        approver_id="operator-expiry",
        now=now,
    )


def test_enrolled_key_expires_at_configured_lifetime(tmp_path):
    store = ApprovalReceiptStore(tmp_path / "trust.sqlite3")
    private = Ed25519PrivateKey.generate()
    store.enroll_key(private.public_key(), label="short-lived", validity_days=1, now=100)

    before_expiry = _receipt(private, now=86499)
    store.verify_and_consume(
        before_expiry,
        capability_id=7,
        transition="APPROVED",
        evidence=["human_approval"],
        approver_id="operator-expiry",
        now=86499,
    )

    at_expiry = _receipt(private, now=86500)
    with pytest.raises(ApprovalError, match="signing_key_expired"):
        store.verify_and_consume(
            at_expiry,
            capability_id=7,
            transition="APPROVED",
            evidence=["human_approval"],
            approver_id="operator-expiry",
            now=86500,
        )


def test_expired_key_can_be_renewed_with_new_key_and_old_key_is_revoked(tmp_path):
    store = ApprovalReceiptStore(tmp_path / "trust.sqlite3")
    old_private = Ed25519PrivateKey.generate()
    old_fingerprint = store.enroll_key(
        old_private.public_key(), label="operator-old", validity_days=1, now=100,
    )
    new_private = Ed25519PrivateKey.generate()
    new_fingerprint = store.rotate_key(
        old_fingerprint,
        new_private.public_key(),
        new_label="operator-renewed",
        reason="scheduled key renewal",
        validity_days=365,
        now=86500,
    )
    assert new_fingerprint != old_fingerprint
    keys = {item["fingerprint"]: item for item in store.list_keys()}
    assert keys[old_fingerprint]["active"] == 0
    assert keys[new_fingerprint]["active"] == 1
    assert keys[new_fingerprint]["expires_at"] == 86500 + 365 * 86400

    old_receipt = _receipt(old_private, now=86500)
    with pytest.raises(ApprovalError, match="signing_key_untrusted_or_revoked"):
        store.verify_and_consume(
            old_receipt, capability_id=7, transition="APPROVED",
            evidence=["human_approval"], approver_id="operator-expiry", now=86500,
        )
    new_receipt = _receipt(new_private, now=86500)
    store.verify_and_consume(
        new_receipt, capability_id=7, transition="APPROVED",
        evidence=["human_approval"], approver_id="operator-expiry", now=86500,
    )


def test_key_validity_is_bounded(tmp_path):
    store = ApprovalReceiptStore(tmp_path / "trust.sqlite3")
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ApprovalError, match="key_validity_days_out_of_range"):
        store.enroll_key(private.public_key(), label="invalid", validity_days=731, now=100)


def test_legacy_trust_rows_receive_expiry_during_migration(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute(
            """CREATE TABLE trusted_signing_keys (
                fingerprint TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                label TEXT NOT NULL,
                active INTEGER NOT NULL,
                enrolled_at INTEGER NOT NULL
            )"""
        )
        db.execute(
            "INSERT INTO trusted_signing_keys VALUES(?,?,?,?,?)",
            ("legacy-fingerprint", b"legacy", "legacy", 1, 1000),
        )
    store = ApprovalReceiptStore(database)
    key = store.list_keys()[0]
    assert key["expires_at"] == 1000 + 365 * 86400
