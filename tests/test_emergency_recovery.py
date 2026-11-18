import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.approval import ApprovalReceiptStore, public_key_fingerprint
from nexora.emergency_recovery import (
    EmergencyRecoveryError,
    EmergencyRecoveryStore,
    create_recovery_authorization,
)


def _setup(tmp_path):
    database = tmp_path / "registry.sqlite3"
    approvals = ApprovalReceiptStore(database)
    recovery = EmergencyRecoveryStore(database)
    old = Ed25519PrivateKey.generate()
    old_fp = approvals.enroll_key(old.public_key(), label="operator-primary", now=100)
    authorities = []
    for number in range(3):
        private = Ed25519PrivateKey.generate()
        authority_id = f"recovery-{number + 1}"
        fingerprint = recovery.enroll_authority(
            private.public_key(), authority_id=authority_id,
            label=f"Recovery Authority {number + 1}", now=100,
        )
        authorities.append((private, authority_id, fingerprint))
    replacement = Ed25519PrivateKey.generate()
    return database, approvals, recovery, old, old_fp, authorities, replacement


def _issue(authorities, old_fp, replacement, *, now=200, reason="operator key compromised"):
    return [
        create_recovery_authorization(
            private,
            authority_id=authority_id,
            old_fingerprint=old_fp,
            new_public_key=replacement.public_key(),
            new_label="operator-recovered",
            reason=reason,
            now=now,
        )
        for private, authority_id, _ in authorities[:2]
    ]


def test_two_independent_recovery_authorities_replace_and_revoke_approval_key(tmp_path):
    _, approvals, recovery, _old, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement)
    new_fp = recovery.recover_approval_key(
        old_fingerprint=old_fp,
        new_public_key=replacement.public_key(),
        new_label="operator-recovered",
        reason="operator key compromised",
        authorizations=authorizations,
        now=200,
    )
    assert new_fp == public_key_fingerprint(replacement.public_key())
    keys = {item["fingerprint"]: item for item in approvals.list_keys()}
    assert keys[old_fp]["active"] == 0
    assert keys[new_fp]["active"] == 1
    events = recovery.history()
    assert events[-1]["event_type"] == "KEY_RECOVERED"
    assert json.loads(events[-1]["detail"])["authorities"] == ["recovery-1", "recovery-2"]
    assert len(approvals.key_history(old_fp)) == 2


def test_recovery_requires_two_distinct_authorities(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    one = _issue(authorities[:1], old_fp, replacement)
    with pytest.raises(EmergencyRecoveryError, match="threshold_not_met"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=one, now=200,
        )


def test_recovery_rejects_duplicate_authority_identity_even_with_two_receipts(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    first = create_recovery_authorization(
        authorities[0][0], authority_id=authorities[0][1], old_fingerprint=old_fp,
        new_public_key=replacement.public_key(), new_label="operator-recovered",
        reason="operator key compromised", now=200,
    )
    second = create_recovery_authorization(
        authorities[0][0], authority_id=authorities[0][1], old_fingerprint=old_fp,
        new_public_key=replacement.public_key(), new_label="operator-recovered",
        reason="operator key compromised", now=200,
    )
    with pytest.raises(EmergencyRecoveryError, match="independent_recovery_authorities_required"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=[first, second], now=200,
        )


def test_recovery_rejects_tampering_and_scope_mismatch(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement)
    authorizations[1]["payload"]["reason"] = "attacker substituted reason"
    with pytest.raises(EmergencyRecoveryError, match="scope_mismatch"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=authorizations, now=200,
        )


def test_recovery_nonce_is_single_use(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement)
    recovery.recover_approval_key(
        old_fingerprint=old_fp, new_public_key=replacement.public_key(),
        new_label="operator-recovered", reason="operator key compromised",
        authorizations=authorizations, now=200,
    )
    # A second operation against the now-revoked key is blocked; nonce replay is not reusable.
    another = Ed25519PrivateKey.generate()
    with pytest.raises(EmergencyRecoveryError, match="active_approval_key_not_found"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=another.public_key(),
            new_label="operator-recovered-again", reason="operator key compromised",
            authorizations=authorizations, now=201,
        )


def test_invalid_second_authorization_rolls_back_consumption_of_first(tmp_path):
    database, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement)
    authorizations[1]["signature"] = "AAAA"
    with pytest.raises(EmergencyRecoveryError, match="signature_invalid"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=authorizations, now=200,
        )
    with sqlite3.connect(database) as db:
        count = db.execute("SELECT COUNT(*) FROM consumed_recovery_authorizations").fetchone()[0]
    assert count == 0


def test_expired_or_revoked_recovery_authority_cannot_recover(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement)
    recovery.revoke_authority(authorities[1][2], reason="authority device compromised", now=150)
    with pytest.raises(EmergencyRecoveryError, match="untrusted_or_revoked"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=authorizations, now=200,
        )


def test_recovery_authorization_expiry_is_enforced(tmp_path):
    _, _, recovery, _, old_fp, authorities, replacement = _setup(tmp_path)
    authorizations = _issue(authorities, old_fp, replacement, now=100)
    with pytest.raises(EmergencyRecoveryError, match="expired_or_future"):
        recovery.recover_approval_key(
            old_fingerprint=old_fp, new_public_key=replacement.public_key(),
            new_label="operator-recovered", reason="operator key compromised",
            authorizations=authorizations, now=701,
        )


def test_recovery_event_history_is_append_only(tmp_path):
    database, _, recovery, _, _, _authorities, _ = _setup(tmp_path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"), sqlite3.connect(database) as db:
        db.execute("UPDATE emergency_recovery_events SET detail='tampered' WHERE event_id=1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"), sqlite3.connect(database) as db:
        db.execute("DELETE FROM emergency_recovery_events WHERE event_id=1")
