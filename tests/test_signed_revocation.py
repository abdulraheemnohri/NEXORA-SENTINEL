import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from nexora.approval import create_receipt, generate_keypair, load_private_key, load_public_key
from nexora.registry import CapabilityRegistry, RegistryError
from nexora.lifecycle_chain import verify_lifecycle_chain_file


def _setup(tmp_path):
    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(17, "Revocation test capability", "A", source_record=True)
    keys = []
    for index in range(3):
        private = tmp_path / f"operator-{index}.pem"
        public = tmp_path / f"operator-{index}.pub.pem"
        generate_keypair(private, public)
        registry.approvals.enroll_key(load_public_key(public), label=f"operator-{index}")
        keys.append(load_private_key(private))
    return registry, keys


def _receipts(keys, transition, evidence, capability_id=17, count=2):
    return [
        create_receipt(
            key, capability_id=capability_id, transition=transition,
            evidence=evidence, approver_id=f"operator-{index}",
        )
        for index, key in enumerate(keys[:count])
    ]


def test_signed_revocation_is_immediate_and_auditable(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "incident_report", "reason:unsafe_behavior"]
    receipts = _receipts(keys, "REVOKE", evidence)
    result = registry.revoke(
        17, "unsafe_behavior", evidence, approval_receipts=receipts,
        approver_ids=["operator-0", "operator-1"],
    )
    assert result["control_state"] == "REVOKED"
    assert registry.revocation_history(17)[0]["approver_id"] == "operator-0,operator-1"
    assert len(json.loads(registry.revocation_history(17)[0]["signer_fingerprints_json"])) == 2
    envelopes = json.loads(registry.revocation_history(17)[0]["receipt_payloads_json"])
    assert len(envelopes) == 2
    assert all(set(item) == {"payload", "signature"} for item in envelopes)
    assert all(item["signature"] for item in envelopes)
    assert registry.verify_signed_history(17)["valid"] is True
    chain = verify_lifecycle_chain_file(registry.database)
    assert chain["valid"] is True
    assert chain["event_count"] == 2  # registration plus signed revocation
    with pytest.raises(RegistryError, match="revoked_capability_is_terminal"):
        registry.transition(17, "REGISTERED", ["schema_validation"])


def test_revocation_requires_two_independent_signers(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    one = _receipts(keys, "REVOKE", evidence, count=1)
    with pytest.raises(RegistryError, match="multi_approval_threshold_not_met"):
        registry.revoke(17, "incident", evidence, approval_receipts=one,
                        approver_ids=["operator-0"])
    assert registry.get(17)["control_state"] == "ACTIVE"


def test_revocation_rejects_same_key_under_two_labels(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    receipts = [
        create_receipt(keys[0], capability_id=17, transition="REVOKE",
                       evidence=evidence, approver_id="operator-0"),
        create_receipt(keys[0], capability_id=17, transition="REVOKE",
                       evidence=evidence, approver_id="operator-1"),
    ]
    with pytest.raises(RegistryError, match="independent_signing_keys_required"):
        registry.revoke(17, "incident", evidence, approval_receipts=receipts,
                        approver_ids=["operator-0", "operator-1"])
    assert registry.get(17)["control_state"] == "ACTIVE"


def test_revocation_rejects_tampering_and_reason_substitution(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    receipts = _receipts(keys, "REVOKE", evidence)
    receipts[1] = dict(receipts[1])
    receipts[1]["signature"] = "ZmFrZQ=="
    with pytest.raises(RegistryError, match="signature_invalid"):
        registry.revoke(17, "incident", evidence, approval_receipts=receipts,
                        approver_ids=["operator-0", "operator-1"])
    with pytest.raises(RegistryError, match="reason_and_basis_must_be_signed"):
        registry.revoke(17, "different_reason", evidence, approval_receipts=receipts,
                        approver_ids=["operator-0", "operator-1"])
    assert registry.get(17)["control_state"] == "ACTIVE"


def test_revocation_receipts_are_single_use(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    receipts = _receipts(keys, "REVOKE", evidence)
    registry.revoke(17, "incident", evidence, approval_receipts=receipts,
                    approver_ids=["operator-0", "operator-1"])
    with pytest.raises(RegistryError, match="already_revoked"):
        registry.revoke(17, "incident", evidence, approval_receipts=receipts,
                        approver_ids=["operator-0", "operator-1"])


def test_revocation_event_is_append_only(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    registry.revoke(17, "incident", evidence,
                    approval_receipts=_receipts(keys, "REVOKE", evidence),
                    approver_ids=["operator-0", "operator-1"])
    with sqlite3.connect(registry.database) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE revocation_events SET reason='rewritten'")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM revocation_events")


def test_signed_rollback_is_record_only_and_replay_protected(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = [
        "rollback_plan", "validation_report", "human_approval",
        "from_release:v2", "target_release:v1", "reason:regression",
    ]
    receipts = _receipts(keys, "ROLLBACK", evidence)
    result = registry.record_rollback(
        17, "v2", "v1", "regression", evidence,
        approval_receipts=receipts, approver_ids=["operator-0", "operator-1"],
    )
    assert result["from_release"] == "v2"
    assert len(json.loads(result["signer_fingerprints_json"])) == 2
    assert registry.verify_signed_history(17, kind="rollback")["valid"] is True
    chain = verify_lifecycle_chain_file(registry.database)
    assert chain["valid"] is True
    assert chain["event_count"] == 2  # registration plus signed rollback authorization
    with pytest.raises(RegistryError, match="receipt_replay_denied"):
        registry.record_rollback(
            17, "v2", "v1", "regression", evidence,
            approval_receipts=receipts, approver_ids=["operator-0", "operator-1"],
        )


def test_concurrent_revocation_only_commits_once(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:race"]
    receipts = _receipts(keys, "REVOKE", evidence)

    def attempt():
        try:
            registry.revoke(17, "race", evidence, approval_receipts=receipts,
                            approver_ids=["operator-0", "operator-1"])
            return "revoked"
        except RegistryError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert outcomes.count("revoked") == 1
    assert outcomes.count("already_revoked") == 1
    assert len(registry.revocation_history(17)) == 1


def test_signed_history_verifier_detects_receipt_tampering(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    registry.revoke(
        17, "incident", evidence,
        approval_receipts=_receipts(keys, "REVOKE", evidence),
        approver_ids=["operator-0", "operator-1"],
    )
    with sqlite3.connect(registry.database) as db:
        row = db.execute(
            "SELECT event_id,receipt_payloads_json FROM revocation_events WHERE capability_id=17"
        ).fetchone()
        envelopes = json.loads(row[1])
        envelopes[0]["signature"] = "ZmFrZQ=="
        db.execute("DROP TRIGGER revocation_events_no_update")
        db.execute(
            "UPDATE revocation_events SET receipt_payloads_json=? WHERE event_id=?",
            (json.dumps(envelopes), row[0]),
        )
    report = registry.verify_signed_history(17)
    assert report["valid"] is False
    assert report["events"][0]["valid"] is False


def test_signed_history_verifier_detects_missing_nonce_consumption(tmp_path):
    registry, keys = _setup(tmp_path)
    evidence = ["revocation_basis", "reason:incident"]
    registry.revoke(
        17, "incident", evidence,
        approval_receipts=_receipts(keys, "REVOKE", evidence),
        approver_ids=["operator-0", "operator-1"],
    )
    event = registry.revocation_history(17)[0]
    envelopes = json.loads(event["receipt_payloads_json"])
    nonce = envelopes[0]["payload"]["nonce"]
    fingerprint = envelopes[0]["payload"]["key_fingerprint"]
    with sqlite3.connect(registry.database) as db:
        db.execute(
            "DELETE FROM consumed_approval_receipts WHERE nonce=? AND fingerprint=?",
            (nonce, fingerprint),
        )
    report = registry.verify_signed_history(17)
    assert report["valid"] is False
    assert "signed_receipt_nonce_consumption_missing" in report["events"][0]["errors"]


def test_signed_history_verification_fails_closed_when_empty(tmp_path):
    registry, _ = _setup(tmp_path)
    report = registry.verify_signed_history(17)
    assert report["valid"] is False
    assert report["event_count"] == 0
