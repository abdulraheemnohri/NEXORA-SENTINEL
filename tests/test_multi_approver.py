import pytest

from nexora.approval import create_receipt, generate_keypair, load_private_key, load_public_key
from nexora.registry import CapabilityRegistry, RegistryError


def _setup(tmp_path):
    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    keys = []
    for number in (1, 2):
        private = tmp_path / f"operator-{number}.pem"
        public = tmp_path / f"operator-{number}.pub.pem"
        generate_keypair(private, public)
        registry.approvals.enroll_key(load_public_key(public), label=f"operator-{number}")
        keys.append(load_private_key(private))
    registry.register(11, "Multi approver test", "A", source_record=True)
    registry.transition(11, "REGISTERED", ["source_record", "schema_validation"])
    registry.transition(11, "IMPLEMENTED", ["implementation_reference"])
    registry.transition(11, "TESTED", ["test_report", "test_passed"])
    registry.transition(11, "SHADOWED", ["shadow_report", "no_side_effects"])
    approved = create_receipt(
        keys[0], capability_id=11, transition="APPROVED",
        evidence=["human_approval"], approver_id="operator-1",
    )
    registry.transition(
        11, "APPROVED", ["human_approval"],
        approver_id="operator-1", approval_receipt=approved,
    )
    evidence = ["human_approval", "rollback_plan", "monitoring_plan"]
    receipts = [
        create_receipt(
            key, capability_id=11, transition="ENABLED",
            evidence=evidence, approver_id=f"operator-{index}",
        )
        for index, key in enumerate(keys, start=1)
    ]
    return registry, evidence, receipts


def test_enabled_requires_two_independent_signed_approvals(tmp_path):
    registry, evidence, receipts = _setup(tmp_path)
    result = registry.transition(
        11, "ENABLED", evidence, approval_receipts=receipts,
        approver_ids=["operator-1", "operator-2"],
    )
    assert result["state"] == "ENABLED"
    assert result["control_state"] == "ACTIVE"
    assert registry.history(11)[-1]["approver_id"] == "operator-1,operator-2"


def test_enabled_rejects_single_approval_without_state_change(tmp_path):
    registry, evidence, receipts = _setup(tmp_path)
    with pytest.raises(RegistryError, match="multi_approval_threshold_not_met"):
        registry.transition(
            11, "ENABLED", evidence, approval_receipts=receipts[:1],
            approver_ids=["operator-1"],
        )
    assert registry.get(11)["state"] == "APPROVED"


def test_enabled_rejects_duplicate_approver_identity(tmp_path):
    registry, evidence, receipts = _setup(tmp_path)
    with pytest.raises(RegistryError, match="distinct_approvers_required"):
        registry.transition(
            11, "ENABLED", evidence, approval_receipts=receipts,
            approver_ids=["operator-1", "operator-1"],
        )
    assert registry.get(11)["state"] == "APPROVED"


def test_enabled_rejects_same_signing_key_even_with_distinct_labels(tmp_path):
    registry, evidence, receipts = _setup(tmp_path)
    duplicate_signer_receipt = create_receipt(
        load_private_key(tmp_path / "operator-1.pem"),
        capability_id=11, transition="ENABLED", evidence=evidence,
        approver_id="operator-2",
    )
    with pytest.raises(RegistryError, match="independent_signing_keys_required"):
        registry.transition(
            11, "ENABLED", evidence,
            approval_receipts=[receipts[0], duplicate_signer_receipt],
            approver_ids=["operator-1", "operator-2"],
        )
    assert registry.get(11)["state"] == "APPROVED"


def test_failed_second_receipt_rolls_back_first_nonce_consumption(tmp_path):
    registry, evidence, receipts = _setup(tmp_path)
    invalid = dict(receipts[1])
    invalid["signature"] = "ZmFrZQ=="
    with pytest.raises(RegistryError, match="signature_invalid"):
        registry.transition(
            11, "ENABLED", evidence,
            approval_receipts=[receipts[0], invalid],
            approver_ids=["operator-1", "operator-2"],
        )
    assert registry.get(11)["state"] == "APPROVED"
    result = registry.transition(
        11, "ENABLED", evidence, approval_receipts=receipts,
        approver_ids=["operator-1", "operator-2"],
    )
    assert result["state"] == "ENABLED"
