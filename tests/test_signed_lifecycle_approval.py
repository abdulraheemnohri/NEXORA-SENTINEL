import pytest

from nexora.approval import (
    ApprovalError,
    create_receipt,
    generate_keypair,
    load_private_key,
    load_public_key,
)
from nexora.registry import CapabilityRegistry, RegistryError


def _registry(tmp_path):
    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    private_path, public_path = tmp_path / "approval-private.pem", tmp_path / "approval-public.pem"
    generate_keypair(private_path, public_path)
    registry.approvals.enroll_key(load_public_key(public_path), label="test-operator")
    return registry, load_private_key(private_path)


def _advance_to_shadowed(registry):
    registry.register(7, "Test capability", "A", source_record=True)
    registry.transition(7, "REGISTERED", ["source_record", "schema_validation"])
    registry.transition(7, "IMPLEMENTED", ["implementation_reference"])
    registry.transition(7, "TESTED", ["test_report", "test_passed"])
    registry.transition(7, "SHADOWED", ["shadow_report", "no_side_effects"])


def test_signed_approval_is_consumed_atomically_with_lifecycle_transition(tmp_path):
    registry, private = _registry(tmp_path)
    _advance_to_shadowed(registry)
    evidence = ["human_approval"]
    receipt = create_receipt(
        private, capability_id=7, transition="APPROVED",
        evidence=evidence, approver_id="operator-1",
    )

    result = registry.transition(
        7, "APPROVED", evidence, approver_id="operator-1",
        approval_receipt=receipt,
    )
    assert result["state"] == "APPROVED"
    assert registry.history(7)[-1]["approver_id"] == "operator-1"


def test_invalid_receipt_does_not_consume_nonce_or_change_state(tmp_path):
    registry, private = _registry(tmp_path)
    _advance_to_shadowed(registry)
    receipt = create_receipt(
        private, capability_id=7, transition="APPROVED",
        evidence=["human_approval"], approver_id="operator-1",
    )
    receipt["signature"] = "ZmFrZQ=="
    with pytest.raises(RegistryError, match="signature_invalid"):
        registry.transition(
            7, "APPROVED", ["human_approval"], approver_id="operator-1",
            approval_receipt=receipt,
        )
    assert registry.get(7)["state"] == "SHADOWED"
    assert registry.history(7)[-1]["requested_state"] == "SHADOWED"


def test_replayed_signed_receipt_cannot_advance_second_transition(tmp_path):
    registry, private = _registry(tmp_path)
    _advance_to_shadowed(registry)
    evidence = ["human_approval"]
    receipt = create_receipt(
        private, capability_id=7, transition="APPROVED",
        evidence=evidence, approver_id="operator-1",
    )
    registry.transition(7, "APPROVED", evidence, approver_id="operator-1", approval_receipt=receipt)
    with pytest.raises(RegistryError, match="receipt_replay_denied"):
        registry.transition(7, "APPROVED", evidence, approver_id="operator-1", approval_receipt=receipt)
    assert registry.get(7)["state"] == "APPROVED"


def test_enabled_transition_requires_new_scoped_signed_receipt(tmp_path):
    registry, private = _registry(tmp_path)
    _advance_to_shadowed(registry)
    approved_evidence = ["human_approval"]
    approved = create_receipt(
        private, capability_id=7, transition="APPROVED",
        evidence=approved_evidence, approver_id="operator-1",
    )
    registry.transition(7, "APPROVED", approved_evidence, approver_id="operator-1", approval_receipt=approved)
    enabled_evidence = ["human_approval", "rollback_plan", "monitoring_plan"]
    enabled = create_receipt(
        private, capability_id=7, transition="ENABLED",
        evidence=enabled_evidence, approver_id="operator-1",
    )
    result = registry.transition(
        7, "ENABLED", enabled_evidence, approver_id="operator-1",
        approval_receipt=enabled,
    )
    assert result["state"] == "ENABLED"
