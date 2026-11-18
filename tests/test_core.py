import json
from pathlib import Path

import pytest

from nexora.catalog import status
from nexora.cli import main
from nexora.lifecycle import (
    Precedence,
    resolve_conflict,
    validate_transition,
)
from nexora.oversight import AuditLog, KillSwitch, PolicyKernel


def test_audit_chain_and_tamper_detection(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    assert log.verify()
    lines = path.read_text().splitlines()
    row = json.loads(lines[0])
    row["payload"]["x"] = 7
    path.write_text(json.dumps(row) + "\n" + lines[1] + "\n")
    assert not log.verify()


def test_corrupt_audit_refuses_append(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text("{bad\n")
    with pytest.raises(RuntimeError):
        AuditLog(p).append("x", {})


def test_unknown_action_denied(tmp_path):
    assert not PolicyKernel(KillSwitch(tmp_path / "KILL")).evaluate("shell.exec", "low").allowed


def test_approval_and_kill_switch(tmp_path):
    stop = KillSwitch(tmp_path / "KILL")
    kernel = PolicyKernel(stop)
    assert not kernel.evaluate("filesystem.read", "medium").allowed
    assert kernel.evaluate("filesystem.read", "medium", True).allowed
    stop.engage("test")
    assert not kernel.evaluate("system.status", "low").allowed


def test_runtime_registration_locked(tmp_path):
    with pytest.raises(PermissionError):
        PolicyKernel(KillSwitch(tmp_path / "KILL")).register_action("x", "low")


def test_catalog_incomplete_is_explicit():
    result = status()
    assert result["expected_capabilities"] == 264
    assert result["expected_families"] == 40
    assert result["registered_capabilities"] == 180
    assert not result["complete"]
    assert not result["exact_id_coverage"]
    assert not result["exact_family_coverage"]


def test_addendum_v_capabilities_are_registered():
    catalog_path = Path(__file__).resolve().parents[1] / "spec" / "capability_catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    rows = {item["id"]: item for item in catalog["capabilities"]}
    assert set(range(216, 265)).issubset(rows)
    assert rows[216]["family"] == "AG"
    assert rows[264]["family"] == "AN"
    assert all(rows[i].get("mechanism") and rows[i].get("gate") for i in range(216, 265))


def test_addendum_v_meta_rules_are_registered():
    rules_path = Path(__file__).resolve().parents[1] / "spec" / "meta_rules.json"
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in rules["rules"]}
    assert set(range(36, 46)).issubset(by_id)
    assert all(by_id[i]["mutable_by_agent"] is False for i in range(36, 46))


def test_interaction_matrix_targets_264():
    matrix_path = Path(__file__).resolve().parents[1] / "spec" / "interaction_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    assert matrix["dimensions"] == [264, 264]
    assert matrix["capability_id_range"] == [1, 264]
    assert matrix["entries"] == []


def test_resume_keeps_kill_switch_engaged_if_audit_is_corrupt(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    marker = data / "KILL"
    marker.write_text("operator\n")
    (data / "audit.jsonl").write_text("{broken\n")
    with pytest.raises(RuntimeError):
        main(["--data-dir", str(data), "resume"])
    assert marker.exists()


def test_catalog_rejects_arbitrary_family_names(tmp_path):
    source = Path(__file__).resolve().parents[1] / "spec" / "capability_catalog.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    data["capabilities"][0]["family"] = "NOT-A-REAL-FAMILY"
    target = tmp_path / "catalog.json"
    target.write_text(json.dumps(data), encoding="utf-8")
    result = status(target)
    assert not result["entries_valid"]
    assert not result["complete"]


def test_lifecycle_requires_sequential_evidence_and_human_approval():
    assert not validate_transition("SPECIFIED", "ENABLED").allowed
    assert not validate_transition("SPECIFIED", "REGISTERED").allowed
    registered = validate_transition("SPECIFIED", "REGISTERED", {"source_record", "schema_validation"})
    assert registered.allowed
    assert not validate_transition("SHADOWED", "APPROVED", {"human_approval"}).allowed
    approved = validate_transition("SHADOWED", "APPROVED", {"human_approval"}, human_approved=True)
    assert approved.allowed
    assert not validate_transition("APPROVED", "ENABLED", {"human_approval", "rollback_plan", "monitoring_plan"}).allowed
    enabled = validate_transition(
        "APPROVED", "ENABLED",
        {"human_approval", "rollback_plan", "monitoring_plan"},
        human_approved=True,
    )
    assert enabled.allowed


def test_conflict_resolution_is_fail_closed():
    assert not resolve_conflict("safety", "feature").allowed
    priorities = {"safety": Precedence.SAFETY, "feature": Precedence.CONVENIENCE}
    decision = resolve_conflict("safety", "feature", priorities)
    assert decision.allowed and decision.winner == "safety"
    assert not resolve_conflict(
        "safety", "governance",
        {"safety": Precedence.SAFETY, "governance": Precedence.SAFETY},
    ).allowed


def test_persistent_registry_records_state_and_append_only_history(tmp_path):
    from nexora.registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(216, "Adversarial input detection", "AG", source_record=True)
    registry.transition(216, "REGISTERED", {"source_record", "schema_validation"})
    registry.transition(216, "IMPLEMENTED", {"implementation_reference"})
    registry.transition(216, "TESTED", {"test_report", "test_passed"})
    registry.transition(216, "SHADOWED", {"shadow_report", "no_side_effects"})
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexora.approval import create_receipt

    private = Ed25519PrivateKey.generate()
    registry.approvals.enroll_key(private.public_key(), label="test operator")
    approved_evidence = {"human_approval"}
    approved_receipt = create_receipt(
        private, capability_id=216, transition="APPROVED",
        evidence=approved_evidence, approver_id="operator:local",
    )
    registry.transition(
        216, "APPROVED", approved_evidence, approver_id="operator:local",
        approval_receipt=approved_receipt,
    )
    enabled_evidence = {"human_approval", "rollback_plan", "monitoring_plan"}
    enabled_receipt = create_receipt(
        private, capability_id=216, transition="ENABLED",
        evidence=enabled_evidence, approver_id="operator:local", now=1000,
    )
    registry.transition(
        216, "ENABLED", enabled_evidence, approver_id="operator:local",
        approval_receipt=enabled_receipt,
    )
    assert registry.get(216)["state"] == "ENABLED"
    history = registry.history(216)
    assert [event["requested_state"] for event in history] == [
        "SPECIFIED", "REGISTERED", "IMPLEMENTED", "TESTED",
        "SHADOWED", "APPROVED", "ENABLED",
    ]
    assert history[-1]["approver_id"] == "operator:local"


def test_registry_rejects_missing_approver_and_preserves_state(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(217, "Uncertainty map", "AH", source_record=True)
    for state, evidence in [
        ("REGISTERED", {"source_record", "schema_validation"}),
        ("IMPLEMENTED", {"implementation_reference"}),
        ("TESTED", {"test_report", "test_passed"}),
        ("SHADOWED", {"shadow_report", "no_side_effects"}),
    ]:
        registry.transition(217, state, evidence)
    with pytest.raises(RegistryError, match="explicit_operator_identity_required"):
        registry.transition(217, "APPROVED", {"human_approval"})
    with pytest.raises(RegistryError, match="signed_approval_receipt_required"):
        registry.transition(217, "APPROVED", {"human_approval"}, approver_id="operator:local")
    assert registry.get(217)["state"] == "SHADOWED"
    assert len(registry.history(217)) == 5


def test_registry_rejects_unknown_capability_and_duplicate_id(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    with pytest.raises(RegistryError, match="unknown_capability_denied"):
        registry.transition(999, "REGISTERED", {"source_record", "schema_validation"})
    registry.register(218, "Interface contracts", "AI", source_record=True)
    with pytest.raises(RegistryError, match="duplicate_or_invalid_capability"):
        registry.register(218, "Duplicate", "AI", source_record=True)



def test_revocation_is_terminal_and_append_only(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(219, "Covert behavior detection", "AG", source_record=True)
    registry.revoke(
        219, "Operator withdrew authorization",
        {"revocation_basis", "incident_record"},
        approver_id="operator:local",
    )
    assert registry.get(219)["control_state"] == "REVOKED"
    assert len(registry.revocation_history(219)) == 1
    with pytest.raises(RegistryError, match="revoked_capability_is_terminal"):
        registry.transition(219, "REGISTERED", {"source_record", "schema_validation"})
    with pytest.raises(RegistryError, match="already_revoked"):
        registry.revoke(
            219, "duplicate", {"revocation_basis"}, approver_id="operator:local"
        )


def test_rollback_is_audited_but_never_executed_by_registry(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(220, "Uncertainty ledger", "AH", source_record=True)
    with pytest.raises(RegistryError, match="rollback_evidence_incomplete"):
        registry.record_rollback(
            220, "v2", "v1", "Regression detected",
            {"rollback_plan"}, approver_id="operator:local",
        )
    event = registry.record_rollback(
        220, "v2", "v1", "Regression detected",
        {"rollback_plan", "validation_report", "human_approval"},
        approver_id="operator:local",
    )
    assert event["from_release"] == "v2"
    assert event["target_release"] == "v1"
    assert registry.get(220)["state"] == "SPECIFIED"
    assert len(registry.rollback_history(220)) == 1


def test_registry_rejects_string_as_evidence_collection(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(221, "Protocol validator", "AI", source_record=True)
    with pytest.raises(RegistryError, match="evidence_must_be_a_collection"):
        registry.transition(221, "REGISTERED", "source_record")


def _approval_fixture(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexora.approval import ApprovalReceiptStore

    private = Ed25519PrivateKey.generate()
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    store.enroll_key(private.public_key(), label="operator workstation")
    return private, store


def test_signed_receipt_verifies_once_and_blocks_replay(tmp_path):
    from nexora.approval import ApprovalError, create_receipt

    private, store = _approval_fixture(tmp_path)
    evidence = {"human_approval", "review_record"}
    receipt = create_receipt(private, capability_id=216, transition="APPROVED",
                             evidence=evidence, approver_id="operator:local", now=1000)
    payload = store.verify_and_consume(receipt, capability_id=216, transition="APPROVED",
                                       evidence=evidence, approver_id="operator:local", now=1001)
    assert payload["capability_id"] == 216
    with pytest.raises(ApprovalError, match="receipt_replay_denied"):
        store.verify_and_consume(receipt, capability_id=216, transition="APPROVED",
                                 evidence=evidence, approver_id="operator:local", now=1001)


def test_signed_receipt_rejects_tampering_wrong_key_and_scope(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexora.approval import ApprovalError, create_receipt

    private, store = _approval_fixture(tmp_path)
    receipt = create_receipt(private, capability_id=216, transition="APPROVED",
                             evidence={"human_approval"}, approver_id="operator:local", now=1000)
    tampered = json.loads(json.dumps(receipt))
    tampered["payload"]["capability_id"] = 217
    with pytest.raises(ApprovalError):
        store.verify_and_consume(tampered, capability_id=216, transition="APPROVED",
                                 evidence={"human_approval"}, approver_id="operator:local", now=1001)
    with pytest.raises(ApprovalError, match="receipt_scope_mismatch"):
        store.verify_and_consume(receipt, capability_id=217, transition="APPROVED",
                                 evidence={"human_approval"}, approver_id="operator:local", now=1001)
    wrong = Ed25519PrivateKey.generate()
    wrong_receipt = create_receipt(wrong, capability_id=216, transition="APPROVED",
                                   evidence={"human_approval"}, approver_id="operator:local", now=1000)
    with pytest.raises(ApprovalError, match="signing_key_untrusted_or_revoked"):
        store.verify_and_consume(wrong_receipt, capability_id=216, transition="APPROVED",
                                 evidence={"human_approval"}, approver_id="operator:local", now=1001)


def test_signed_receipt_rejects_expiry_and_evidence_mismatch(tmp_path):
    from nexora.approval import ApprovalError, create_receipt

    private, store = _approval_fixture(tmp_path)
    evidence = {"human_approval", "rollback_plan", "monitoring_plan"}
    receipt = create_receipt(private, capability_id=218, transition="ENABLED",
                             evidence=evidence, approver_id="operator:local",
                             ttl_seconds=30, now=1000)
    with pytest.raises(ApprovalError, match="receipt_expired"):
        store.verify_and_consume(receipt, capability_id=218, transition="ENABLED",
                                 evidence=evidence, approver_id="operator:local", now=1031)
    with pytest.raises(ApprovalError, match="receipt_evidence_mismatch"):
        store.verify_and_consume(receipt, capability_id=218, transition="ENABLED",
                                 evidence={"human_approval"}, approver_id="operator:local", now=1001)


def test_revoked_signing_key_cannot_authorize(tmp_path):
    from nexora.approval import ApprovalError, create_receipt

    private, store = _approval_fixture(tmp_path)
    receipt = create_receipt(private, capability_id=219, transition="APPROVED",
                             evidence={"human_approval"}, approver_id="operator:local", now=1000)
    store.revoke_key(receipt["payload"]["key_fingerprint"])
    with pytest.raises(ApprovalError, match="signing_key_untrusted_or_revoked"):
        store.verify_and_consume(receipt, capability_id=219, transition="APPROVED",
                                 evidence={"human_approval"}, approver_id="operator:local", now=1001)


def test_signing_key_file_is_private_and_not_overwritten(tmp_path):
    import os

    from nexora.approval import ApprovalError, generate_signing_key, load_private_key

    path = tmp_path / "operator-ed25519.pem"
    assert generate_signing_key(path)
    assert load_private_key(path)
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(ApprovalError, match="private_key_already_exists"):
        generate_signing_key(path)



def test_registry_consumes_signed_receipt_atomically_with_transition(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from nexora.approval import create_receipt
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(222, "Approval transaction", "AI", source_record=True)
    private = Ed25519PrivateKey.generate()
    registry.approvals.enroll_key(private.public_key(), label="test operator")
    evidence = {"human_approval"}
    receipt = create_receipt(
        private, capability_id=222, transition="APPROVED", evidence=evidence,
        approver_id="operator:test", now=1000,
    )
    with pytest.raises(RegistryError, match="non_sequential_transition_denied"):
        registry.transition(
            222, "APPROVED", evidence, approver_id="operator:test",
            approval_receipt=receipt,
        )
    assert registry.get(222)["state"] == "SPECIFIED"
    payload = registry.approvals.verify_and_consume(
        receipt, capability_id=222, transition="APPROVED", evidence=evidence,
        approver_id="operator:test", now=1001,
    )
    assert payload["capability_id"] == 222


def test_registry_requires_receipt_even_with_operator_label(tmp_path):
    from nexora.registry import CapabilityRegistry, RegistryError

    registry = CapabilityRegistry(tmp_path / "registry.sqlite3")
    registry.register(223, "No unsigned promotion", "AI", source_record=True)
    for state, evidence in [
        ("REGISTERED", {"source_record", "schema_validation"}),
        ("IMPLEMENTED", {"implementation_reference"}),
        ("TESTED", {"test_report", "test_passed"}),
        ("SHADOWED", {"shadow_report", "no_side_effects"}),
    ]:
        registry.transition(223, state, evidence)
    with pytest.raises(RegistryError, match="signed_approval_receipt_required"):
        registry.transition(
            223, "APPROVED", {"human_approval"}, approver_id="operator:local"
        )
    assert registry.get(223)["state"] == "SHADOWED"
