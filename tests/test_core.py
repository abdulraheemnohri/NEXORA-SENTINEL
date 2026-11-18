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
    registry.transition(216, "APPROVED", {"human_approval"}, approver_id="operator:local")
    registry.transition(
        216, "ENABLED",
        {"human_approval", "rollback_plan", "monitoring_plan"},
        approver_id="operator:local",
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
    with pytest.raises(RegistryError, match="human_authorization_required"):
        registry.transition(217, "APPROVED", {"human_approval"})
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
