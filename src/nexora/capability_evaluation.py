"""Read-only evaluation of evidence coverage for capability lifecycle gates.

This module reports evidence presence only. It does not prove artifact truth,
change lifecycle state, grant approval, or enable capability execution.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nexora.evidence import EVIDENCE_TYPES, EvidenceLedger
from nexora.lifecycle import EVIDENCE_FOR, LIFECYCLE


class CapabilityEvaluationError(ValueError):
    """Raised for invalid capability evaluation requests."""


def evaluate_capability(
    capability_id: int,
    records: list[dict[str, Any]],
    *,
    ledger_valid: bool,
    human_approved: bool = False,
    evidence_types: set[str] | None = None,
    evidence_record_count: int | None = None,
) -> dict[str, Any]:
    """Evaluate evidence-token coverage for one capability, fail-closed."""
    if type(capability_id) is not int or not 1 <= capability_id <= 264:
        raise CapabilityEvaluationError("capability_id_out_of_range")
    if type(ledger_valid) is not bool or type(human_approved) is not bool:
        raise CapabilityEvaluationError("invalid_evaluation_flags")
    if not isinstance(records, list):
        raise CapabilityEvaluationError("records_must_be_a_list")
    selected = [row for row in records if isinstance(row, dict)
                and row.get("capability_id") == capability_id]
    supplied = (
        set(evidence_types) if evidence_types is not None
        else {row.get("evidence_type") for row in selected}
    )
    if any(not isinstance(value, str) or value not in EVIDENCE_TYPES for value in supplied):
        raise CapabilityEvaluationError("unsupported_evidence_type_in_evaluation")
    record_count = len(selected) if evidence_record_count is None else evidence_record_count
    if type(record_count) is not int or record_count < len(supplied):
        raise CapabilityEvaluationError("invalid_evidence_record_count")
    stages = []
    for state in LIFECYCLE[1:]:
        required = EVIDENCE_FOR.get(state, set())
        missing = sorted(required - supplied)
        approval_gate = state in {"APPROVED", "ENABLED"} and not human_approved
        stages.append({
            "state": state,
            "required_evidence": sorted(required),
            "present_evidence": sorted(required & supplied),
            "missing_evidence": missing,
            "human_authorization_required": approval_gate,
            "ready": ledger_valid and not missing and not approval_gate,
        })
    if not ledger_valid:
        overall = "BLOCKED_LEDGER_INTEGRITY"
        next_state = None
    else:
        next_state = next((stage["state"] for stage in stages if not stage["ready"]), None)
        # Readiness is a report, not a lifecycle state transition.
        overall = "EVIDENCE_COMPLETE" if next_state is None else "EVIDENCE_GAPS"
    return {
        "capability_id": capability_id,
        "ledger_valid": ledger_valid,
        "evidence_records": record_count,
        "evidence_types": sorted(value for value in supplied if isinstance(value, str)),
        "stages": stages,
        "first_blocked_gate": next_state,
        "assessment": overall,
        "human_approved_input": human_approved,
        "lifecycle_changed": False,
        "execution_enabled": False,
        "note": "Evidence presence is not proof of artifact validity or authorization.",
    }


def evaluate_from_ledger(
    database: Path,
    capability_id: int,
    *,
    human_approved: bool = False,
) -> dict[str, Any]:
    """Evaluate against a verified local ledger; invalid chains fail closed."""
    ledger = EvidenceLedger(database)
    verification = ledger.verify()
    if not verification["valid"]:
        return evaluate_capability(
            capability_id, [], ledger_valid=False, human_approved=False,
        ) | {"ledger_verification": verification}
    summary = ledger.evidence_summary(capability_id)
    return evaluate_capability(
        capability_id, [], ledger_valid=True, human_approved=human_approved,
        evidence_types=set(summary["evidence_types"]),
        evidence_record_count=summary["record_count"],
    ) | {"ledger_verification": verification}
