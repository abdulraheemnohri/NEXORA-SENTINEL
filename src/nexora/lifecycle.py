"""Fail-closed capability lifecycle and conflict governance.

This module records eligibility decisions only; it never executes capabilities.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

LIFECYCLE = (
    "SPECIFIED", "REGISTERED", "IMPLEMENTED", "TESTED",
    "SHADOWED", "APPROVED", "ENABLED",
)
EVIDENCE_FOR = {
    "REGISTERED": {"source_record", "schema_validation"},
    "IMPLEMENTED": {"implementation_reference"},
    "TESTED": {"test_report", "test_passed"},
    "SHADOWED": {"shadow_report", "no_side_effects"},
    "APPROVED": {"human_approval"},
    "ENABLED": {"human_approval", "rollback_plan", "monitoring_plan"},
}


@dataclass(frozen=True)
class LifecycleDecision:
    allowed: bool
    current: str
    requested: str
    reason: str


def validate_transition(
    current: str,
    requested: str,
    evidence: Iterable[str] = (),
    *,
    human_approved: bool = False,
) -> LifecycleDecision:
    if current not in LIFECYCLE or requested not in LIFECYCLE:
        return LifecycleDecision(False, current, requested, "unknown_state_denied")
    if requested == current:
        return LifecycleDecision(True, current, requested, "no_op")
    if LIFECYCLE.index(requested) != LIFECYCLE.index(current) + 1:
        return LifecycleDecision(False, current, requested, "non_sequential_transition_denied")
    supplied = set(evidence)
    missing = EVIDENCE_FOR.get(requested, set()) - supplied
    if missing:
        return LifecycleDecision(False, current, requested, "required_evidence_missing:" + ",".join(sorted(missing)))
    if requested in {"APPROVED", "ENABLED"} and not human_approved:
        return LifecycleDecision(False, current, requested, "human_authorization_required")
    return LifecycleDecision(True, current, requested, "transition_eligible")


class Precedence(IntEnum):
    SAFETY = 0
    GOVERNANCE = 1
    OPERATIONAL = 2
    CONVENIENCE = 3


@dataclass(frozen=True)
class ConflictDecision:
    allowed: bool
    winner: str | None
    reason: str


def resolve_conflict(
    left: str,
    right: str,
    priorities: dict[str, Precedence] | None = None,
) -> ConflictDecision:
    """Unknown or equal-priority conflicts are blocked for independent review."""
    if priorities is None or left not in priorities or right not in priorities:
        return ConflictDecision(False, None, "unknown_conflict_requires_human_review")
    a, b = priorities[left], priorities[right]
    if not isinstance(a, Precedence) or not isinstance(b, Precedence):
        return ConflictDecision(False, None, "invalid_priority_requires_human_review")
    if a == b:
        return ConflictDecision(False, None, "equal_priority_conflict_requires_human_review")
    winner = left if a < b else right
    return ConflictDecision(True, winner, "fixed_precedence_applied")
