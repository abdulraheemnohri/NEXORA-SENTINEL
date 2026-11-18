"""Pure state-machine transition API."""
from nexora.lifecycle import LIFECYCLE, LifecycleDecision, validate_transition


def next_state(current: str, requested: str, evidence=(), *, human_approved: bool = False) -> LifecycleDecision:
    return validate_transition(current, requested, evidence, human_approved=human_approved)


__all__ = ["LIFECYCLE", "LifecycleDecision", "next_state"]
