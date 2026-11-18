"""Conflict resolution facade."""
from nexora.lifecycle import ConflictDecision, Precedence, resolve_conflict


def resolve(left: str, right: str, priorities=None) -> ConflictDecision:
    return resolve_conflict(left, right, priorities)


__all__ = ["ConflictDecision", "Precedence", "resolve"]
