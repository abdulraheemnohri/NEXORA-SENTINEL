"""Deterministic proposal planner; plans are inert data, never commands."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    goal: str
    action: str
    risk: str
    status: str = "PROPOSED_FOR_REVIEW"


class Planner:
    def create(self, goal: str, action: str, risk: str = "medium") -> Plan:
        if not isinstance(goal, str) or not goal.strip():
            raise ValueError("goal_required")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action_required")
        if risk not in {"low", "medium", "high", "critical"}:
            raise ValueError("unknown_risk_denied")
        return Plan(goal=goal.strip(), action=action.strip(), risk=risk)
