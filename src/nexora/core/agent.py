"""Minimal agent kernel that turns goals into reviewable plans only."""
from dataclasses import dataclass

from nexora.core.planner import Plan, Planner
from nexora.oversight.policy_kernel import PolicyKernel


@dataclass(frozen=True)
class AgentResult:
    plan: Plan
    decision: dict


class AgentKernel:
    def __init__(self, policy: PolicyKernel):
        self.policy = policy
        self.planner = Planner()

    def propose(self, goal: str, action: str, risk: str = "medium") -> AgentResult:
        plan = self.planner.create(goal, action, risk)
        decision = self.policy.evaluate(action, risk).to_dict()
        return AgentResult(plan=plan, decision=decision)
