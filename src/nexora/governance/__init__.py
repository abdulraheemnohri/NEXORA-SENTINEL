"""Governance decision APIs; unknown relations remain unknown."""
from nexora.governance.interaction_matrix import InteractionMatrix
from nexora.governance.precedence import Precedence, resolve_conflict

__all__ = ["InteractionMatrix", "Precedence", "resolve_conflict"]
