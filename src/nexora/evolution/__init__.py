"""Evolution proposal and promotion gates; no self-modification executor."""
from nexora.evolution.proposer import EvolutionProposal
from nexora.evolution.validator import validate_proposal

__all__ = ["EvolutionProposal", "validate_proposal"]
