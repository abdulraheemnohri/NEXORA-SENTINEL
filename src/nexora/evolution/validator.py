"""Static eligibility checks for a proposed change; never promotes it."""
from nexora.evolution.proposer import EvolutionProposal


def validate_proposal(proposal: EvolutionProposal, *, tests_passed: bool, security_reviewed: bool) -> dict:
    proposal.validate()
    if type(tests_passed) is not bool or type(security_reviewed) is not bool:
        raise ValueError("validation_evidence_must_be_boolean")
    missing = []
    if not tests_passed:
        missing.append("tests_not_passed")
    if not security_reviewed:
        missing.append("security_review_missing")
    return {"eligible_for_shadow_review": not missing, "reasons": missing, "promotion": "DISABLED"}
