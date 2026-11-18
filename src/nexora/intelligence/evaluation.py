"""Small deterministic output checks; not a claim of model safety certification."""
from dataclasses import dataclass


@dataclass(frozen=True)
class EvaluationResult:
    accepted_for_review: bool
    reasons: tuple[str, ...]


def evaluate_output(output: str, *, max_chars: int = 20000) -> EvaluationResult:
    if not isinstance(output, str):
        return EvaluationResult(False, ("output_not_text",))
    reasons = []
    if not output.strip():
        reasons.append("empty_output")
    if len(output) > max_chars:
        reasons.append("output_too_large")
    return EvaluationResult(not reasons, tuple(reasons))
