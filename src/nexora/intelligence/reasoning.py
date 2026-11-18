"""Reasoning output contract; text remains an untrusted proposal."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ReasoningProposal:
    content: str
    model_id: str
    confidence: float | None = None

    def validate(self):
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("reasoning_content_required")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise ValueError("model_id_required")
        if self.confidence is not None and (type(self.confidence) not in (int, float) or not 0 <= self.confidence <= 1):
            raise ValueError("confidence_out_of_range")
        return self
