"""Structured change proposal; proposal creation never changes project files."""
from dataclasses import dataclass


@dataclass(frozen=True)
class EvolutionProposal:
    proposal_id: str
    summary: str
    diff_sha256: str
    author: str

    def validate(self):
        if not all(isinstance(value, str) and value.strip() for value in (
            self.proposal_id, self.summary, self.diff_sha256, self.author
        )):
            raise ValueError("evolution_proposal_fields_required")
        if len(self.diff_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.diff_sha256):
            raise ValueError("proposal_digest_invalid")
        return self
