"""Shadow evaluation record; this module does not run candidate code."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ShadowReport:
    candidate_digest: str
    baseline_digest: str
    observed_differences: tuple[str, ...]
    side_effects_observed: bool

    def eligible(self) -> bool:
        return bool(self.candidate_digest and self.baseline_digest) and not self.side_effects_observed and not self.observed_differences
