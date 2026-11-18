"""Validated immutable capability source record."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityRecord:
    capability_id: int
    name: str
    family: str
    source: str

    def validate(self):
        if type(self.capability_id) is not int or not 1 <= self.capability_id <= 264:
            raise ValueError("capability_id_out_of_range")
        if not all(isinstance(value, str) and value.strip() for value in (self.name, self.family, self.source)):
            raise ValueError("capability_source_fields_required")
        return self
