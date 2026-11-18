"""Content provenance records using canonical SHA-256 fingerprints."""
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ProvenanceRecord:
    source_id: str
    sha256: str

    @classmethod
    def from_content(cls, source_id: str, content: bytes):
        if not isinstance(source_id, str) or not source_id.strip() or not isinstance(content, bytes):
            raise ValueError("provenance_input_invalid")
        return cls(source_id.strip(), hashlib.sha256(content).hexdigest())

    def verify(self, content: bytes) -> bool:
        return hashlib.sha256(content).hexdigest() == self.sha256
