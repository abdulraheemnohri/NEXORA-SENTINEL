"""Explicit knowledge item schema; no unsupported inference is attached."""
from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeItem:
    subject: str
    predicate: str
    object: str
    source_id: str

    def validate(self):
        if not all(isinstance(x, str) and x.strip() for x in (self.subject, self.predicate, self.object, self.source_id)):
            raise ValueError("knowledge_item_fields_required")
        return self
