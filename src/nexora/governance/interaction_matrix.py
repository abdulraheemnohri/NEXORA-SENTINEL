"""Fail-closed reader for the supplied capability interaction matrix."""
import json
from pathlib import Path


class InteractionMatrix:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text(encoding="utf-8"))
        if self.data.get("dimensions") != [264, 264]:
            raise ValueError("interaction_matrix_dimensions_invalid")
        self._entries = {}
        for entry in self.data.get("entries", []):
            if not isinstance(entry, dict):
                raise TypeError("interaction_matrix_entry_invalid")
            pair = (entry.get("source"), entry.get("target"))
            if pair[0] not in range(1, 265) or pair[1] not in range(1, 265) or pair in self._entries:
                raise ValueError("interaction_matrix_pair_invalid_or_duplicate")
            self._entries[pair] = entry

    def relation(self, source: int, target: int) -> dict:
        if type(source) is not int or type(target) is not int or not 1 <= source <= 264 or not 1 <= target <= 264:
            raise ValueError("capability_id_out_of_range")
        entry = self._entries.get((source, target))
        return {"known": False, "decision": "BLOCK_AND_ESCALATE"} if entry is None else {
            "known": True, "decision": "REVIEW_REQUIRED", "entry": entry,
        }
