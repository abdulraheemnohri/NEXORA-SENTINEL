"""Loads only explicit, source-backed capability catalogue records."""
import json
from pathlib import Path

from nexora.capabilities.base import CapabilityRecord


def load_records(path: Path) -> list[CapabilityRecord]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data.get("capabilities")
    if not isinstance(rows, list):
        raise ValueError("capability_catalog_invalid")
    records = [CapabilityRecord(row["id"], row["name"], row["family"], row["source"]).validate() for row in rows]
    ids = [record.capability_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_capability_id")
    return records
