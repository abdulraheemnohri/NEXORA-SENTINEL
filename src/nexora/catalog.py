"""Exact-source capability registry validation; missing source entries remain explicit."""
import json
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[2] / "spec" / "capability_catalog.json"


def status(path: Path = CATALOG) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("capabilities", [])
    ids = [x.get("id") for x in rows if isinstance(x, dict)]
    families = {x.get("family") for x in rows if isinstance(x, dict)}
    valid = all(
        isinstance(x, dict)
        and isinstance(x.get("id"), int)
        and x.get("name")
        and x.get("family")
        and x.get("status") in {
            "specified", "registered", "implemented", "tested",
            "shadowed", "approved", "enabled",
        }
        for x in rows
    )
    expected = data.get("expected_capability_count", 264)
    expected_families = data.get("expected_family_count", 40)
    unique = len(ids) == len(set(ids))
    complete = len(rows) == expected and len(families) == expected_families and unique and valid
    return {
        "expected_capabilities": expected,
        "registered_capabilities": len(rows),
        "expected_families": expected_families,
        "represented_families": len(families),
        "unique_ids": unique,
        "entries_valid": valid,
        "complete": complete,
        "status": data.get("status", "unknown"),
        "missing_ranges": data.get("missing_ranges", []),
    }
