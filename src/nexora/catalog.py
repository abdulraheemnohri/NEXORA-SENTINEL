"""Exact-source capability registry validation; missing source entries remain explicit."""
import json
import sysconfig
from pathlib import Path

PACKAGE_SPEC = Path(sysconfig.get_path("data")) / "share" / "nexora" / "spec"
SOURCE_SPEC = Path(__file__).resolve().parents[2] / "spec"
CATALOG = (PACKAGE_SPEC / "capability_catalog.json"
           if (PACKAGE_SPEC / "capability_catalog.json").is_file()
           else SOURCE_SPEC / "capability_catalog.json")
EXPECTED_FAMILIES = {
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
    "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "AA", "AB", "AC", "AD", "AE", "AF", "AG", "AH", "AI", "AJ", "AK", "AL", "AM", "AN",
}
VALID_STATUSES = {
    "specified", "registered", "implemented", "tested",
    "shadowed", "approved", "enabled",
}
REQUIRED_FIELDS = {"id", "name", "family", "family_name", "status", "source"}


def status(path: Path = CATALOG) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("capabilities", [])
    valid_rows = [x for x in rows if isinstance(x, dict)]
    ids = [x.get("id") for x in valid_rows]
    families = {x.get("family") for x in valid_rows if x.get("family") in EXPECTED_FAMILIES}
    entries_valid = len(valid_rows) == len(rows) and all(
        REQUIRED_FIELDS.issubset(x)
        and isinstance(x.get("id"), int)
        and not isinstance(x.get("id"), bool)
        and 1 <= x["id"] <= 264
        and isinstance(x.get("name"), str) and bool(x["name"].strip())
        and x.get("family") in (EXPECTED_FAMILIES | {"CROSS-CUTTING"})
        and isinstance(x.get("family_name"), str) and bool(x["family_name"].strip())
        and x.get("status") in VALID_STATUSES
        and isinstance(x.get("source"), str) and bool(x["source"].strip())
        for x in valid_rows
    )
    expected = data.get("expected_capability_count", 264)
    expected_families = data.get("expected_family_count", 40)
    unique = len(ids) == len(set(ids))
    exact_ids = set(ids) == set(range(1, 265))
    exact_families = families == EXPECTED_FAMILIES
    complete = (
        len(rows) == expected == 264
        and expected_families == 40
        and exact_ids and exact_families and unique and entries_valid
        and not data.get("missing_ranges")
        and data.get("status") == "complete"
    )
    return {
        "expected_capabilities": expected,
        "registered_capabilities": len(rows),
        "expected_families": expected_families,
        "represented_families": len(families),
        "unique_ids": unique,
        "exact_id_coverage": exact_ids,
        "exact_family_coverage": exact_families,
        "entries_valid": entries_valid,
        "complete": complete,
        "status": data.get("status", "unknown"),
        "missing_ranges": data.get("missing_ranges", []),
    }
