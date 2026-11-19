"""Source-backed 40-family inventory; missing assignments remain unknown."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from nexora.catalog import CATALOG, EXPECTED_FAMILIES, VALID_STATUSES


class FamilyInventoryError(ValueError):
    """Raised when source catalogue data cannot be inspected safely."""


def build_family_inventory(catalog_path: Path = CATALOG) -> dict[str, Any]:
    """Count source-backed capability rows without inventing missing assignments."""
    path = Path(catalog_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FamilyInventoryError("capability_catalogue_read_failed") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("capabilities"), list):
        raise FamilyInventoryError("capability_catalogue_schema_invalid")

    members: dict[str, list[dict[str, Any]]] = {
        family: [] for family in sorted(EXPECTED_FAMILIES)
    }
    seen_ids: set[int] = set()
    unknown_family_rows = 0
    cross_cutting_rows: list[int] = []
    for row in payload["capabilities"]:
        if not isinstance(row, dict):
            raise FamilyInventoryError("capability_record_invalid")
        identifier = row.get("id")
        if type(identifier) is not int or not 1 <= identifier <= 264:
            raise FamilyInventoryError("capability_id_invalid")
        if identifier in seen_ids:
            raise FamilyInventoryError("capability_id_duplicate")
        seen_ids.add(identifier)
        family = row.get("family")
        family_name = row.get("family_name")
        source = row.get("source")
        name = row.get("name")
        status = row.get("status")
        if not isinstance(name, str) or not name.strip():
            raise FamilyInventoryError("capability_name_missing")
        if not isinstance(source, str) or not source.strip():
            raise FamilyInventoryError("capability_source_missing")
        if status not in VALID_STATUSES:
            raise FamilyInventoryError("capability_status_invalid")
        if family == "CROSS-CUTTING":
            cross_cutting_rows.append(identifier)
            continue
        if not isinstance(family, str) or family not in EXPECTED_FAMILIES:
            unknown_family_rows += 1
            continue
        if not isinstance(family_name, str) or not family_name.strip():
            raise FamilyInventoryError("source_family_name_missing")
        members[family].append({
            "id": identifier,
            "name": row.get("name"),
            "family_name": family_name.strip(),
            "source": row.get("source"),
            "status": row.get("status"),
        })

    families: list[dict[str, Any]] = []
    conflicting_names: list[str] = []
    for code, rows in members.items():
        names = sorted({row["family_name"] for row in rows})
        if len(names) > 1:
            conflicting_names.append(code)
        families.append({
            "family_code": code,
            "family_name": names[0] if len(names) == 1 else None,
            "family_name_status": (
                "SOURCE_BACKED" if len(names) == 1
                else "CONFLICTING_SOURCE_NAMES" if len(names) > 1
                else "NOT_YET_SOURCE_BACKED"
            ),
            "source_backed_capability_count": len(rows),
            "capability_ids": sorted(row["id"] for row in rows),
            "capabilities": sorted(rows, key=lambda item: item["id"]),
        })

    expected_ids = set(range(1, 265))
    missing_ids = sorted(expected_ids - seen_ids)
    represented = sum(bool(group["source_backed_capability_count"]) for group in families)
    return {
        "status": "SOURCE_INVENTORY_REVIEW_REQUIRED" if (
            missing_ids or unknown_family_rows or conflicting_names or represented < 40
        ) else "SOURCE_INVENTORY_COMPLETE",
        "expected_family_count": 40,
        "represented_family_count": represented,
        "unrepresented_family_codes": [
            group["family_code"] for group in families
            if group["source_backed_capability_count"] == 0
        ],
        "conflicting_family_name_codes": conflicting_names,
        "source_backed_capability_count": len(seen_ids),
        "missing_capability_ids": missing_ids,
        "unknown_family_assignment_count": unknown_family_rows,
        "cross_cutting_capability_ids": sorted(cross_cutting_rows),
        "cross_cutting_capability_count": len(cross_cutting_rows),
        "families": families,
        "controls": {
            "read_only": True,
            "family_assignment_inference_enabled": False,
            "relationship_inference_enabled": False,
            "capability_activation_enabled": False,
            "execution_enabled": False,
        },
        "note": (
            "Only family names and capability assignments present in the "
            "source catalogue are displayed. Missing capability IDs are not "
            "assigned to families, and no inter-family relationship is inferred."
        ),
    }
