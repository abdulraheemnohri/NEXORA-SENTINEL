"""Read-only report for source-backed self-capability specifications."""
from __future__ import annotations

import json
import sysconfig
from collections import Counter
from pathlib import Path
from typing import Any

PACKAGE_SPEC = Path(sysconfig.get_path("data")) / "share" / "nexora" / "spec"
SOURCE_SPEC = Path(__file__).resolve().parents[2] / "spec"


def _spec_path(name: str) -> Path:
    packaged = PACKAGE_SPEC / name
    return packaged if packaged.is_file() else SOURCE_SPEC / name


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"self_capability_spec_unreadable:{Path(path).name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"self_capability_spec_must_be_object:{Path(path).name}")
    return value


def build_report(*, catalog_path: Path | None = None, rules_path: Path | None = None,
                 matrix_path: Path | None = None, family: str | None = None,
                 include_records: bool = False) -> dict[str, Any]:
    """Summarize exact supplied definitions, explicit gaps and unknown relations."""
    catalog = _read(catalog_path or _spec_path("capability_catalog.json"))
    rules = _read(rules_path or _spec_path("meta_rules.json"))
    matrix = _read(matrix_path or _spec_path("interaction_matrix.json"))
    rows, rule_rows = catalog.get("capabilities"), rules.get("rules")
    if not isinstance(rows, list) or not isinstance(rule_rows, list):
        raise ValueError("self_capability_spec_rows_invalid")
    ids: list[int] = []
    family_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    valid_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("capability_record_must_be_object")
        value = row.get("id")
        if type(value) is not int or not 1 <= value <= 264:
            raise ValueError("capability_id_invalid")
        if value in ids:
            raise ValueError("duplicate_capability_id")
        if not all(isinstance(row.get(key), str) and row[key].strip()
                   for key in ("name", "family", "family_name", "source", "status")):
            raise ValueError("capability_record_source_fields_missing")
        ids.append(value)
        family_counts[row["family"]] += 1
        source_counts[row["source"]] += 1
        valid_rows.append(row)
    rule_ids: list[int] = []
    for row in rule_rows:
        if not isinstance(row, dict):
            raise ValueError("meta_rule_record_must_be_object")
        value = row.get("id")
        if type(value) is not int or not 1 <= value <= 45:
            raise ValueError("meta_rule_id_invalid")
        if value in rule_ids:
            raise ValueError("duplicate_meta_rule_id")
        if not all(isinstance(row.get(key), str) and row[key].strip()
                   for key in ("title", "text", "status")):
            raise ValueError("meta_rule_source_fields_missing")
        rule_ids.append(value)
    missing_ids = sorted(set(range(1, 265)) - set(ids))
    missing_rules = sorted(set(range(1, 46)) - set(rule_ids))
    selected = valid_rows
    if family is not None:
        if not isinstance(family, str) or not family.strip():
            raise ValueError("family_filter_invalid")
        selected = [row for row in valid_rows if row["family"].casefold() == family.casefold()]
    entries = matrix.get("entries")
    if not isinstance(entries, list):
        raise ValueError("interaction_matrix_entries_invalid")
    return {
        "catalogue": {
            "expected_capabilities": 264, "source_backed_capabilities": len(valid_rows),
            "missing_capability_count": len(missing_ids), "missing_capability_ids": missing_ids,
            "represented_families": len(family_counts), "expected_families": 40,
            "family_counts": dict(sorted(family_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
            "declared_status": catalog.get("status", "unknown"),
            "complete": not missing_ids and len(family_counts) == 40,
        },
        "meta_rules": {
            "expected_rules": 45, "source_backed_rules": len(rule_rows),
            "missing_rule_count": len(missing_rules), "missing_rule_ids": missing_rules,
            "declared_status": rules.get("status", "unknown"), "complete": not missing_rules,
        },
        "interactions": {
            "matrix_dimensions": matrix.get("dimensions"), "known_relation_count": len(entries),
            "declared_status": matrix.get("status", "unknown"),
            "unknown_relation_policy": matrix.get("unknown_relation_policy", "unknown"),
            "note": "No pairwise relation is inferred from numbering or family membership.",
        },
        "cross_cutting_layers": catalog.get("cross_cutting_layers", []),
        "filter": {"family": family}, "records": selected if include_records else [],
        "execution_enabled": False, "policy_mutation_enabled": False,
        "autonomous_promotion_enabled": False,
    }
