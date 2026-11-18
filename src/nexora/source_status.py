"""Report exact-source recovery gaps without inventing catalogue content."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexora.catalog import CATALOG

SOURCE_SPEC = Path(__file__).resolve().parents[2] / "spec"
META_RULES = SOURCE_SPEC / "meta_rules.json"


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("source_artifact_must_be_object")
    return payload


def build_source_status(
    catalog_path: Path = CATALOG,
    rules_path: Path = META_RULES,
) -> dict[str, Any]:
    catalog = _read_json(Path(catalog_path))
    rules = _read_json(Path(rules_path))
    capability_rows = catalog.get("capabilities", [])
    rule_rows = rules.get("rules", [])
    if not isinstance(capability_rows, list) or not isinstance(rule_rows, list):
        raise ValueError("source_artifact_records_must_be_lists")
    capability_ids = {
        row.get("id") for row in capability_rows
        if isinstance(row, dict) and type(row.get("id")) is int
    }
    rule_ids = {
        row.get("id") for row in rule_rows
        if isinstance(row, dict) and type(row.get("id")) is int
    }
    missing_capabilities = sorted(set(range(1, 265)) - capability_ids)
    missing_rules = sorted(set(range(1, 46)) - rule_ids)
    return {
        "status": "SOURCE_RECOVERY_REQUIRED" if missing_capabilities or missing_rules else "SOURCE_COVERAGE_PRESENT",
        "capabilities": {
            "expected": 264, "source_backed": len(capability_ids),
            "missing_count": len(missing_capabilities),
            "missing_ids": missing_capabilities,
            "catalogue_status": catalog.get("status", "unknown"),
        },
        "meta_rules": {
            "expected": 45, "source_backed": len(rule_ids),
            "missing_count": len(missing_rules),
            "missing_ids": missing_rules,
            "catalogue_status": rules.get("status", "unknown"),
        },
        "import_contract": {
            "requires_exact_source_text": True,
            "requires_source_label_or_document_reference": True,
            "rejects_duplicate_ids": True,
            "rejects_overwrite_of_existing_records": True,
            "requires_human_review_before_catalogue_update": True,
            "automatic_import_performed": False,
        },
        "execution_enabled": False,
        "policy_mutation_enabled": False,
        "note": (
            "This report identifies missing source records only. It does not "
            "reconstruct definitions, infer family assignments, or generate meta-rules."
        ),
    }
