"""Read-only project specification and governance readiness reports.

This module reports source gaps and policy gaps. It never fills missing source
material, authorizes settings, changes governance, or enables execution.
"""
from __future__ import annotations

import json
import stat
from dataclasses import fields
from pathlib import Path
from typing import Any

from nexora.config import Settings
from nexora.governance.validation import (
    DEFAULT_MATRIX,
    DEFAULT_PRECEDENCE,
    build_governance_report,
)
from nexora.source_status import META_RULES, SOURCE_SPEC, build_source_status
from nexora.catalog import CATALOG, status as catalog_status

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SETTINGS_POLICY = ROOT / "config" / "settings_authorization.json"


def _ranges(values: list[int]) -> list[str]:
    """Compress sorted integer IDs into deterministic inclusive ranges."""
    if not values:
        return []
    result: list[str] = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        result.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    result.append(str(start) if start == previous else f"{start}-{previous}")
    return result


def build_settings_policy_status(
    policy_path: Path = DEFAULT_SETTINGS_POLICY,
) -> dict[str, Any]:
    """Report authorization-policy readiness without interpreting or applying it."""
    path = Path(policy_path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        present = False
    else:
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("settings_authorization_policy_is_symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("settings_authorization_policy_not_a_file")
        present = True

    setting_names = sorted(field.name for field in fields(Settings))
    required_controls = [
        "per_setting_authority",
        "human_confirmation",
        "before_after_audit",
        "backup_before_apply",
        "rollback_trigger_conditions",
        "rollback_verification",
        "unknown_policy_denies",
    ]
    return {
        "status": "POLICY_NOT_APPROVED" if not present else "PRESENT_REQUIRES_INDEPENDENT_REVIEW",
        "policy_file": str(path),
        "policy_file_present": present,
        "settings_count": len(setting_names),
        "settings_without_approved_authorization": setting_names,
        "required_policy_controls": required_controls,
        "missing_policy_controls": required_controls,
        "authorization": "NOT_EVALUATED",
        "apply_supported": False,
        "rollback_supported": False,
        "settings_mutation_enabled": False,
        "execution_enabled": False,
        "note": (
            "Presence of a policy file is not approval. No policy schema, authority, "
            "per-setting permissions, or rollback rules are inferred from file contents. "
            "An owner-reviewed policy and independent verification are required."
        ),
    }


def build_spec_status(
    catalog_path: Path = CATALOG,
    rules_path: Path = META_RULES,
    matrix_path: Path = DEFAULT_MATRIX,
    precedence_path: Path = DEFAULT_PRECEDENCE,
    settings_policy_path: Path = DEFAULT_SETTINGS_POLICY,
) -> dict[str, Any]:
    """Aggregate exact-source, matrix, family, and settings-policy readiness."""
    source = build_source_status(catalog_path, rules_path)
    catalogue = catalog_status(catalog_path)
    governance = build_governance_report(matrix_path, precedence_path)
    settings_policy = build_settings_policy_status(settings_policy_path)

    missing_capabilities = source["capabilities"]["missing_ids"]
    missing_rules = source["meta_rules"]["missing_ids"]
    unknown_pairs = governance["matrix"]["unknown_pairs"]
    blockers: list[dict[str, Any]] = []
    if missing_capabilities:
        blockers.append({
            "id": "missing_capability_source",
            "status": "BLOCKED",
            "missing_count": len(missing_capabilities),
            "missing_ranges": _ranges(missing_capabilities),
        })
    if not catalogue["entries_valid"] or not catalogue["unique_ids"]:
        blockers.append({
            "id": "capability_catalogue_integrity",
            "status": "BLOCKED",
            "entries_valid": catalogue["entries_valid"],
            "unique_ids": catalogue["unique_ids"],
        })
    if not catalogue["exact_family_coverage"]:
        blockers.append({
            "id": "capability_family_coverage",
            "status": "BLOCKED",
            "expected_families": catalogue["expected_families"],
            "represented_families": catalogue["represented_families"],
        })
    if missing_rules:
        blockers.append({
            "id": "missing_meta_rule_source",
            "status": "BLOCKED",
            "missing_count": len(missing_rules),
            "missing_ranges": _ranges(missing_rules),
        })
    if unknown_pairs:
        blockers.append({
            "id": "interaction_matrix_unknown_pairs",
            "status": "BLOCKED",
            "unknown_pairs": unknown_pairs,
            "declared_pairs": governance["matrix"]["declared_pairs"],
            "possible_pairs": governance["matrix"]["possible_pairs"],
        })
    if settings_policy["status"] != "POLICY_APPROVED":
        blockers.append({
            "id": "settings_authorization_and_rollback",
            "status": "BLOCKED",
            "policy_status": settings_policy["status"],
            "settings_count": settings_policy["settings_count"],
        })

    return {
        "status": "BLOCKED" if blockers else "READY_FOR_INDEPENDENT_REVIEW",
        "scope": {
            "architecture": "STA-264",
            "canonical_capabilities": 264,
            "canonical_meta_rules": 45,
            "source_backed_capability_subset_only": bool(missing_capabilities),
            "source_backed_meta_rule_subset_only": bool(missing_rules),
            "full_specification_claimed": False,
        },
        "capability_catalogue": {
            **catalogue,
            "missing_id_ranges": _ranges(missing_capabilities),
        },
        "source_recovery": {
            "capabilities": source["capabilities"],
            "meta_rules": source["meta_rules"],
            "import_contract": source["import_contract"],
        },
        "interaction_matrix": governance["matrix"],
        "precedence": governance["precedence"],
        "settings_authorization": settings_policy,
        "blockers": blockers,
        "controls": {
            "read_only": True,
            "relationship_inference_enabled": False,
            "settings_mutation_enabled": False,
            "policy_mutation_enabled": False,
            "execution_enabled": False,
            "autonomy_increase_enabled": False,
        },
        "next_safe_actions": [
            "Import missing source records only from exact authoritative material.",
            "Review and approve each interaction relationship with provenance.",
            "Obtain owner approval for per-setting authorization and rollback rules.",
        ],
    }
