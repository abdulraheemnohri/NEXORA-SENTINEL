"""Strict, read-only validation of STA source specification artifacts.

Validation checks structure and provenance. It never creates missing capability
records, meta-rules, interaction relations, settings, or authorization grants.
"""
from __future__ import annotations

import json
import re
import stat
import sysconfig
from pathlib import Path
from typing import Any

from nexora.catalog import CATALOG, EXPECTED_FAMILIES, VALID_STATUSES
from nexora.governance.validation import DEFAULT_MATRIX, DEFAULT_PRECEDENCE, RELATIONS
from nexora.source_status import META_RULES

_PACKAGE_SPEC = Path(sysconfig.get_path("data")) / "share" / "nexora" / "spec"
_PACKAGED_MATRIX = _PACKAGE_SPEC / "interaction_matrix.json"
_PACKAGED_PRECEDENCE = _PACKAGE_SPEC / "precedence.json"
DEFAULT_VALIDATION_MATRIX = _PACKAGED_MATRIX if _PACKAGED_MATRIX.is_file() else DEFAULT_MATRIX
DEFAULT_VALIDATION_PRECEDENCE = (
    _PACKAGED_PRECEDENCE if _PACKAGED_PRECEDENCE.is_file() else DEFAULT_PRECEDENCE
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CAPABILITY_FIELDS = {"id", "name", "family", "family_name", "status", "source"}
_META_RULE_FIELDS = {"id", "title", "text", "status", "mutable_by_agent"}
_EXPECTED_PRECEDENCE = ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"]


class SpecificationValidationError(ValueError):
    """Raised for invalid validator arguments or an unusable report."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpecificationValidationError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _read_object(path: Path, label: str, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    source = Path(path)
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        errors.append({"artifact": label, "code": "file_missing"})
        return None
    except OSError as exc:
        errors.append({"artifact": label, "code": "file_unreadable", "detail": type(exc).__name__})
        return None
    if stat.S_ISLNK(metadata.st_mode):
        errors.append({"artifact": label, "code": "symlink_refused"})
        return None
    if not stat.S_ISREG(metadata.st_mode):
        errors.append({"artifact": label, "code": "not_regular_file"})
        return None
    try:
        raw = source.read_text(encoding="utf-8")
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except SpecificationValidationError as exc:
        errors.append({"artifact": label, "code": str(exc)})
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append({"artifact": label, "code": "invalid_json_or_encoding", "detail": type(exc).__name__})
        return None
    if not isinstance(payload, dict):
        errors.append({"artifact": label, "code": "root_must_be_object"})
        return None
    return payload


def _ranges(values: list[int]) -> list[str]:
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


def _error(
    errors: list[dict[str, Any]],
    artifact: str,
    code: str,
    record_id: int | None = None,
) -> None:
    item: dict[str, Any] = {"artifact": artifact, "code": code}
    if record_id is not None:
        item["record_id"] = record_id
    errors.append(item)


def _validate_capabilities(
    document: dict[str, Any] | None,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    label = "capability_catalogue"
    if document is None:
        return {"valid": False, "registered": 0, "missing_ids": list(range(1, 265)), "families_present": []}
    if type(document.get("expected_capability_count")) is not int or document.get("expected_capability_count") != 264:
        _error(errors, label, "expected_capability_count_must_be_264")
    if type(document.get("expected_family_count")) is not int or document.get("expected_family_count") != 40:
        _error(errors, label, "expected_family_count_must_be_40")
    catalogue_status = document.get("status")
    if not isinstance(catalogue_status, str) or catalogue_status not in {"partial_source_import", "complete"}:
        _error(errors, label, "catalogue_status_invalid")

    rows = document.get("capabilities")
    if not isinstance(rows, list):
        _error(errors, label, "capabilities_must_be_list")
        rows = []

    seen: set[int] = set()
    family_names: dict[str, set[str]] = {}
    valid_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            _error(errors, label, f"record_{index}_must_be_object")
            continue
        missing = sorted(_CAPABILITY_FIELDS - row.keys())
        if missing:
            _error(errors, label, f"record_missing_fields:{','.join(missing)}")
            continue
        identifier = row.get("id")
        if type(identifier) is not int or not 1 <= identifier <= 264:
            _error(errors, label, "capability_id_invalid")
            continue
        if identifier in seen:
            _error(errors, label, "duplicate_capability_id", identifier)
            continue
        seen.add(identifier)

        if any(
            not isinstance(row.get(field), str) or not row[field].strip()
            for field in ("name", "family_name", "source")
        ):
            _error(errors, label, "capability_text_or_source_invalid", identifier)
        family = row.get("family")
        if not isinstance(family, str) or family not in EXPECTED_FAMILIES | {"CROSS-CUTTING"}:
            _error(errors, label, "capability_family_invalid", identifier)
        elif isinstance(row.get("family_name"), str) and row["family_name"].strip():
            family_names.setdefault(family, set()).add(row["family_name"].strip())
        if not isinstance(row.get("status"), str) or row["status"] not in VALID_STATUSES:
            _error(errors, label, "capability_status_invalid", identifier)
        valid_count += 1

    for family, names in sorted(family_names.items()):
        if len(names) > 1:
            _error(errors, label, f"conflicting_family_names:{family}")

    missing_ids = sorted(set(range(1, 265)) - seen)
    missing_families = sorted(EXPECTED_FAMILIES - set(family_names))
    declared_ranges = document.get("missing_ranges")
    actual_ranges = _ranges(missing_ids)
    if not isinstance(declared_ranges, list) or declared_ranges != actual_ranges:
        _error(errors, label, "declared_missing_ranges_do_not_match_records")
    if catalogue_status == "complete" and missing_ids:
        _error(errors, label, "complete_status_with_missing_capabilities")
    if catalogue_status == "complete" and valid_count != 264:
        _error(errors, label, "complete_status_with_invalid_record_count")
    if catalogue_status == "complete" and missing_families:
        _error(errors, label, "complete_status_with_missing_families")

    return {
        "valid": True,
        "registered": len(seen),
        "valid_record_count": valid_count,
        "expected": 264,
        "missing_ids": missing_ids,
        "missing_ranges": actual_ranges,
        "families_present": sorted(family_names),
        "family_count_present": len(family_names),
        "missing_families": missing_families,
        "complete": not missing_ids and valid_count == 264 and not missing_families,
    }


def _validate_meta_rules(
    document: dict[str, Any] | None,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    label = "meta_rules"
    if document is None:
        return {"valid": False, "registered": 0, "missing_ids": list(range(1, 46))}
    if type(document.get("expected_rule_count")) is not int or document.get("expected_rule_count") != 45:
        _error(errors, label, "expected_rule_count_must_be_45")
    rules_status = document.get("status")
    if not isinstance(rules_status, str) or rules_status not in {"partial_source_import", "complete"}:
        _error(errors, label, "meta_rule_status_invalid")

    rows = document.get("rules")
    if not isinstance(rows, list):
        _error(errors, label, "rules_must_be_list")
        rows = []

    seen: set[int] = set()
    valid_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            _error(errors, label, f"record_{index}_must_be_object")
            continue
        missing = sorted(_META_RULE_FIELDS - row.keys())
        if missing:
            _error(errors, label, f"record_missing_fields:{','.join(missing)}")
            continue
        identifier = row.get("id")
        if type(identifier) is not int or not 1 <= identifier <= 45:
            _error(errors, label, "meta_rule_id_invalid")
            continue
        if identifier in seen:
            _error(errors, label, "duplicate_meta_rule_id", identifier)
            continue
        seen.add(identifier)
        if any(
            not isinstance(row.get(field), str) or not row[field].strip()
            for field in ("title", "text", "status")
        ):
            _error(errors, label, "meta_rule_text_invalid", identifier)
        if row.get("mutable_by_agent") is not False:
            _error(errors, label, "meta_rule_must_be_immutable_to_agent", identifier)
        valid_count += 1

    missing_ids = sorted(set(range(1, 46)) - seen)
    declared_ranges = document.get("missing_rule_ranges")
    actual_ranges = _ranges(missing_ids)
    if not isinstance(declared_ranges, list) or declared_ranges != actual_ranges:
        _error(errors, label, "declared_missing_rule_ranges_do_not_match_records")
    if rules_status == "complete" and missing_ids:
        _error(errors, label, "complete_status_with_missing_meta_rules")
    if rules_status == "complete" and valid_count != 45:
        _error(errors, label, "complete_status_with_invalid_record_count")

    return {
        "valid": True,
        "registered": len(seen),
        "valid_record_count": valid_count,
        "expected": 45,
        "missing_ids": missing_ids,
        "missing_ranges": actual_ranges,
        "complete": not missing_ids and valid_count == 45,
        "agent_mutation_allowed": False,
    }


def _validate_matrix(
    document: dict[str, Any] | None,
    capability_ids: set[int],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    label = "interaction_matrix"
    if document is None:
        return {
            "valid": False,
            "declared_pairs": 0,
            "possible_pairs": 264 * 264,
            "unknown_pairs": 264 * 264,
            "coverage_complete": False,
        }
    if document.get("dimensions") != [264, 264]:
        _error(errors, label, "dimensions_must_be_264_by_264")
    if document.get("capability_id_range") != [1, 264]:
        _error(errors, label, "capability_id_range_invalid")
    if document.get("default_relation") != "unknown":
        _error(errors, label, "default_relation_must_remain_unknown")
    if document.get("unknown_relation_policy") != "deny_or_require_human_review":
        _error(errors, label, "unknown_relation_policy_must_fail_closed")
    allowed = document.get("allowed_relations")
    if (
        not isinstance(allowed, list)
        or any(not isinstance(value, str) for value in allowed)
        or len(allowed) != len(set(allowed))
        or set(allowed) != RELATIONS
    ):
        _error(errors, label, "allowed_relation_vocabulary_invalid")

    rows = document.get("entries")
    if not isinstance(rows, list):
        _error(errors, label, "entries_must_be_list")
        rows = []

    seen: set[tuple[int, int]] = set()
    valid_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            _error(errors, label, f"entry_{index}_must_be_object")
            continue
        source, target, relation = row.get("source"), row.get("target"), row.get("relation")
        if (
            type(source) is not int
            or type(target) is not int
            or not (1 <= source <= 264 and 1 <= target <= 264)
        ):
            _error(errors, label, f"entry_{index}_pair_out_of_range")
            continue
        pair = (source, target)
        if pair in seen:
            _error(errors, label, "duplicate_interaction_pair")
            continue
        seen.add(pair)
        if source not in capability_ids or target not in capability_ids:
            _error(errors, label, "relation_references_missing_capability")
        if not isinstance(relation, str) or relation not in RELATIONS:
            _error(errors, label, "interaction_relation_invalid")
        if not isinstance(row.get("source_ref"), str) or not row["source_ref"].strip():
            _error(errors, label, "interaction_source_reference_required")
        if (
            not isinstance(row.get("evidence_sha256"), str)
            or not _SHA256.fullmatch(row["evidence_sha256"])
        ):
            _error(errors, label, "interaction_evidence_sha256_required")
        valid_count += 1

    possible = 264 * 264
    unknown = possible - len(seen)
    return {
        "valid": True,
        "declared_pairs": len(seen),
        "possible_pairs": possible,
        "unknown_pairs": unknown,
        "coverage_ratio": round(len(seen) / possible, 8),
        "coverage_complete": unknown == 0,
        "entries_with_provenance": valid_count,
        "automatic_compatibility_grants": False,
    }


def _validate_precedence(
    document: dict[str, Any] | None,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    label = "precedence"
    if document is None:
        return {"valid": False, "status": "MISSING"}
    valid = True
    if document.get("priority_order") != _EXPECTED_PRECEDENCE:
        _error(errors, label, "priority_order_invalid")
        valid = False
    if document.get("unknown_conflict") != "BLOCK_AND_ESCALATE":
        _error(errors, label, "unknown_conflict_must_block_and_escalate")
        valid = False
    if document.get("equal_priority_conflict") != "BLOCK_AND_ESCALATE":
        _error(errors, label, "equal_priority_conflict_must_block_and_escalate")
        valid = False
    if document.get("mutable_by_agent") is not False:
        _error(errors, label, "precedence_must_be_immutable_to_agent")
        valid = False
    return {
        "valid": valid,
        "priority_order": document.get("priority_order"),
        "unknown_conflict": document.get("unknown_conflict"),
        "equal_priority_conflict": document.get("equal_priority_conflict"),
        "mutable_by_agent": document.get("mutable_by_agent"),
    }


def validate_specification(
    *,
    catalog_path: Path = CATALOG,
    rules_path: Path = META_RULES,
    matrix_path: Path = DEFAULT_VALIDATION_MATRIX,
    precedence_path: Path = DEFAULT_VALIDATION_PRECEDENCE,
) -> dict[str, Any]:
    """Validate source artifact structure and provenance without writing files.

    A structurally valid but incomplete source remains VALID_PARTIAL_BLOCKED.
    Even a complete artifact set is marked as requiring separate policy and
    governance review; this validator never grants implementation authority.
    """
    errors: list[dict[str, Any]] = []
    catalog_doc = _read_object(Path(catalog_path), "capability_catalogue", errors)
    rules_doc = _read_object(Path(rules_path), "meta_rules", errors)
    matrix_doc = _read_object(Path(matrix_path), "interaction_matrix", errors)
    precedence_doc = _read_object(Path(precedence_path), "precedence", errors)

    catalog = _validate_capabilities(catalog_doc, errors)
    rules = _validate_meta_rules(rules_doc, errors)
    capability_ids = set(
        range(1, 265)
        if catalog_doc is None
        else (
            row["id"]
            for row in catalog_doc.get("capabilities", [])
            if isinstance(row, dict)
            and type(row.get("id")) is int
            and 1 <= row["id"] <= 264
        )
    )
    matrix = _validate_matrix(matrix_doc, capability_ids, errors)
    precedence = _validate_precedence(precedence_doc, errors)

    valid = not errors
    complete = (
        valid
        and catalog.get("complete", False)
        and rules.get("complete", False)
        and matrix.get("coverage_complete", False)
        and precedence.get("valid", False)
    )
    if not valid:
        status = "INVALID"
    elif complete:
        status = "VALID_COMPLETE_REQUIRES_INDEPENDENT_REVIEW"
    else:
        status = "VALID_PARTIAL_BLOCKED"

    return {
        "status": status,
        "valid": valid,
        "complete": complete,
        "artifacts": {
            "capability_catalogue": catalog,
            "meta_rules": rules,
            "interaction_matrix": matrix,
            "precedence": precedence,
        },
        "errors": errors,
        "controls": {
            "read_only": True,
            "source_mutation_enabled": False,
            "relationship_inference_enabled": False,
            "policy_mutation_enabled": False,
            "settings_mutation_enabled": False,
            "execution_enabled": False,
            "autonomy_increase_enabled": False,
        },
        "note": (
            "Structural validity is not source authenticity, policy approval, "
            "governance approval, implementation evidence or execution authorization. "
            "Unknown capability definitions, meta-rules and interaction pairs remain unresolved."
        ),
    }
