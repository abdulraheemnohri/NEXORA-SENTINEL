"""Read-only family-level evidence evaluation; never promotes capabilities."""
from __future__ import annotations

import json
import sqlite3
import sysconfig
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from nexora.capability_evaluation import evaluate_capability
from nexora.evidence import EvidenceError, EvidenceLedger

PACKAGE_SPEC = Path(sysconfig.get_path("data")) / "share" / "nexora" / "spec"
SOURCE_SPEC = Path(__file__).resolve().parents[2] / "spec"
FAMILIES = tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ") + tuple(
    f"A{letter}" for letter in "ABCDEFGHIJKLMN"
)
ALL_FAMILIES = frozenset(FAMILIES)


class FamilyEvaluationError(ValueError):
    """Raised when family evaluation input is malformed."""


def _catalogue(path: Path | None) -> list[dict[str, Any]]:
    selected = path or (
        PACKAGE_SPEC / "capability_catalog.json"
        if (PACKAGE_SPEC / "capability_catalog.json").is_file()
        else SOURCE_SPEC / "capability_catalog.json"
    )
    try:
        payload = json.loads(Path(selected).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FamilyEvaluationError("capability_catalog_unreadable") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("capabilities"), list):
        raise FamilyEvaluationError("capability_catalog_shape_invalid")
    rows = payload["capabilities"]
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise FamilyEvaluationError("capability_record_must_be_object")
        capability_id = row.get("id")
        if type(capability_id) is not int or not 1 <= capability_id <= 264:
            raise FamilyEvaluationError("capability_id_invalid")
        if capability_id in seen:
            raise FamilyEvaluationError("duplicate_capability_id")
        seen.add(capability_id)
        for key in ("name", "family", "family_name", "status", "source"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise FamilyEvaluationError("capability_source_fields_missing")
        if row["family"] not in ALL_FAMILIES | {"CROSS-CUTTING"}:
            raise FamilyEvaluationError("capability_family_unknown")
    return rows


def build_family_evaluation(
    database: Path | None = None,
    *,
    catalog_path: Path | None = None,
    family: str | None = None,
) -> dict[str, Any]:
    """Evaluate evidence coverage for source-backed capabilities by family."""
    all_rows = _catalogue(catalog_path)
    rows = all_rows
    if family is not None:
        if not isinstance(family, str) or not family.strip():
            raise FamilyEvaluationError("family_filter_invalid")
        rows = [row for row in rows if row["family"].casefold() == family.casefold()]

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["family"]].append(row)

    ledger_path = Path(database) if database is not None else Path("data/registry.sqlite3")
    ledger_state = "NOT_FOUND"
    ledger_verification: dict[str, Any] | None = None
    ledger: EvidenceLedger | None = None
    if ledger_path.is_file():
        try:
            ledger = EvidenceLedger(ledger_path, readonly=True)
            ledger_verification = ledger.verify()
            ledger_state = "VALID" if ledger_verification["valid"] else "INVALID"
        except (EvidenceError, OSError, sqlite3.Error):
            ledger_state = "INVALID"
            ledger_verification = {"valid": False, "error": "ledger_unreadable"}
        if ledger_state != "VALID":
            ledger = None

    family_reports = []
    for family_code, members in sorted(grouped.items()):
        statuses = Counter(row["status"] for row in members)
        capability_reports = []
        for row in sorted(members, key=lambda item: item["id"]):
            if ledger is not None:
                summary = ledger.evidence_summary(row["id"])
                evidence = evaluate_capability(
                    row["id"], [], ledger_valid=True,
                    evidence_types=set(summary["evidence_types"]),
                    evidence_record_count=summary["record_count"],
                )
                if (
                    evidence["assessment"] == "EVIDENCE_GAPS"
                    and evidence["first_blocked_gate"] in {"APPROVED", "ENABLED"}
                    and all(not stage["missing_evidence"] for stage in evidence["stages"])
                ):
                    evidence["assessment"] = "EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION"
            elif ledger_state == "INVALID":
                evidence = {
                    "assessment": "BLOCKED_LEDGER_INTEGRITY",
                    "evidence_records": 0, "evidence_types": [],
                    "first_blocked_gate": None,
                }
            else:
                evidence = {
                    "assessment": "NOT_EVALUATED_NO_LEDGER",
                    "evidence_records": None, "evidence_types": [],
                    "first_blocked_gate": None,
                }
            capability_reports.append({
                "id": row["id"], "name": row["name"],
                "catalogue_status": row["status"], "source": row["source"],
                "evidence": evidence,
            })
        assessments = Counter(item["evidence"]["assessment"] for item in capability_reports)
        if ledger_state == "NOT_FOUND":
            assessment = "NOT_EVALUATED_NO_LEDGER"
        elif ledger_state == "INVALID":
            assessment = "BLOCKED_LEDGER_INTEGRITY"
        elif (
            assessments.get("EVIDENCE_COMPLETE", 0)
            + assessments.get("EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION", 0)
            == len(members)
        ):
            assessment = (
                "EVIDENCE_COMPLETE"
                if assessments.get("EVIDENCE_COMPLETE", 0) == len(members)
                else "EVIDENCE_PRESENT_AWAITING_HUMAN_AUTHORIZATION"
            )
        else:
            assessment = "EVIDENCE_GAPS"
        family_reports.append({
            "family": family_code, "family_name": members[0]["family_name"],
            "source_backed_capabilities": len(members),
            "catalogue_status_counts": dict(sorted(statuses.items())),
            "evidence_assessment": assessment,
            "evidence_assessment_counts": dict(sorted(assessments.items())),
            "capabilities": capability_reports,
        })

    all_ids = {row["id"] for row in all_rows}
    missing_ids = sorted(set(range(1, 265)) - all_ids)
    return {
        "scope": "source_backed_catalogue_records_only",
        "ledger": {"path": str(ledger_path), "status": ledger_state,
                   "verification": ledger_verification},
        "catalogue": {
            "target_capabilities": 264, "source_backed_capabilities": len(all_ids),
            "missing_source_definition_count": len(missing_ids),
            "missing_source_definition_ids": missing_ids,
            "represented_families": len({row["family"] for row in all_rows}),
            "expected_families": 40,
        },
        "filter": {"family": family}, "families": family_reports,
        "lifecycle_changed": False, "capability_promotions_performed": False,
        "execution_enabled": False, "policy_mutation_enabled": False,
        "note": (
            "Evidence presence is not artifact validation or authorization. "
            "Missing source definitions and unknown relationships remain unknown."
        ),
    }
