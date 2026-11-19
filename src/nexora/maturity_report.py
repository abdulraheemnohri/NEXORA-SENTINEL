"""Read-only capability maturity and evidence intelligence report.

L0-L4 is deliberately unassigned until canonical criteria are source-backed.
Existing lifecycle evidence gates remain the only maturity-adjacent assessment.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nexora.capability_evaluation import evaluate_capability
from nexora.evidence import EvidenceError, EvidenceLedger
from nexora.family_evaluation import FamilyEvaluationError, _catalogue


class MaturityReportError(ValueError):
    """Raised when a maturity report cannot be built safely."""


def build_maturity_report(
    database: Path | None = None,
    *,
    catalog_path: Path | None = None,
    capability_id: int | None = None,
) -> dict[str, Any]:
    """Build a source-backed report without assigning invented maturity levels."""
    if capability_id is not None and (
        type(capability_id) is not int or not 1 <= capability_id <= 264
    ):
        raise MaturityReportError("capability_id_out_of_range")
    try:
        catalogue = _catalogue(catalog_path)
    except FamilyEvaluationError as exc:
        raise MaturityReportError(str(exc)) from exc
    if capability_id is not None:
        catalogue = [row for row in catalogue if row["id"] == capability_id]
        if not catalogue:
            raise MaturityReportError("capability_not_source_backed")

    ledger_path = Path(database) if database is not None else Path("data/registry.sqlite3")
    ledger_status = "NOT_FOUND"
    ledger = None
    verification = None
    if ledger_path.is_file():
        try:
            ledger = EvidenceLedger(ledger_path, readonly=True)
            verification = ledger.verify()
            ledger_status = "VALID" if verification["valid"] else "INVALID"
            if ledger_status != "VALID":
                ledger = None
        except (EvidenceError, OSError, ValueError) as exc:
            ledger_status = "INVALID"
            verification = {"valid": False, "error": type(exc).__name__}
            ledger = None

    reports = []
    for row in sorted(catalogue, key=lambda item: item["id"]):
        if ledger is None:
            evidence = {
                "assessment": (
                    "BLOCKED_LEDGER_INTEGRITY" if ledger_status == "INVALID"
                    else "NOT_EVALUATED_NO_LEDGER"
                ),
                "first_blocked_gate": None,
                "evidence_records": 0 if ledger_status == "INVALID" else None,
                "evidence_types": [],
            }
        else:
            summary = ledger.evidence_summary(row["id"])
            evidence = evaluate_capability(
                row["id"], [], ledger_valid=True,
                evidence_types=set(summary["evidence_types"]),
                evidence_record_count=summary["record_count"],
            )
        reports.append({
            "capability_id": row["id"],
            "name": row["name"],
            "family": row["family"],
            "family_name": row["family_name"],
            "source": row["source"],
            "catalogue_status": row["status"],
            "lifecycle_evidence": evidence,
            "maturity_scale": {
                "status": "UNDEFINED_SOURCE_GAP",
                "assigned_level": None,
                "reason": "Canonical L0-L4 definitions and evidence thresholds are not present.",
            },
            "regression_detection": {
                "status": "NOT_AVAILABLE_NO_TRUSTED_LIFECYCLE_HISTORY",
                "automatic_regression_action": False,
            },
            "promotion": {
                "status": "HUMAN_REVIEW_ONLY",
                "automatic_promotion": False,
                "lifecycle_mutation": False,
                "execution_enabled": False,
            },
        })

    all_ids = {row["id"] for row in _catalogue(catalog_path)}
    return {
        "scope": "source_backed_catalogue_records_only",
        "ledger": {
            "path": str(ledger_path),
            "status": ledger_status,
            "verification": verification,
        },
        "catalogue": {
            "target_capabilities": 264,
            "source_backed_capabilities": len(all_ids),
            "missing_source_definition_ids": sorted(set(range(1, 265)) - all_ids),
        },
        "maturity_scale": {
            "name": "L0-L4",
            "status": "UNDEFINED_SOURCE_GAP",
            "levels_assigned": False,
            "criteria_invented": False,
        },
        "capabilities": reports,
        "lifecycle_changed": False,
        "capability_promotions_performed": False,
        "policy_mutation_enabled": False,
        "execution_enabled": False,
    }
