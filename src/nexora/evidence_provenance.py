"""Read-only evidence provenance inventory.

Source URI, revision and collection time are operator-supplied declarations.
They are not independently authenticated or fetched by this module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nexora.evidence import EvidenceError, EvidenceLedger


def build_provenance_report(
    database: Path, *, capability_id: int | None = None, limit: int = 500,
) -> dict[str, Any]:
    if capability_id is not None and (
        type(capability_id) is not int or not 1 <= capability_id <= 264
    ):
        raise EvidenceError("capability_id_out_of_range")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise EvidenceError("limit_out_of_range")
    ledger = EvidenceLedger(Path(database), readonly=True)
    integrity = ledger.verify()
    records = ledger.list(capability_id=capability_id, limit=limit)
    with ledger._connect() as db:
        if capability_id is None:
            total = db.execute("SELECT COUNT(*) FROM capability_evidence").fetchone()[0]
        else:
            total = db.execute(
                "SELECT COUNT(*) FROM capability_evidence WHERE capability_id=?",
                (capability_id,),
            ).fetchone()[0]
    counts = {
        "DECLARED_COMPLETE": 0,
        "DECLARED_PARTIAL": 0,
        "UNDECLARED": 0,
        "UNVERIFIED": 0,
    }
    result: list[dict[str, Any]] = []
    for row in reversed(records):
        uri = row.get("source_uri")
        revision = row.get("source_revision")
        collected_at = row.get("collected_at")
        if not integrity["valid"]:
            status = "UNVERIFIED"
            reason = "ledger_chain_integrity_failed"
        elif uri and revision:
            status = "DECLARED_COMPLETE"
            reason = "source_uri_and_revision_operator_declared"
        elif uri or revision or collected_at:
            status = "DECLARED_PARTIAL"
            reason = "source_provenance_fields_incomplete"
        else:
            status = "UNDECLARED"
            reason = "no_source_provenance_declared"
        counts[status] += 1
        result.append({
            "sequence": row["sequence"],
            "capability_id": row["capability_id"],
            "evidence_type": row["evidence_type"],
            "reference": row["reference"],
            "artifact_sha256": row["artifact_sha256"],
            "source_uri": uri,
            "source_revision": revision,
            "collected_at": collected_at,
            "operator": row["operator"],
            "status": status,
            "reason": reason,
        })
    return {
        "status": "LEDGER_INTEGRITY_FAILED" if not integrity["valid"] else (
            "DISPLAY_LIMIT_REACHED" if total > len(result) else "REPORTED"
        ),
        "read_only": True,
        "ledger_integrity": integrity,
        "capability_id": capability_id,
        "total_records": total,
        "reported_records": len(result),
        "complete": total == len(result),
        "counts": counts,
        "records": result,
        "policy_note": (
            "Source URI, revision and collection time are operator declarations. "
            "NEXORA does not fetch sources, prove authorship, authenticate revision "
            "history, or determine whether source content changed. UNDECLARED is not "
            "evidence of invalidity; DECLARED_COMPLETE is not independent verification."
        ),
    }
