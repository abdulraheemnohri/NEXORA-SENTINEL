"""Read-only evidence freshness intelligence.

Freshness is UNKNOWN unless an operator explicitly records a timezone-aware
expiry on the evidence record. No expiry policy is inferred from evidence type,
creation time, capability state, or external source.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexora.evidence import EvidenceError, EvidenceLedger


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone_required")
    return parsed.astimezone(UTC)


def build_freshness_report(
    database: Path,
    *,
    capability_id: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a read-only report; caller-supplied now makes boundary tests deterministic."""
    if capability_id is not None and (
        type(capability_id) is not int or not 1 <= capability_id <= 264
    ):
        raise EvidenceError("capability_id_out_of_range")
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise EvidenceError("now_must_be_timezone_aware")
    instant = instant.astimezone(UTC)
    ledger = EvidenceLedger(Path(database), readonly=True)
    integrity = ledger.verify()
    records = ledger.list(capability_id=capability_id, limit=500)
    # list() is intentionally bounded for display. Freshness must not silently
    # imply complete coverage when more than 500 records exist.
    with ledger._connect() as db:
        if capability_id is None:
            total = db.execute("SELECT COUNT(*) FROM capability_evidence").fetchone()[0]
        else:
            total = db.execute(
                "SELECT COUNT(*) FROM capability_evidence WHERE capability_id=?",
                (capability_id,),
            ).fetchone()[0]
    results: list[dict[str, Any]] = []
    counts = {"CURRENT": 0, "EXPIRED": 0, "UNKNOWN": 0, "UNVERIFIED": 0, "INVALID_METADATA": 0}
    for record in reversed(records):
        expiry = record.get("expires_at")
        if not integrity["valid"]:
            status = "UNVERIFIED"
            reason = "ledger_chain_integrity_failed"
        elif expiry is None:
            status = "UNKNOWN"
            reason = "no_operator_declared_expiry"
        else:
            try:
                boundary = _parse_timestamp(expiry)
                if instant > boundary:
                    status, reason = "EXPIRED", "operator_declared_expiry_passed"
                else:
                    status, reason = "CURRENT", "within_operator_declared_expiry"
            except (TypeError, ValueError):
                status, reason = "INVALID_METADATA", "expiry_timestamp_invalid"
        counts[status] += 1
        results.append({
            "sequence": record["sequence"],
            "capability_id": record["capability_id"],
            "evidence_type": record["evidence_type"],
            "reference": record["reference"],
            "artifact_sha256": record["artifact_sha256"],
            "operator": record["operator"],
            "created_at": record["created_at"],
            "expires_at": expiry,
            "status": status,
            "reason": reason,
        })
    return {
        "status": "LEDGER_INTEGRITY_FAILED" if not integrity["valid"] else (
            "DISPLAY_LIMIT_REACHED" if total > len(records) else "REPORTED"
        ),
        "generated_at": instant.isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "ledger_integrity": integrity,
        "capability_id": capability_id,
        "total_records": total,
        "reported_records": len(results),
        "complete": total == len(results),
        "counts": counts,
        "records": results,
        "policy_note": (
            "CURRENT and EXPIRED are based only on explicit operator-declared expiry. "
            "UNKNOWN is not evidence of validity. Missing required evidence is not inferred. "
            "No lifecycle transition, authorization, deletion, or execution is performed."
        ),
    }
