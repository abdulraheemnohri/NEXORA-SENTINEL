"""Read-only structural lifecycle history and regression diagnostics.

Legacy lifecycle events are append-only at the SQLite trigger layer but are not
cryptographically hash-chained. This module deliberately reports that limitation.
It never initializes a database, changes state, or authorizes execution.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from nexora.lifecycle import LIFECYCLE


class LifecycleHistoryError(RuntimeError):
    """Raised when the lifecycle database cannot be safely inspected."""


def _readonly(database: Path) -> sqlite3.Connection:
    path = Path(database)
    if not path.is_file():
        raise LifecycleHistoryError("registry_database_not_found")
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def build_lifecycle_history(database: Path, capability_id: int | None = None) -> dict:
    """Replay append-only lifecycle rows and report structural inconsistencies."""
    if capability_id is not None and (
        type(capability_id) is not int or not 1 <= capability_id <= 264
    ):
        raise LifecycleHistoryError("capability_id_out_of_range")
    try:
        with _readonly(database) as db:
            tables = {row["name"] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            required = {"capabilities", "lifecycle_events", "revocation_events", "rollback_events"}
            if not required.issubset(tables):
                raise LifecycleHistoryError("registry_schema_incomplete")
            caps_sql = "SELECT * FROM capabilities"
            event_sql = "SELECT * FROM lifecycle_events"
            rev_sql = "SELECT capability_id,event_id,created_at FROM revocation_events"
            rollback_sql = "SELECT capability_id,event_id,created_at FROM rollback_events"
            params: tuple = ()
            if capability_id is not None:
                caps_sql += " WHERE capability_id=?"
                event_sql += " WHERE capability_id=?"
                rev_sql += " WHERE capability_id=?"
                rollback_sql += " WHERE capability_id=?"
                params = (capability_id,)
            capabilities = [dict(row) for row in db.execute(caps_sql, params)]
            events = [dict(row) for row in db.execute(event_sql + " ORDER BY event_id", params)]
            revocations = [dict(row) for row in db.execute(rev_sql + " ORDER BY event_id", params)]
            rollbacks = [dict(row) for row in db.execute(rollback_sql + " ORDER BY event_id", params)]
    except sqlite3.Error as exc:
        raise LifecycleHistoryError("registry_read_failed_closed") from exc

    by_cap: dict[int, list[dict]] = {}
    for event in events:
        by_cap.setdefault(event["capability_id"], []).append(event)
    rev_by_cap: dict[int, list[dict]] = {}
    for event in revocations:
        rev_by_cap.setdefault(event["capability_id"], []).append(event)
    rollback_by_cap: dict[int, list[dict]] = {}
    for event in rollbacks:
        rollback_by_cap.setdefault(event["capability_id"], []).append(event)

    records = []
    regressions = []
    for cap in capabilities:
        cid = cap["capability_id"]
        rows = by_cap.get(cid, [])
        issues = []
        replay_state = None
        expected_index = 0
        for row in rows:
            previous = row["previous_state"]
            requested = row["requested_state"]
            if expected_index == 0:
                if previous is not None or requested != "SPECIFIED":
                    issues.append({"code": "INITIAL_EVENT_INVALID", "event_id": row["event_id"]})
                replay_state = requested
                expected_index = 1
                continue
            if previous != replay_state:
                issues.append({"code": "PREVIOUS_STATE_MISMATCH", "event_id": row["event_id"]})
            if replay_state not in LIFECYCLE or requested not in LIFECYCLE:
                issues.append({"code": "UNKNOWN_LIFECYCLE_STATE", "event_id": row["event_id"]})
            elif LIFECYCLE.index(requested) != LIFECYCLE.index(replay_state) + 1:
                issues.append({"code": "NON_SEQUENTIAL_TRANSITION", "event_id": row["event_id"]})
            replay_state = requested
        if not rows:
            issues.append({"code": "LIFECYCLE_HISTORY_MISSING"})
        elif replay_state != cap["state"]:
            issues.append({"code": "CURRENT_STATE_DOES_NOT_MATCH_HISTORY"})
        rev_count = len(rev_by_cap.get(cid, []))
        if cap.get("control_state") == "REVOKED" and rev_count == 0:
            issues.append({"code": "REVOKED_WITHOUT_REVOCATION_EVENT"})
        if cap.get("control_state") == "ACTIVE" and rev_count:
            issues.append({"code": "REVOCATION_EVENT_WITH_ACTIVE_CONTROL_STATE"})
        if rev_count > 1:
            issues.append({"code": "MULTIPLE_REVOCATION_EVENTS"})
        for issue in issues:
            regressions.append({"capability_id": cid, **issue})
        records.append({
            "capability_id": cid,
            "name": cap["name"],
            "family": cap["family"],
            "state": cap["state"],
            "control_state": cap.get("control_state", "UNKNOWN"),
            "lifecycle_event_count": len(rows),
            "revocation_event_count": rev_count,
            "rollback_event_count": len(rollback_by_cap.get(cid, [])),
            "replayed_state": replay_state,
            "structurally_consistent": not issues,
            "issues": issues,
            "events": rows,
        })

    return {
        "status": "STRUCTURALLY_CONSISTENT" if not regressions else "REGRESSION_DETECTED",
        "capability_count": len(records),
        "lifecycle_event_count": len(events),
        "revocation_event_count": len(revocations),
        "rollback_event_count": len(rollbacks),
        "regression_count": len(regressions),
        "regressions": regressions,
        "capabilities": records,
        "integrity": {
            "append_only_triggers": "PRESENT_IN_SCHEMA",
            "cryptographic_hash_chain": "NOT_IMPLEMENTED_FOR_LEGACY_LIFECYCLE_EVENTS",
            "history_authenticity": "UNVERIFIED",
            "assessment": "Structural replay detects inconsistencies but cannot prove records were not rewritten outside SQLite triggers.",
        },
        "read_only": True,
        "authorization_granted": False,
        "lifecycle_changed": False,
        "execution_enabled": False,
        "automatic_repair": False,
    }
