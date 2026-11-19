"""Read-only inspection of self-family proposals and human review history."""
from __future__ import annotations

import json
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

PROPOSAL_ID = re.compile(r"^[0-9a-f]{24}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DECISIONS = {"SUBMITTED", "REVIEWED", "REJECTED"}


class ProposalReadError(ValueError):
    """Raised when the local proposal store cannot be safely inspected."""


def read_proposals(
    database: Path,
    *,
    proposal_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Read proposal records with SQLite read-only mode; never initialize storage.

    Review labels are operator-declared workflow metadata, not signed approvals,
    lifecycle authorization, or permission to execute a proposal.
    """
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ProposalReadError("proposal_list_limit_out_of_range")
    if proposal_id is not None and (
        not isinstance(proposal_id, str) or not PROPOSAL_ID.fullmatch(proposal_id)
    ):
        raise ProposalReadError("proposal_id_invalid")

    path = Path(database)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {
            "status": "NOT_CONFIGURED",
            "database": str(path),
            "count": 0,
            "proposals": [],
            "read_only": True,
            "execution_enabled": False,
        }
    except OSError as exc:
        raise ProposalReadError("proposal_database_unreadable") from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise ProposalReadError("proposal_database_symlink_refused")
    if not stat.S_ISREG(metadata.st_mode):
        raise ProposalReadError("proposal_database_not_a_regular_file")

    connection = None
    try:
        connection = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro",
            uri=True,
            timeout=3,
        )
        connection.row_factory = sqlite3.Row
        integrity = connection.execute("PRAGMA quick_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise ProposalReadError("proposal_database_integrity_failed")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {"self_family_proposals", "self_family_review_events"}
        if not required.issubset(tables):
            return {
                "status": "SCHEMA_UNAVAILABLE",
                "database": str(path),
                "count": 0,
                "proposals": [],
                "read_only": True,
                "execution_enabled": False,
            }

        if proposal_id is None:
            rows = connection.execute(
                "SELECT proposal_id,family,summary,evidence_json,payload_sha256,"
                "execution,created_at FROM self_family_proposals "
                "ORDER BY created_at DESC,proposal_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT proposal_id,family,summary,evidence_json,payload_sha256,"
                "execution,created_at FROM self_family_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchall()

        proposals: list[dict[str, Any]] = []
        for row in rows:
            try:
                evidence = json.loads(row["evidence_json"])
            except (json.JSONDecodeError, TypeError) as exc:
                raise ProposalReadError("proposal_evidence_json_invalid") from exc
            if (
                not isinstance(evidence, list)
                or any(not isinstance(item, str) for item in evidence)
            ):
                raise ProposalReadError("proposal_evidence_schema_invalid")
            if not DIGEST.fullmatch(str(row["payload_sha256"])):
                raise ProposalReadError("proposal_digest_schema_invalid")
            if row["execution"] != "DISABLED":
                raise ProposalReadError("proposal_execution_invariant_broken")

            events = connection.execute(
                "SELECT event_id,decision,operator_label,evidence_json,note,created_at "
                "FROM self_family_review_events WHERE proposal_id=? ORDER BY event_id",
                (row["proposal_id"],),
            ).fetchall()
            history = []
            for event in events:
                if event["decision"] not in DECISIONS:
                    raise ProposalReadError("proposal_review_decision_invalid")
                try:
                    review_evidence = json.loads(event["evidence_json"])
                except (json.JSONDecodeError, TypeError) as exc:
                    raise ProposalReadError("proposal_review_evidence_invalid") from exc
                if (
                    not isinstance(review_evidence, list)
                    or any(not isinstance(item, str) for item in review_evidence)
                ):
                    raise ProposalReadError("proposal_review_evidence_schema_invalid")
                history.append({
                    "event_id": event["event_id"],
                    "decision": event["decision"],
                    "operator_label": event["operator_label"],
                    "evidence": review_evidence,
                    "note": event["note"],
                    "created_at": event["created_at"],
                })

            latest = history[-1]["decision"] if history else "UNKNOWN"
            if latest not in {"SUBMITTED", "REVIEWED", "REJECTED"}:
                raise ProposalReadError("proposal_review_state_invalid")
            from nexora.proposal_review import (
                ProposalReviewError,
                read_signed_proposal_review,
            )
            try:
                signed_review = read_signed_proposal_review(connection, row)
            except ProposalReviewError as exc:
                raise ProposalReadError(str(exc)) from exc

            proposals.append({
                "proposal_id": row["proposal_id"],
                "family": row["family"],
                "summary": row["summary"],
                "evidence": evidence,
                "payload_sha256": row["payload_sha256"],
                "payload_digest_status": "RECORDED_NOT_RECOMPUTED",
                "created_at": row["created_at"],
                "review_state": latest,
                "review_history": history,
                "signed_review": signed_review,
                "execution": "DISABLED",
                "authorization": "NOT_GRANTED",
            })
    except ProposalReadError:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        raise ProposalReadError("proposal_database_read_failed") from exc
    finally:
        if connection is not None:
            connection.close()

    return {
        "status": "VALID",
        "database": str(path),
        "count": len(proposals),
        "proposals": proposals,
        "read_only": True,
        "execution_enabled": False,
        "approval_authorization_granted": False,
        "note": (
            "REVIEWED is an operator-recorded review label only. It is not a "
            "cryptographic approval, lifecycle transition, or execution grant."
        ),
    }
