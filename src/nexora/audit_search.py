"""Read-only search over the existing hash-chained audit JSONL log."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from nexora.file_lock import UnsafeFilePathError, open_regular_file


class AuditSearchError(ValueError):
    """Raised when audit search filters are invalid or the log is not trustworthy."""


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def search_audit_log(
    path: Path,
    *,
    event: str | None = None,
    contains: str | None = None,
    from_sequence: int | None = None,
    to_sequence: int | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Verify the entire log before returning a filtered, bounded result set."""
    if event is not None and (
        not isinstance(event, str) or not event.strip() or len(event) > 128
    ):
        raise AuditSearchError("event_filter_invalid")
    if contains is not None and (
        not isinstance(contains, str) or len(contains) > 256
    ):
        raise AuditSearchError("contains_filter_invalid")
    if from_sequence is not None and (
        type(from_sequence) is not int or from_sequence < 1
    ):
        raise AuditSearchError("from_sequence_must_be_positive")
    if to_sequence is not None and (
        type(to_sequence) is not int or to_sequence < 1
    ):
        raise AuditSearchError("to_sequence_must_be_positive")
    if (
        from_sequence is not None
        and to_sequence is not None
        and to_sequence < from_sequence
    ):
        raise AuditSearchError("sequence_range_invalid")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise AuditSearchError("limit_out_of_range")

    source = Path(path)
    try:
        descriptor = open_regular_file(source, os.O_RDONLY)
    except FileNotFoundError:
        return {
            "status": "NOT_CONFIGURED",
            "valid": None,
            "total_entries": 0,
            "matched_entries": 0,
            "results": [],
            "filters": {
                "event": event,
                "contains": contains,
                "from_sequence": from_sequence,
                "to_sequence": to_sequence,
                "limit": limit,
            },
            "read_only": True,
            "execution_enabled": False,
        }
    except UnsafeFilePathError as exc:
        raise AuditSearchError("audit_log_path_unsafe") from exc
    except OSError as exc:
        raise AuditSearchError("audit_log_unreadable") from exc

    previous = "0" * 64
    verified: list[dict[str, Any]] = []
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditSearchError(f"audit_log_invalid_json:{line_number}") from exc
                if not isinstance(row, dict):
                    raise AuditSearchError(f"audit_log_record_invalid:{line_number}")
                body = {key: value for key, value in row.items() if key != "hash"}
                expected = hashlib.sha256(
                    (previous + _canonical(body)).encode("utf-8")
                ).hexdigest()
                if row.get("sequence") != len(verified) + 1:
                    raise AuditSearchError(f"audit_log_sequence_invalid:{line_number}")
                if row.get("previous_hash") != previous or row.get("hash") != expected:
                    raise AuditSearchError(f"audit_log_hash_chain_invalid:{line_number}")
                verified.append(row)
                previous = expected
    except (OSError, UnicodeError) as exc:
        raise AuditSearchError("audit_log_unreadable") from exc

    needle = contains.casefold() if contains is not None else None
    matches = []
    for row in verified:
        sequence = row["sequence"]
        if from_sequence is not None and sequence < from_sequence:
            continue
        if to_sequence is not None and sequence > to_sequence:
            continue
        if event is not None and row.get("event") != event:
            continue
        if needle is not None and needle not in _canonical(row).casefold():
            continue
        matches.append(row)

    return {
        "status": "VALID",
        "valid": True,
        "total_entries": len(verified),
        "matched_entries": len(matches),
        "returned_entries": min(len(matches), limit),
        "results": matches[-limit:],
        "filters": {
            "event": event,
            "contains": contains,
            "from_sequence": from_sequence,
            "to_sequence": to_sequence,
            "limit": limit,
        },
        "head_hash": previous,
        "read_only": True,
        "execution_enabled": False,
        "note": "The complete log is hash-chain verified before filtering; no record is changed.",
    }
