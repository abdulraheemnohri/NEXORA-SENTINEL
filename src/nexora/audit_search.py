"""Read-only, hash-chain-verified audit log search."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from nexora._oversight_impl import GENESIS, canonical


class AuditSearchError(ValueError):
    """Raised when an audit log or search request cannot be trusted."""


def _validate_filters(
    *,
    event: str | None,
    contains: str | None,
    from_sequence: int | None,
    to_sequence: int | None,
    limit: int,
) -> None:
    if event is not None and (
        not isinstance(event, str) or not event.strip() or len(event) > 256
    ):
        raise AuditSearchError("audit_search_event_filter_invalid")
    if contains is not None and (
        not isinstance(contains, str) or not contains.strip() or len(contains) > 1024
    ):
        raise AuditSearchError("audit_search_contains_filter_invalid")
    for name, value in (
        ("from_sequence", from_sequence),
        ("to_sequence", to_sequence),
    ):
        if value is not None and (type(value) is not int or value < 1):
            raise AuditSearchError(f"audit_search_{name}_invalid")
    if (
        from_sequence is not None
        and to_sequence is not None
        and from_sequence > to_sequence
    ):
        raise AuditSearchError("audit_search_sequence_range_invalid")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise AuditSearchError("audit_search_limit_out_of_range")


def search_audit_log(
    path: Path,
    *,
    event: str | None = None,
    contains: str | None = None,
    from_sequence: int | None = None,
    to_sequence: int | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Verify the complete append-only hash chain before returning filtered rows.

    Missing logs are reported as NOT_CONFIGURED without creating directories or
    files. Invalid, symlinked, or non-regular files never return partial results.
    """
    _validate_filters(
        event=event,
        contains=contains,
        from_sequence=from_sequence,
        to_sequence=to_sequence,
        limit=limit,
    )
    source = Path(path)
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        return {
            "status": "NOT_CONFIGURED",
            "valid": None,
            "path": str(source),
            "entries_verified": 0,
            "matched_entries": 0,
            "results": [],
            "filters": {
                "event": event,
                "contains": contains,
                "from_sequence": from_sequence,
                "to_sequence": to_sequence,
            },
            "limit": limit,
            "truncated": False,
            "read_only": True,
            "execution_enabled": False,
        }
    except OSError as exc:
        raise AuditSearchError("audit_log_unreadable") from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise AuditSearchError("audit_log_symlink_refused")
    if not stat.S_ISREG(metadata.st_mode):
        raise AuditSearchError("audit_log_not_a_regular_file")

    previous = GENESIS
    verified_count = 0
    matched_count = 0
    results: list[dict[str, Any]] = []
    search_text = contains.casefold() if contains is not None else None

    try:
        with source.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                if len(line) > 1_000_000:
                    raise AuditSearchError(f"audit_record_too_large:{line_number}")
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditSearchError(f"audit_log_invalid_json:{line_number}") from exc
                if not isinstance(record, dict):
                    raise AuditSearchError(f"audit_record_not_object:{line_number}")

                body = {key: value for key, value in record.items() if key != "hash"}
                expected = hashlib.sha256(
                    (previous + canonical(body)).encode("utf-8")
                ).hexdigest()
                if (
                    record.get("previous_hash") != previous
                    or record.get("hash") != expected
                    or record.get("sequence") != verified_count + 1
                ):
                    raise AuditSearchError(f"audit_chain_integrity_failed:{line_number}")

                verified_count += 1
                previous = expected

                sequence = record["sequence"]
                if from_sequence is not None and sequence < from_sequence:
                    continue
                if to_sequence is not None and sequence > to_sequence:
                    continue
                if event is not None and record.get("event") != event:
                    continue
                if search_text is not None and search_text not in canonical(record).casefold():
                    continue

                matched_count += 1
                if len(results) < limit:
                    results.append(record)
    except AuditSearchError:
        raise
    except (OSError, UnicodeError) as exc:
        raise AuditSearchError("audit_log_unreadable") from exc

    return {
        "status": "VALID",
        "valid": True,
        "path": str(source),
        "entries_verified": verified_count,
        "matched_entries": matched_count,
        "results": results,
        "filters": {
            "event": event,
            "contains": contains,
            "from_sequence": from_sequence,
            "to_sequence": to_sequence,
        },
        "limit": limit,
        "truncated": matched_count > len(results),
        "head_hash": previous,
        "read_only": True,
        "execution_enabled": False,
    }
