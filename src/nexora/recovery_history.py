"""Persistent, independently witnessed recovery simulation history.

Simulation records contain metadata only: no database contents or absolute paths.
A record is trusted only when its SHA-256 is present in the verified Ed25519
witness chain. An interrupted write therefore fails closed rather than appearing
as a completed simulation.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexora.backup import BackupError
from nexora.file_lock import exclusive_file_lock
from nexora.oversight.witness import (
    IndependentWitness,
    WitnessVerificationError,
    verify_witness_chain,
)
from nexora.recovery_planner import RecoveryPlanningError, simulate_recovery


class RecoveryHistoryError(RuntimeError):
    """Raised when recovery history cannot be safely recorded or verified."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def record_recovery_simulation(
    backup: Path,
    *,
    backup_trusted_key: Path,
    witness_private_key: Path,
    witness_receipt_log: Path,
    history_log: Path,
    audit_log: Path | None = None,
) -> dict[str, Any]:
    """Run an explicitly approved isolated simulation and persist its signed evidence."""
    try:
        result = simulate_recovery(
            Path(backup), trusted_public_key=Path(backup_trusted_key), confirm=True,
        )
        if result.get("simulation") != "PASSED" or result.get("temporary_output_removed") is not True:
            raise RecoveryHistoryError("simulation_did_not_complete_with_cleanup")
        event = {
            "schema_version": 1,
            "simulation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "PASSED",
            "backup_name": Path(backup).name,
            "backup_sha256": result["verified_sha256"],
            "sqlite_integrity": result["integrity"],
            "user_version": result["user_version"],
            "table_count": result["table_count"],
            "temporary_output_removed": True,
            "live_database_touched": False,
            "persistent_restore_created": False,
        }
        event_hash = _digest(event)
        history_path = Path(history_log)
        receipt_path = Path(witness_receipt_log)
        lock_paths = (
            history_path.with_name(history_path.name + ".lock"),
            receipt_path.with_name(receipt_path.name + ".lock"),
        )
        if any(path.is_symlink() for path in (history_path, receipt_path, *lock_paths)):
            raise RecoveryHistoryError("history_or_receipt_log_symlink_refused")
        # A single append write prevents interleaving. The witness chain is the
        # authority; unreceipted history rows are ignored by the reader.
        with exclusive_file_lock(history_path.with_name(history_path.name + ".lock")):
            history_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(history_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                payload = _canonical({"event": event, "event_hash": event_hash}) + bytes([10])
                with os.fdopen(fd, "ab", closefd=True) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                fd = -1
            finally:
                if fd >= 0:
                    os.close(fd)
        receipt = IndependentWitness(receipt_path, Path(witness_private_key)).attest(
            event_hash, "recovery_simulation",
        )
        audit_recorded = False
        if audit_log is not None:
            from nexora.oversight import AuditLog
            AuditLog(Path(audit_log)).append("recovery.simulation.passed", {
                "simulation_id": event["simulation_id"],
                "event_hash": event_hash,
                "backup_sha256": event["backup_sha256"],
                "witness_sequence": receipt["payload"]["sequence"],
            })
            audit_recorded = True
        return {
            "recorded": True,
            "event": event,
            "event_hash": event_hash,
            "witness_sequence": receipt["payload"]["sequence"],
            "audit_recorded": audit_recorded,
            "history_log": str(history_path),
            "witness_receipt_log": str(receipt_path),
        }
    except (OSError, ValueError, KeyError, TypeError, BackupError, RecoveryPlanningError, WitnessVerificationError) as exc:
        raise RecoveryHistoryError(f"recovery_simulation_recording_failed:{type(exc).__name__}") from exc


def read_recovery_history(
    history_log: Path,
    witness_receipt_log: Path,
    *,
    trusted_witness_public_key: Path,
    limit: int = 50,
) -> dict[str, Any]:
    """Return only history events authenticated by a complete trusted receipt chain."""
    if type(limit) is not int or not 1 <= limit <= 500:
        raise RecoveryHistoryError("history_limit_out_of_range")
    history_path, receipt_path = Path(history_log), Path(witness_receipt_log)
    history_lock = history_path.with_name(history_path.name + ".lock")
    receipt_lock = receipt_path.with_name(receipt_path.name + ".lock")
    if any(path.is_symlink() for path in (history_path, receipt_path, history_lock, receipt_lock)):
        raise RecoveryHistoryError("history_or_receipt_log_symlink_refused")
    try:
        chain = verify_witness_chain(receipt_path, Path(trusted_witness_public_key))
        trusted_hashes: set[str] = set()
        with receipt_path.open(encoding="utf-8") as stream:
            for line in stream:
                receipt = json.loads(line)
                if receipt["payload"].get("event_type") == "recovery_simulation":
                    trusted_hashes.add(receipt["payload"]["event_hash"])
        events = []
        if history_path.is_file():
            with (
                exclusive_file_lock(history_path.with_name(history_path.name + ".lock")),
                history_path.open(encoding="utf-8") as stream,
            ):
                for number, line in enumerate(stream, 1):
                    row = json.loads(line)
                    event = row.get("event")
                    event_hash = row.get("event_hash")
                    if not isinstance(event, dict) or _digest(event) != event_hash:
                        raise RecoveryHistoryError(f"history_record_integrity_invalid:{number}")
                    if event_hash in trusted_hashes:
                            events.append(event)
        events.sort(key=lambda item: (item.get("timestamp", ""), item.get("simulation_id", "")), reverse=True)
        return {
            "valid": True,
            "trusted_receipt_chain": chain,
            "record_count": len(events),
            "events": events[:limit],
            "unwitnessed_records_excluded": True,
            "read_only": True,
        }
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, WitnessVerificationError) as exc:
        if isinstance(exc, RecoveryHistoryError):
            raise
        raise RecoveryHistoryError(f"recovery_history_verification_failed:{type(exc).__name__}") from exc


__all__ = ["RecoveryHistoryError", "read_recovery_history", "record_recovery_simulation"]
