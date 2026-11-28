"""Authoritative fail-closed oversight implementation.

Kept separate from the public oversight package namespace to preserve the
legacy import API while exposing modular submodules.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nexora.file_lock import exclusive_file_lock, open_regular_file

GENESIS = "0" * 64


class KillSwitch:
    def __init__(self, marker: Path):
        self.marker = Path(marker)

    def is_engaged(self) -> bool:
        """Treat every marker-inspection failure except a missing path as engaged.

        Path.exists() follows symlinks and can report a dangling kill-marker
        symlink as absent. lstat() observes the marker itself, and errors other
        than FileNotFoundError fail closed rather than authorizing work.
        """
        try:
            self.marker.lstat()
        except FileNotFoundError:
            return False
        except (OSError, ValueError):
            return True
        return True

    def _transition_lock(self):
        return self.marker.with_name(self.marker.name + ".transition.lock")

    def _engage_unlocked(self, reason: str = "operator") -> None:
        self.marker.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".KILL.", dir=self.marker.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write((reason.strip() or "operator")[:256] + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.marker)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _clear_unlocked(self) -> None:
        self.marker.unlink(missing_ok=True)

    def engage(self, reason: str = "operator") -> None:
        with exclusive_file_lock(self._transition_lock()):
            self._engage_unlocked(reason)

    def clear(self) -> None:
        with exclusive_file_lock(self._transition_lock()):
            self._clear_unlocked()

    def engage_and_record(
        self, audit_log: Any, reason: str = "operator", payload: dict | None = None
    ) -> None:
        """Engage first, then record while excluding concurrent kill/resume transitions."""
        with exclusive_file_lock(self._transition_lock()):
            self._engage_unlocked(reason)
            audit_log.append(
                "kill.engaged",
                payload if payload is not None else {"source": "operator"},
            )

    def clear_and_record(self, audit_log: Any, payload: dict | None = None) -> None:
        """Record the clear decision before removing the marker, under the same lock."""
        with exclusive_file_lock(self._transition_lock()):
            audit_log.append(
                "kill.cleared",
                payload if payload is not None else {"human_initiated": True},
            )
            self._clear_unlocked()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = open_regular_file(
            self.path, os.O_CREAT | os.O_RDWR, 0o600
        )
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_entries(stream) -> list[dict]:
        result = []
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Corrupt audit line {number}") from exc
                if not isinstance(item, dict):
                    raise ValueError(f"Invalid audit line {number}")
                result.append(item)
        return result

    @staticmethod
    def _verify_entries(rows: list[dict]) -> bool:
        previous = GENESIS
        for sequence, item in enumerate(rows, 1):
            body = {key: value for key, value in item.items() if key != "hash"}
            expected = hashlib.sha256(
                (previous + canonical(body)).encode()
            ).hexdigest()
            if (
                item.get("sequence") != sequence
                or item.get("previous_hash") != previous
                or item.get("hash") != expected
            ):
                return False
            previous = expected
        return True

    def entries(self) -> list[dict]:
        descriptor = open_regular_file(self.path, os.O_RDONLY)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            return self._read_entries(stream)

    def verify(self) -> bool:
        try:
            return self._verify_entries(self.entries())
        except (OSError, ValueError, TypeError):
            return False

    def append(self, event: str, payload: dict) -> dict:
        # Keep verification, sequence allocation and append on one checked
        # descriptor so a path swap cannot redirect the write after validation.
        lock_path = self.path.with_name(self.path.name + ".lock")
        with exclusive_file_lock(lock_path):
            descriptor = open_regular_file(
                self.path, os.O_RDWR | os.O_APPEND
            )
            with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
                try:
                    stream.seek(0)
                    rows = self._read_entries(stream)
                    if not self._verify_entries(rows):
                        raise RuntimeError("Audit integrity failure; append refused")
                except RuntimeError:
                    raise
                except (OSError, ValueError, TypeError) as exc:
                    raise RuntimeError(
                        "Audit integrity failure; append refused"
                    ) from exc
                previous = rows[-1]["hash"] if rows else GENESIS
                body = {
                    "sequence": len(rows) + 1,
                    "event": event,
                    "payload": payload,
                    "previous_hash": previous,
                }
                record = {
                    **body,
                    "hash": hashlib.sha256(
                        (previous + canonical(body)).encode()
                    ).hexdigest(),
                }
                stream.seek(0, os.SEEK_END)
                stream.write(canonical(record) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return record


class Witness:
    """Separate local receipt stream; not a remote or hardware trust anchor."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = open_regular_file(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def attest(self, event_hash: str, event_type: str) -> dict:
        if not isinstance(event_hash, str) or len(event_hash) != 64 or any(
            char not in "0123456789abcdef" for char in event_hash
        ):
            raise ValueError("Expected lowercase SHA-256 digest")
        if not isinstance(event_type, str):
            raise TypeError("Expected string event type")
        body = {"event_hash": event_hash, "event_type": event_type}
        receipt = {
            **body,
            "witness_hash": hashlib.sha256(canonical(body).encode()).hexdigest(),
        }
        lock_path = self.path.with_name(self.path.name + ".lock")
        with exclusive_file_lock(lock_path):
            descriptor = open_regular_file(self.path, os.O_WRONLY | os.O_APPEND)
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                stream.write(canonical(receipt) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        return receipt


@dataclass(frozen=True)
class Decision:
    action: str
    allowed: bool
    reason: str
    autonomy_level: str = "L0"

    def to_dict(self):
        return asdict(self)


IMMUTABLE_SAFETY_BASELINE = (
    "safety_precedes_all_other_priorities", "unknown_actions_are_denied",
    "proposal_is_not_mutation", "privilege_expansion_requires_human_approval",
    "high_and_critical_risk_require_human_approval", "kill_switch_blocks_all_actions",
    "audit_integrity_failure_blocks_actions", "autonomy_defaults_to_l0",
    "generated_code_requires_sandbox", "every_decision_is_observable",
)


class PolicyKernel:
    def __init__(self, kill: KillSwitch):
        self.kill = kill
        self.registered = {
            "system.status": "low", "audit.verify": "low",
            "filesystem.read": "medium",
        }

    def register_action(self, *_):
        raise PermissionError("Runtime policy mutation disabled")

    def evaluate(self, action: str, risk: str, human_approved: bool = False) -> Decision:
        if self.kill.is_engaged():
            return Decision(action, False, "kill_switch_engaged")
        if action not in self.registered:
            return Decision(action, False, "unknown_action_denied")
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if risk not in levels:
            return Decision(action, False, "invalid_risk_denied")
        if levels[risk] > levels[self.registered[action]]:
            return Decision(action, False, "risk_exceeds_registration")
        if risk != "low" and not human_approved:
            return Decision(action, False, "explicit_approval_required")
        return Decision(action, True, "approved_by_v0_1_baseline")
