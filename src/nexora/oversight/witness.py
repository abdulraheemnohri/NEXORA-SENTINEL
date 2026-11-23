"""Cryptographically signed independent witness receipts.

Use a separately enrolled key and retain its public key outside the backup location.
This remains a local witness process unless the signing key is held by an independent host.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexora.backup import _fingerprint, _load_private, _load_public
from nexora.file_lock import exclusive_file_lock, open_regular_file


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _receipt_hash(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(receipt)).hexdigest()


class WitnessVerificationError(RuntimeError):
    """Raised when a witness chain cannot be independently verified."""


def _verify_witness_stream(
    stream,
    public: Ed25519PublicKey,
    *,
    collect_event_type: str | None = None,
) -> dict[str, Any]:
    """Verify a witness stream already opened through a checked file descriptor."""
    fingerprint = _fingerprint(public)
    previous = "0" * 64
    count = 0
    payload: dict[str, Any] = {}
    event_hashes: set[str] = set()
    try:
        stream.seek(0)
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                receipt = json.loads(line)
                payload = receipt["payload"]
                signature = base64.b64decode(receipt["signature"], validate=True)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise WitnessVerificationError(f"receipt_format_invalid:{line_number}") from exc
            if not isinstance(payload, dict):
                raise WitnessVerificationError(f"receipt_payload_invalid:{line_number}")
            if payload.get("sequence") != count + 1:
                raise WitnessVerificationError(f"receipt_sequence_invalid:{line_number}")
            if payload.get("previous_receipt_hash") != previous:
                raise WitnessVerificationError(f"receipt_chain_invalid:{line_number}")
            if payload.get("signer_fingerprint") != fingerprint:
                raise WitnessVerificationError(f"receipt_signer_untrusted:{line_number}")
            try:
                public.verify(signature, _canonical(payload))
            except Exception as exc:
                raise WitnessVerificationError(f"receipt_signature_invalid:{line_number}") from exc
            if collect_event_type is not None and payload.get("event_type") == collect_event_type:
                event_hash = payload.get("event_hash")
                if isinstance(event_hash, str):
                    event_hashes.add(event_hash)
            previous = _receipt_hash(receipt)
            count += 1
    except (OSError, UnicodeError) as exc:
        raise WitnessVerificationError("witness_log_unreadable") from exc
    report = {
        "valid": True,
        "count": count,
        "last_receipt_hash": previous,
        "signer_fingerprint": fingerprint,
        "last_event_hash": payload.get("event_hash") if count else None,
        "last_event_type": payload.get("event_type") if count else None,
    }
    if collect_event_type is not None:
        report["_event_hashes"] = event_hashes
    return report


def _verify_witness_chain(path: Path, public: Ed25519PublicKey) -> dict[str, Any]:
    """Open and verify a witness path without following a symlink."""
    try:
        descriptor = open_regular_file(Path(path), os.O_RDONLY)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            return _verify_witness_stream(stream, public)
    except WitnessVerificationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise WitnessVerificationError("witness_log_unreadable") from exc


def verify_witness_chain_event_hashes(
    path: Path,
    trusted_public_key: Ed25519PublicKey | Path,
    *,
    event_type: str,
) -> tuple[dict[str, Any], frozenset[str]]:
    """Verify a witness chain and collect one event type from the same locked read.

    The returned event hashes are derived only from receipts whose sequence,
    predecessor hash, signer fingerprint and Ed25519 signature were verified.
    Keeping verification and extraction in one descriptor pass avoids a
    verify-then-reopen pathname race in evidence consumers.
    """
    if not isinstance(event_type, str) or not event_type.strip():
        raise WitnessVerificationError("event_type_required")
    path = Path(path)
    public = _load_public(trusted_public_key)
    lock_path = path.with_name(path.name + ".lock")
    with exclusive_file_lock(lock_path):
        try:
            descriptor = open_regular_file(path, os.O_RDONLY)
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                report = _verify_witness_stream(
                    stream, public, collect_event_type=event_type,
                )
        except WitnessVerificationError:
            raise
        except (OSError, UnicodeError) as exc:
            raise WitnessVerificationError("witness_log_unreadable") from exc
    event_hashes = report.pop("_event_hashes", set())
    return report, frozenset(event_hashes)


class IndependentWitness:
    """Append-only signed witness receipt stream, separate from the backup signer."""

    def __init__(self, path: Path, signing_key: Ed25519PrivateKey | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = _load_private(signing_key)
        descriptor = open_regular_file(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def attest(self, event_hash: str, event_type: str) -> dict[str, Any]:
        if not isinstance(event_hash, str) or len(event_hash) != 64 or any(
            char not in "0123456789abcdef" for char in event_hash
        ):
            raise WitnessVerificationError("event_hash_must_be_sha256")
        if not isinstance(event_type, str) or not event_type.strip():
            raise WitnessVerificationError("event_type_required")

        # The lock covers verification, sequence allocation, signing and durable append.
        # Read and write use the same checked descriptor; the path is never reopened.
        lock_path = self.path.with_name(self.path.name + ".lock")
        with exclusive_file_lock(lock_path):
            descriptor = open_regular_file(self.path, os.O_RDWR)
            with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
                previous = "0" * 64
                sequence = 1
                if os.fstat(stream.fileno()).st_size:
                    verified = _verify_witness_stream(stream, self.signing_key.public_key())
                    previous = verified["last_receipt_hash"]
                    sequence = verified["count"] + 1
                payload = {
                    "sequence": sequence,
                    "event_hash": event_hash,
                    "event_type": event_type.strip()[:128],
                    "timestamp": int(time.time()),
                    "previous_receipt_hash": previous,
                    "signer_fingerprint": _fingerprint(self.signing_key.public_key()),
                }
                receipt = {
                    "payload": payload,
                    "signature": base64.b64encode(
                        self.signing_key.sign(_canonical(payload))
                    ).decode("ascii"),
                }
                stream.seek(0, os.SEEK_END)
                stream.write(_canonical(receipt).decode("utf-8") + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return receipt


def verify_witness_chain(
    path: Path, trusted_public_key: Ed25519PublicKey | Path,
) -> dict[str, Any]:
    """Verify every signed receipt and the complete sequence/hash linkage."""
    path = Path(path)
    public = _load_public(trusted_public_key)
    lock_path = path.with_name(path.name + ".lock")
    with exclusive_file_lock(lock_path):
        return _verify_witness_chain(path, public)


__all__ = [
    "IndependentWitness",
    "WitnessVerificationError",
    "verify_witness_chain",
    "verify_witness_chain_event_hashes",
]
