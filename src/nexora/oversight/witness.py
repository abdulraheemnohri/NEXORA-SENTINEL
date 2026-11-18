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
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexora.backup import _fingerprint, _load_private, _load_public


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _receipt_hash(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(receipt)).hexdigest()


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    """Serialize cooperating processes on POSIX and Windows using a sidecar lock file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as lock_stream:
        if os.name == "nt":
            import msvcrt

            lock_stream.seek(0, os.SEEK_END)
            if lock_stream.tell() == 0:
                lock_stream.write(bytes([0]))
                lock_stream.flush()
            lock_stream.seek(0)
            msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_stream.seek(0)
                msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)


class WitnessVerificationError(RuntimeError):
    """Raised when a witness chain cannot be independently verified."""


def _verify_witness_chain(
    path: Path, public: Ed25519PublicKey,
) -> dict[str, Any]:
    fingerprint = _fingerprint(public)
    previous = "0" * 64
    count = 0
    try:
        with path.open(encoding="utf-8") as stream:
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
                previous = _receipt_hash(receipt)
                count += 1
    except OSError as exc:
        raise WitnessVerificationError("witness_log_unreadable") from exc
    return {"valid": True, "count": count, "last_receipt_hash": previous, "signer_fingerprint": fingerprint}


class IndependentWitness:
    """Append-only signed witness receipt stream, separate from the backup signer."""

    def __init__(self, path: Path, signing_key: Ed25519PrivateKey | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = _load_private(signing_key)
        self.path.touch(exist_ok=True)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def attest(self, event_hash: str, event_type: str) -> dict[str, Any]:
        if not isinstance(event_hash, str) or len(event_hash) != 64 or any(
            char not in "0123456789abcdef" for char in event_hash
        ):
            raise WitnessVerificationError("event_hash_must_be_sha256")
        if not isinstance(event_type, str) or not event_type.strip():
            raise WitnessVerificationError("event_type_required")

        # The lock covers verification, sequence allocation, signing and durable append.
        # Every process must use this API and the same sidecar lock path.
        lock_path = self.path.with_name(self.path.name + ".lock")
        with _exclusive_file_lock(lock_path):
            previous = "0" * 64
            sequence = 1
            if self.path.stat().st_size:
                verified = _verify_witness_chain(self.path, self.signing_key.public_key())
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
                "signature": base64.b64encode(self.signing_key.sign(_canonical(payload))).decode("ascii"),
            }
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(_canonical(receipt).decode("utf-8") + chr(10))
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
    with _exclusive_file_lock(lock_path):
        return _verify_witness_chain(path, public)


__all__ = ["IndependentWitness", "WitnessVerificationError", "verify_witness_chain"]
