"""Signed Ed25519 trust-anchor rotation statements; never auto-enroll a new key."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexora.approval import load_private_key, load_public_key, public_key_fingerprint

REPOSITORY = "abdulraheemnohri/NEXORA-SENTINEL"
ROLES = {"backup", "update", "witness"}
HEX_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_FIELDS = {
    "schema_version",
    "repository",
    "role",
    "transition_id",
    "created_at",
    "reason",
    "old_fingerprint",
    "new_fingerprint",
    "new_public_key_pem",
    "signer_fingerprint",
}


class TrustRotationError(ValueError):
    """Raised when a trust-anchor transition cannot be safely created or verified."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _require_regular_file(path: Path, label: str) -> None:
    try:
        metadata = Path(path).lstat()
    except FileNotFoundError as exc:
        raise TrustRotationError(f"{label}_missing") from exc
    except OSError as exc:
        raise TrustRotationError(f"{label}_unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise TrustRotationError(f"{label}_symlink_refused")
    if not stat.S_ISREG(metadata.st_mode):
        raise TrustRotationError(f"{label}_not_a_regular_file")


def create_rotation_statement(
    *,
    role: str,
    old_private_key: Path,
    new_public_key: Path,
    output: Path,
    reason: str,
) -> dict[str, Any]:
    """Create an old-key-signed transition statement without changing trust pins."""
    if role not in ROLES:
        raise TrustRotationError("trust_role_invalid")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
        raise TrustRotationError("trust_rotation_reason_required")

    old_path = Path(old_private_key)
    new_path = Path(new_public_key)
    _require_regular_file(old_path, "old_private_key")
    _require_regular_file(new_path, "new_public_key")

    try:
        old_signer = load_private_key(old_path)
        new_public = load_public_key(new_path)
        new_pem = new_path.read_text(encoding="ascii")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise TrustRotationError("trust_rotation_key_invalid") from exc

    old_fingerprint = public_key_fingerprint(old_signer.public_key())
    new_fingerprint = public_key_fingerprint(new_public)
    if old_fingerprint == new_fingerprint:
        raise TrustRotationError("trust_rotation_new_key_matches_old_key")

    payload = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "role": role,
        "transition_id": secrets.token_hex(16),
        "created_at": datetime.now(UTC).isoformat(),
        "reason": reason.strip(),
        "old_fingerprint": old_fingerprint,
        "new_fingerprint": new_fingerprint,
        "new_public_key_pem": new_pem,
        "signer_fingerprint": old_fingerprint,
    }
    signature = base64.b64encode(old_signer.sign(_canonical(payload))).decode("ascii")
    document = {"payload": payload, "signature": signature}
    serialized = json.dumps(
        document, sort_keys=True, indent=2, ensure_ascii=False,
    ) + "\n"

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except FileExistsError as exc:
        raise TrustRotationError("trust_rotation_output_exists") from exc
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise TrustRotationError("trust_rotation_statement_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return {
        "created": True,
        "role": role,
        "transition_id": payload["transition_id"],
        "old_fingerprint": old_fingerprint,
        "new_fingerprint": new_fingerprint,
        "output": str(destination),
        "signature_algorithm": "Ed25519",
        "trust_pin_changed": False,
        "new_key_enrolled": False,
        "activation_status": "NOT_APPLIED",
        "requires_out_of_band_confirmation": True,
    }


def verify_rotation_statement(
    manifest_path: Path,
    *,
    trusted_old_public_key: Path,
) -> dict[str, Any]:
    """Verify a transition against the old pin; never enroll the embedded new key."""
    path = Path(manifest_path)
    _require_regular_file(path, "trust_rotation_manifest")
    old_path = Path(trusted_old_public_key)
    _require_regular_file(old_path, "trusted_old_public_key")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        old_public = load_public_key(old_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise TrustRotationError("trust_rotation_manifest_or_pin_invalid") from exc

    if not isinstance(document, dict) or set(document) != {"payload", "signature"}:
        raise TrustRotationError("trust_rotation_manifest_schema_invalid")
    payload = document["payload"]
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise TrustRotationError("trust_rotation_payload_schema_invalid")
    if payload.get("schema_version") != 1 or payload.get("repository") != REPOSITORY:
        raise TrustRotationError("trust_rotation_context_invalid")
    if payload.get("role") not in ROLES:
        raise TrustRotationError("trust_rotation_role_invalid")
    if not isinstance(payload.get("transition_id"), str) or not re.fullmatch(
        r"[0-9a-f]{32}", payload["transition_id"]
    ):
        raise TrustRotationError("trust_rotation_id_invalid")
    if (
        not isinstance(payload.get("reason"), str)
        or not payload["reason"].strip()
        or len(payload["reason"]) > 1024
    ):
        raise TrustRotationError("trust_rotation_reason_invalid")
    created_at = payload.get("created_at")
    if not isinstance(created_at, str):
        raise TrustRotationError("trust_rotation_timestamp_invalid")
    try:
        parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustRotationError("trust_rotation_timestamp_invalid") from exc
    if parsed_created_at.tzinfo is None:
        raise TrustRotationError("trust_rotation_timestamp_must_be_timezone_aware")
    old_fingerprint = payload.get("old_fingerprint")
    new_fingerprint = payload.get("new_fingerprint")
    if (
        not isinstance(old_fingerprint, str)
        or not HEX_FINGERPRINT.fullmatch(old_fingerprint)
        or not isinstance(new_fingerprint, str)
        or not HEX_FINGERPRINT.fullmatch(new_fingerprint)
    ):
        raise TrustRotationError("trust_rotation_fingerprint_invalid")

    trusted_fingerprint = public_key_fingerprint(old_public)
    if (
        old_fingerprint != trusted_fingerprint
        or payload.get("signer_fingerprint") != trusted_fingerprint
    ):
        raise TrustRotationError("trust_rotation_old_pin_mismatch")

    pem = payload.get("new_public_key_pem")
    if not isinstance(pem, str) or len(pem) > 4096:
        raise TrustRotationError("trust_rotation_new_public_key_invalid")
    try:
        new_public = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise TrustRotationError("trust_rotation_new_public_key_invalid") from exc
    if not isinstance(new_public, Ed25519PublicKey):
        raise TrustRotationError("trust_rotation_new_ed25519_key_required")
    actual_new_fingerprint = public_key_fingerprint(new_public)
    if (
        actual_new_fingerprint != new_fingerprint
        or actual_new_fingerprint == trusted_fingerprint
    ):
        raise TrustRotationError("trust_rotation_new_fingerprint_mismatch")

    signature_value = document["signature"]
    if not isinstance(signature_value, str):
        raise TrustRotationError("trust_rotation_signature_invalid")
    try:
        signature = base64.b64decode(signature_value, validate=True)
        old_public.verify(signature, _canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise TrustRotationError("trust_rotation_signature_invalid") from exc

    return {
        "valid": True,
        "role": payload["role"],
        "transition_id": payload["transition_id"],
        "old_fingerprint": trusted_fingerprint,
        "new_fingerprint": actual_new_fingerprint,
        "reason": payload["reason"],
        "signature_verified_against": "EXISTING_OLD_PIN",
        "new_key_enrolled": False,
        "trust_pin_changed": False,
        "activation_status": "NOT_APPLIED",
        "requires_out_of_band_confirmation": True,
        "read_only": True,
        "execution_enabled": False,
        "note": (
            "A valid transition statement proves the old pinned key signed this "
            "proposal. It does not enroll the new key, update configuration, or "
            "activate the replacement trust anchor."
        ),
    }
