"""Ed25519-signed update manifests with an externally pinned public key."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPOSITORY = "abdulraheemnohri/NEXORA-SENTINEL"
FIELDS = {
    "format_version", "repository", "ref", "commit_sha",
    "version", "created_at", "signer_fingerprint",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class UpdateSignatureError(ValueError):
    """An update manifest or its trust anchor is invalid."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _private(path: Path) -> Ed25519PrivateKey:
    try:
        if os.name == "posix" and Path(path).stat().st_mode & 0o077:
            raise UpdateSignatureError("update_private_key_permissions_too_open")
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise UpdateSignatureError("update_private_key_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise UpdateSignatureError("update_ed25519_private_key_required")
    return key


def _public(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise UpdateSignatureError("trusted_update_public_key_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateSignatureError("trusted_update_ed25519_public_key_required")
    return key


def create_manifest(
    *, commit_sha: str, version: str, signing_key: Path, output: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Create a signed manifest without replacing an existing output file."""
    if not SHA_RE.fullmatch(commit_sha):
        raise UpdateSignatureError("manifest_commit_sha_invalid")
    if not version or len(version) > 64 or any(ord(char) < 32 for char in version):
        raise UpdateSignatureError("manifest_version_invalid")
    signer = _private(signing_key)
    payload = {
        "format_version": 1,
        "repository": REPOSITORY,
        "ref": "refs/heads/main",
        "commit_sha": commit_sha,
        "version": version,
        "created_at": created_at or datetime.now(UTC).isoformat(),
        "signer_fingerprint": _fingerprint(signer.public_key()),
    }
    signature = base64.b64encode(signer.sign(_canonical(payload))).decode("ascii")
    manifest = {**payload, "signature": signature}
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = -1
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".nexora-update-", dir=destination.parent)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, destination)
        temporary.unlink()
    except FileExistsError as exc:
        raise UpdateSignatureError("manifest_output_exists") from exc
    except OSError as exc:
        raise UpdateSignatureError("manifest_write_failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {
        "created": True,
        "manifest": str(destination),
        "commit_sha": commit_sha,
        "version": version,
        "signer_fingerprint": payload["signer_fingerprint"],
    }


def verify_manifest(manifest_path: Path, trusted_key_path: Path) -> dict[str, Any]:
    """Verify signature and identity using a separately supplied trust anchor."""
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateSignatureError("update_manifest_unreadable") from exc
    if not isinstance(manifest, dict) or set(manifest) != FIELDS | {"signature"}:
        raise UpdateSignatureError("update_manifest_schema_invalid")
    payload = {key: manifest[key] for key in FIELDS}
    if payload["format_version"] != 1:
        raise UpdateSignatureError("update_manifest_version_unsupported")
    if payload["repository"] != REPOSITORY or payload["ref"] != "refs/heads/main":
        raise UpdateSignatureError("update_manifest_repository_or_ref_mismatch")
    sha = payload["commit_sha"]
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise UpdateSignatureError("update_manifest_commit_sha_invalid")
    version = payload["version"]
    if not isinstance(version, str) or not version or len(version) > 64:
        raise UpdateSignatureError("update_manifest_version_invalid")
    fingerprint = payload["signer_fingerprint"]
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise UpdateSignatureError("update_manifest_fingerprint_invalid")
    trusted = _public(Path(trusted_key_path))
    actual_fingerprint = _fingerprint(trusted)
    if actual_fingerprint != fingerprint:
        raise UpdateSignatureError("update_signer_does_not_match_external_trust_pin")
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
        trusted.verify(signature, _canonical(payload))
    except Exception as exc:
        raise UpdateSignatureError("update_manifest_signature_invalid") from exc
    return {
        "valid": True,
        "repository": payload["repository"],
        "ref": payload["ref"],
        "commit_sha": sha,
        "version": version,
        "created_at": payload["created_at"],
        "signer_fingerprint": actual_fingerprint,
        "trust": "externally_pinned_ed25519_key",
    }
