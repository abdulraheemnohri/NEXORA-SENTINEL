from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.update_signing import (
    UpdateSignatureError,
    create_manifest,
    generate_update_signing_keypair,
    verify_manifest,
)


def keypair(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "update-private.pem"
    public_path = tmp_path / "update-public.pem"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    private_path.chmod(0o600)
    return private_path, public_path


def test_manifest_round_trip_with_external_trust_anchor(tmp_path):
    private, public = keypair(tmp_path)
    manifest = tmp_path / "release.manifest.json"
    result = create_manifest(
        commit_sha="a" * 40, version="0.3.0",
        signing_key=private, output=manifest,
    )
    verified = verify_manifest(manifest, public)
    assert result["created"] is True
    assert verified["valid"] is True
    assert verified["commit_sha"] == "a" * 40
    assert verified["trust"] == "externally_pinned_ed25519_key"


def test_manifest_rejects_wrong_trusted_key(tmp_path):
    private, _ = keypair(tmp_path)
    _, other_public = keypair(tmp_path / "other") if (tmp_path / "other").mkdir() is None else (None, None)
    manifest = tmp_path / "release.json"
    create_manifest(commit_sha="b" * 40, version="0.3.0",
                    signing_key=private, output=manifest)
    with pytest.raises(UpdateSignatureError, match="does_not_match_external_trust_pin"):
        verify_manifest(manifest, other_public)


def test_manifest_rejects_tampering(tmp_path):
    private, public = keypair(tmp_path)
    manifest = tmp_path / "release.json"
    create_manifest(commit_sha="c" * 40, version="0.3.0",
                    signing_key=private, output=manifest)
    payload = json.loads(manifest.read_text())
    payload["version"] = "9.9.9"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(UpdateSignatureError, match="signature_invalid"):
        verify_manifest(manifest, public)


def test_manifest_refuses_overwrite(tmp_path):
    private, _ = keypair(tmp_path)
    manifest = tmp_path / "release.json"
    manifest.write_text("keep")
    with pytest.raises(UpdateSignatureError, match="output_exists"):
        create_manifest(commit_sha="d" * 40, version="0.3.0",
                        signing_key=private, output=manifest)
    assert manifest.read_text() == "keep"


def test_manifest_rejects_wrong_repository_or_ref(tmp_path):
    private, public = keypair(tmp_path)
    manifest = tmp_path / "release.json"
    create_manifest(commit_sha="e" * 40, version="0.3.0",
                    signing_key=private, output=manifest)
    payload = json.loads(manifest.read_text())
    payload["ref"] = "refs/heads/other"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(UpdateSignatureError, match="repository_or_ref_mismatch"):
        verify_manifest(manifest, public)



def test_update_keygen_creates_matching_restricted_keypair(tmp_path):
    private = tmp_path / "keys" / "update-private.pem"
    public = tmp_path / "keys" / "update-public.pem"
    fingerprint = generate_update_signing_keypair(private, public)
    assert private.exists()
    assert public.exists()
    assert len(fingerprint) == 64
    if private.stat().st_mode & 0o777 != 0o600:
        pytest.fail("private key permissions must be 0600")
    manifest = tmp_path / "release.json"
    create_manifest(
        commit_sha="f" * 40, version="0.3.0",
        signing_key=private, output=manifest,
    )
    assert verify_manifest(manifest, public)["signer_fingerprint"] == fingerprint


def test_update_keygen_refuses_overwrite(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    private.write_text("existing private data")
    with pytest.raises(UpdateSignatureError, match="output_exists"):
        generate_update_signing_keypair(private, public)
    assert private.read_text() == "existing private data"
    assert not public.exists()


def test_update_keygen_requires_distinct_paths(tmp_path):
    destination = tmp_path / "same.pem"
    with pytest.raises(UpdateSignatureError, match="paths_must_be_different"):
        generate_update_signing_keypair(destination, destination)
    assert not destination.exists()
