import json
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.trust_rotation import (
    TrustRotationError,
    create_rotation_statement,
    verify_rotation_statement,
)


def _write_private(path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    if os.name == "posix":
        path.chmod(0o600)
    return path


def _write_public(path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path


def test_trust_rotation_statement_is_signed_by_old_key_and_never_enrolls_new_key(tmp_path):
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    old_public = _write_public(tmp_path / "old" / "public.pem", old)
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "transitions" / "rotation.json"

    created = create_rotation_statement(
        role="update",
        old_private_key=old_private,
        new_public_key=new_public,
        output=manifest,
        reason="Scheduled signing key rotation",
    )
    verified = verify_rotation_statement(
        manifest,
        trusted_old_public_key=old_public,
    )

    assert created["created"] is True
    assert created["trust_pin_changed"] is False
    assert created["new_key_enrolled"] is False
    assert verified["valid"] is True
    assert verified["role"] == "update"
    assert verified["new_key_enrolled"] is False
    assert verified["trust_pin_changed"] is False
    assert verified["activation_status"] == "NOT_APPLIED"
    assert verified["requires_out_of_band_confirmation"] is True


def test_trust_rotation_verification_rejects_wrong_old_pin(tmp_path):
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    wrong_public = _write_public(
        tmp_path / "wrong" / "public.pem", Ed25519PrivateKey.generate()
    )
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "rotation.json"
    create_rotation_statement(
        role="backup",
        old_private_key=old_private,
        new_public_key=new_public,
        output=manifest,
        reason="Backup key rotation",
    )

    with pytest.raises(TrustRotationError, match="old_pin_mismatch"):
        verify_rotation_statement(manifest, trusted_old_public_key=wrong_public)


def test_trust_rotation_verification_rejects_tampered_reason(tmp_path):
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    old_public = _write_public(tmp_path / "old" / "public.pem", old)
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "rotation.json"
    create_rotation_statement(
        role="witness",
        old_private_key=old_private,
        new_public_key=new_public,
        output=manifest,
        reason="Witness key rotation",
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["payload"]["reason"] = "tampered"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(TrustRotationError, match="signature_invalid"):
        verify_rotation_statement(manifest, trusted_old_public_key=old_public)


def test_trust_rotation_refuses_overwrite_and_same_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    private = _write_private(tmp_path / "old" / "private.pem", key)
    public = _write_public(tmp_path / "old" / "public.pem", key)
    output = tmp_path / "rotation.json"

    with pytest.raises(TrustRotationError, match="matches_old"):
        create_rotation_statement(
            role="update",
            old_private_key=private,
            new_public_key=public,
            output=output,
            reason="No-op rotation",
        )

    other = Ed25519PrivateKey.generate()
    new_public = _write_public(tmp_path / "new" / "public.pem", other)
    create_rotation_statement(
        role="update",
        old_private_key=private,
        new_public_key=new_public,
        output=output,
        reason="Real rotation",
    )
    with pytest.raises(TrustRotationError, match="output_exists"):
        create_rotation_statement(
            role="update",
            old_private_key=private,
            new_public_key=new_public,
            output=output,
            reason="Attempt overwrite",
        )


def test_trust_rotation_refuses_symlinked_key_and_manifest_paths(tmp_path):
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    old_public = _write_public(tmp_path / "old" / "public.pem", old)
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "rotation.json"
    create_rotation_statement(
        role="backup",
        old_private_key=old_private,
        new_public_key=new_public,
        output=manifest,
        reason="Backup key rotation",
    )
    link = tmp_path / "rotation-link.json"
    try:
        link.symlink_to(manifest)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(TrustRotationError, match="manifest_symlink_refused"):
        verify_rotation_statement(link, trusted_old_public_key=old_public)


def test_trust_rotation_cli_create_and_verify(tmp_path, capsys):
    from nexora.cli import main

    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    old_public = _write_public(tmp_path / "old" / "public.pem", old)
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "rotation.json"

    result = main([
        "trust-rotate",
        "--role", "update",
        "--old-private-key", str(old_private),
        "--new-public-key", str(new_public),
        "--output", str(manifest),
        "--reason", "CLI rotation test",
    ])
    created = json.loads(capsys.readouterr().out)
    assert result == 0
    assert created["new_key_enrolled"] is False

    result = main([
        "trust-verify", str(manifest),
        "--trusted-old-public-key", str(old_public),
    ])
    verified = json.loads(capsys.readouterr().out)
    assert result == 0
    assert verified["valid"] is True
    assert verified["trust_pin_changed"] is False


def test_trust_rotation_rejects_boolean_schema_version(tmp_path):
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    old_private = _write_private(tmp_path / "old" / "private.pem", old)
    old_public = _write_public(tmp_path / "old" / "public.pem", old)
    new_public = _write_public(tmp_path / "new" / "public.pem", new)
    manifest = tmp_path / "rotation.json"
    create_rotation_statement(
        role="update",
        old_private_key=old_private,
        new_public_key=new_public,
        output=manifest,
        reason="Test strict schema version",
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["payload"]["schema_version"] = True
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(TrustRotationError, match="context_invalid"):
        verify_rotation_statement(manifest, trusted_old_public_key=old_public)
