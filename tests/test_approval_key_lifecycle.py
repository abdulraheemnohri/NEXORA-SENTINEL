import os
import sqlite3

import pytest

import nexora.approval as approval_module
from nexora.approval import (
    ApprovalError,
    ApprovalReceiptStore,
    generate_keypair,
    load_private_key,
    load_public_key,
)


def _keypair(tmp_path, label):
    private = tmp_path / f"{label}-private.pem"
    public = tmp_path / f"{label}-public.pem"
    generate_keypair(private, public)
    return private, public


def test_keypair_permissions_and_no_overwrite(tmp_path):
    private, public = _keypair(tmp_path, "first")
    assert load_public_key(public)
    assert load_private_key(private)
    if os.name == "posix":
        assert private.stat().st_mode & 0o777 == 0o600
    else:
        # Windows ACLs inherit from the parent directory; POSIX mode bits do not apply.
        assert private.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    with pytest.raises(ApprovalError, match="already_exists"):
        generate_keypair(private, public)


def test_key_enrollment_rotation_and_revocation_are_audited(tmp_path):
    _old_private, old_public = _keypair(tmp_path, "old")
    _new_private, new_public = _keypair(tmp_path, "new")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    old_fingerprint = store.enroll_key(load_public_key(old_public), label="primary", now=10)
    new_fingerprint = store.rotate_key(
        old_fingerprint, load_public_key(new_public),
        new_label="replacement", reason="scheduled rotation", now=20,
    )

    keys = {item["fingerprint"]: item for item in store.list_keys()}
    assert keys[old_fingerprint]["active"] == 0
    assert keys[old_fingerprint]["revoked_at"] == 20
    assert keys[old_fingerprint]["replaced_by"] == new_fingerprint
    assert keys[new_fingerprint]["active"] == 1
    assert [item["event_type"] for item in store.key_history()] == [
        "ENROLLED", "ROTATED",
    ]

    store.revoke_key(new_fingerprint, reason="key suspected compromised")
    assert store.list_keys(include_revoked=False) == []
    assert [item["event_type"] for item in store.key_history()] == [
        "ENROLLED", "ROTATED", "REVOKED",
    ]


def test_failed_rotation_keeps_old_key_active(tmp_path):
    _, old_public = _keypair(tmp_path, "old")
    _, new_public = _keypair(tmp_path, "new")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    old_fingerprint = store.enroll_key(load_public_key(old_public), label="primary")
    with pytest.raises(ApprovalError, match="rotation_reason_required"):
        store.rotate_key(
            old_fingerprint, load_public_key(new_public),
            new_label="replacement", reason="",
        )
    keys = {item["fingerprint"]: item for item in store.list_keys()}
    assert keys[old_fingerprint]["active"] == 1
    assert len(keys) == 1
    assert [item["event_type"] for item in store.key_history()] == ["ENROLLED"]


def test_revoked_key_cannot_authorize_new_transition(tmp_path):
    from nexora.approval import create_receipt

    old_private, old_public = _keypair(tmp_path, "old")
    store = ApprovalReceiptStore(tmp_path / "approvals.sqlite3")
    fingerprint = store.enroll_key(load_public_key(old_public), label="approver")
    evidence = ["human_approval"]
    receipt = create_receipt(
        load_private_key(old_private), capability_id=12, transition="APPROVED",
        evidence=evidence, approver_id="operator-1", now=100,
    )
    store.revoke_key(fingerprint, reason="operator requested revocation")
    with pytest.raises(ApprovalError, match="untrusted_or_revoked"):
        store.verify_and_consume(
            receipt, capability_id=12, transition="APPROVED",
            evidence=evidence, approver_id="operator-1", now=101,
        )


def test_key_history_is_append_only(tmp_path):
    _, public = _keypair(tmp_path, "first")
    database = tmp_path / "approvals.sqlite3"
    store = ApprovalReceiptStore(database)
    store.enroll_key(load_public_key(public), label="operator")
    with sqlite3.connect(database) as db, pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM signing_key_events")



def _symlink_or_skip(target, link):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def test_public_key_loader_rejects_symlink_without_reading_target(tmp_path):
    _, public = _keypair(tmp_path, "public")
    link = tmp_path / "public-link.pem"
    _symlink_or_skip(public, link)

    with pytest.raises(ApprovalError, match="public_key_unreadable_or_invalid"):
        load_public_key(link)


def test_private_key_loader_rejects_symlink_without_reading_target(tmp_path):
    private, _ = _keypair(tmp_path, "private")
    link = tmp_path / "private-link.pem"
    _symlink_or_skip(private, link)

    with pytest.raises(ApprovalError, match="private_key_unreadable_or_invalid"):
        load_private_key(link)


def test_public_key_loader_rejects_non_regular_file(tmp_path):
    directory = tmp_path / "public-key-directory"
    directory.mkdir()

    with pytest.raises(ApprovalError, match="public_key_unreadable_or_invalid"):
        load_public_key(directory)


def test_private_key_permissions_are_checked_on_open_descriptor(tmp_path):
    if os.name != "posix":
        pytest.skip("private-key mode-bit test requires POSIX")
    private, _ = _keypair(tmp_path, "permissions")
    private.chmod(0o644)

    with pytest.raises(ApprovalError, match="private_key_permissions_too_open"):
        load_private_key(private)


def test_approval_key_loaders_reject_oversized_files(tmp_path):
    oversized_public = tmp_path / "oversized-public.pem"
    oversized_private = tmp_path / "oversized-private.pem"
    oversized_public.write_bytes(b"x" * (approval_module.MAX_APPROVAL_KEY_FILE_BYTES + 1))
    oversized_private.write_bytes(b"x" * (approval_module.MAX_APPROVAL_KEY_FILE_BYTES + 1))
    if os.name == "posix":
        oversized_private.chmod(0o600)

    with pytest.raises(ApprovalError, match="public_key_file_too_large"):
        load_public_key(oversized_public)
    with pytest.raises(ApprovalError, match="private_key_file_too_large"):
        load_private_key(oversized_private)


def test_public_key_loader_rejects_path_replacement_during_read(tmp_path, monkeypatch):
    _, public = _keypair(tmp_path, "replace")
    target = tmp_path / "unrelated.txt"
    target.write_text("preserve-me", encoding="utf-8")
    real_read = os.read
    replaced = False

    def replace_after_read(descriptor, count):
        nonlocal replaced
        data = real_read(descriptor, count)
        if data and not replaced:
            public.unlink()
            _symlink_or_skip(target, public)
            replaced = True
        return data

    monkeypatch.setattr(approval_module.os, "read", replace_after_read)
    with pytest.raises(ApprovalError, match="public_key_path_changed"):
        load_public_key(public)

    assert replaced
    assert public.is_symlink()
    assert target.read_text(encoding="utf-8") == "preserve-me"



def test_generate_signing_key_rejects_overwrite_without_changing_existing_key(tmp_path):
    path = tmp_path / "approval-private.pem"
    approval_module.generate_signing_key(path)
    original = path.read_bytes()

    with pytest.raises(ApprovalError, match="key_overwrite_disabled"):
        approval_module.generate_signing_key(path, overwrite=True)

    assert path.read_bytes() == original
    with pytest.raises(ApprovalError, match="key_output_already_exists"):
        approval_module.generate_signing_key(path)


def test_generate_signing_key_rejects_dangling_symlink_destination(tmp_path):
    target = tmp_path / "missing-target.pem"
    link = tmp_path / "approval-link.pem"
    _symlink_or_skip(target, link)

    with pytest.raises(ApprovalError, match="key_output_already_exists"):
        approval_module.generate_signing_key(link)

    assert link.is_symlink()
    assert not target.exists()


def test_generate_signing_key_preserves_replacement_path_on_write(tmp_path, monkeypatch):
    path = tmp_path / "approval-private.pem"
    target = tmp_path / "unrelated.txt"
    target.write_text("preserve-me", encoding="utf-8")
    real_write = os.write
    replaced = False

    def replace_after_write(descriptor, data):
        nonlocal replaced
        written = real_write(descriptor, data)
        if not replaced:
            path.unlink()
            _symlink_or_skip(target, path)
            replaced = True
        return written

    monkeypatch.setattr(approval_module.os, "write", replace_after_write)
    with pytest.raises(ApprovalError, match="key_output_path_changed"):
        approval_module.generate_signing_key(path)

    assert replaced
    assert path.is_symlink()
    assert target.read_text(encoding="utf-8") == "preserve-me"


def test_generate_keypair_rejects_dangling_symlink_before_creating_private_key(tmp_path):
    private = tmp_path / "private.pem"
    target = tmp_path / "missing-public.pem"
    public_link = tmp_path / "public.pem"
    _symlink_or_skip(target, public_link)

    with pytest.raises(ApprovalError, match="key_output_already_exists"):
        generate_keypair(private, public_link)

    assert not private.exists()
    assert public_link.is_symlink()
    assert not target.exists()


def test_generate_keypair_preserves_replacement_public_path(tmp_path, monkeypatch):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    target = tmp_path / "unrelated.txt"
    target.write_text("preserve-me", encoding="utf-8")
    real_write = os.write
    replaced = False

    def replace_after_write(descriptor, data):
        nonlocal replaced
        written = real_write(descriptor, data)
        if not replaced:
            public.unlink()
            _symlink_or_skip(target, public)
            replaced = True
        return written

    monkeypatch.setattr(approval_module.os, "write", replace_after_write)
    with pytest.raises(ApprovalError, match="key_output_path_changed"):
        generate_keypair(private, public)

    assert replaced
    assert public.is_symlink()
    assert not private.exists()
    assert target.read_text(encoding="utf-8") == "preserve-me"
