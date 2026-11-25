import json
import multiprocessing
import sqlite3
from pathlib import Path

import pytest

import nexora.backup as backup_module
from nexora.backup import (
    BackupError,
    create_backup,
    generate_backup_signing_key,
    restore_backup,
    verify_backup,
)
from nexora.cli import main
from nexora.oversight.witness import (
    IndependentWitness,
    WitnessVerificationError,
    verify_witness_chain,
)


def _database(path):
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA user_version=7")
        db.execute("CREATE TABLE records(value TEXT NOT NULL)")
        db.execute("INSERT INTO records VALUES('committed in WAL')")
    return path


def _keys(tmp_path, prefix="backup"):
    private = tmp_path / f"{prefix}-private.pem"
    public = tmp_path / f"{prefix}-public.pem"
    fingerprint = generate_backup_signing_key(private, public)
    return private, public, fingerprint


def _create(source, backup, private):
    return create_backup(source, backup, signing_key=private)


def test_backup_includes_wal_commits_and_verifies_signature(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, fingerprint = _keys(tmp_path)
    manifest = _create(source, backup, private)
    result = verify_backup(backup, trusted_public_key=public)
    assert result["valid"] is True
    assert result["user_version"] == 7
    assert result["tables"] == ["records"]
    assert result["signer_fingerprint"] == fingerprint
    assert manifest["sha256"] == result["sha256"]


def test_backup_detects_data_tampering(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    _create(source, backup, private)
    with backup.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(BackupError, match="backup_hash_mismatch"):
        verify_backup(backup, trusted_public_key=public)


def test_backup_rejects_invalid_database_and_missing_source(tmp_path):
    private, _, _ = _keys(tmp_path)
    with pytest.raises(BackupError, match="source_database_not_found"):
        create_backup(tmp_path / "missing.db", tmp_path / "backup.db", signing_key=private)
    bad = tmp_path / "bad.db"
    bad.write_text("not sqlite")
    with pytest.raises(BackupError):
        create_backup(bad, tmp_path / "bad-backup.db", signing_key=private)


def test_restore_is_verified_and_non_destructive(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    _create(source, backup, private)
    destination = tmp_path / "restored.sqlite3"
    result = restore_backup(backup, destination, trusted_public_key=public)
    assert result["restored"] is True
    with sqlite3.connect(destination) as db:
        assert db.execute("SELECT value FROM records").fetchone()[0] == "committed in WAL"
    with pytest.raises(BackupError, match="restore_destination_exists"):
        restore_backup(backup, destination, trusted_public_key=public)


def test_manifest_tampering_is_detected(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    _create(source, backup, private)
    manifest = backup.with_name(backup.name + ".manifest.json")
    data = json.loads(manifest.read_text())
    data["user_version"] = 99
    manifest.write_text(json.dumps(data))
    with pytest.raises(BackupError, match="backup_signature_invalid"):
        verify_backup(backup, trusted_public_key=public)


def test_backup_requires_external_trust_anchor(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, fingerprint = _keys(tmp_path, "right")
    _, wrong_public, _ = _keys(tmp_path, "wrong")
    _create(source, backup, private)
    with pytest.raises(BackupError, match="backup_signer_not_trusted"):
        verify_backup(backup, trusted_public_key=wrong_public)
    assert verify_backup(backup, trusted_public_key=public)["signer_fingerprint"] == fingerprint


def test_key_generation_is_non_overwriting_and_private(tmp_path):
    import os

    private, public, fingerprint = _keys(tmp_path)
    assert len(fingerprint) == 64
    assert private.exists() and public.exists()
    if os.name == "posix":
        assert private.stat().st_mode & 0o077 == 0
    with pytest.raises(BackupError, match="backup_signing_key_exists"):
        generate_backup_signing_key(private, public)


def test_restore_rejects_wrong_key_without_creating_destination(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, _, _ = _keys(tmp_path, "backup")
    _, wrong_public, _ = _keys(tmp_path, "wrong")
    _create(source, backup, private)
    destination = tmp_path / "must-not-exist.sqlite3"
    with pytest.raises(BackupError, match="backup_signer_not_trusted"):
        restore_backup(backup, destination, trusted_public_key=wrong_public)
    assert not destination.exists()


def test_independent_witness_chain_verifies_and_detects_tampering(tmp_path):
    private, public, _ = _keys(tmp_path, "witness")
    path = tmp_path / "witness" / "receipts.jsonl"
    witness = IndependentWitness(path, private)
    first = witness.attest("a" * 64, "backup")
    second = witness.attest("b" * 64, "restore")
    assert first["payload"]["sequence"] == 1
    assert second["payload"]["sequence"] == 2
    result = verify_witness_chain(path, public)
    assert result["valid"] and result["count"] == 2
    lines = path.read_text().splitlines()
    row = json.loads(lines[0])
    row["payload"]["event_type"] = "forged"
    lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(WitnessVerificationError, match="receipt_signature_invalid"):
        verify_witness_chain(path, public)


def test_witness_chain_rejects_wrong_trust_anchor(tmp_path):
    private, _, _ = _keys(tmp_path, "witness")
    _, wrong_public, _ = _keys(tmp_path, "wrong")
    path = tmp_path / "receipts.jsonl"
    IndependentWitness(path, private).attest("c" * 64, "backup")
    with pytest.raises(WitnessVerificationError, match="receipt_signer_untrusted"):
        verify_witness_chain(path, wrong_public)


def test_witness_refuses_to_extend_corrupt_chain(tmp_path):
    private, _, _ = _keys(tmp_path, "witness")
    path = tmp_path / "receipts.jsonl"
    witness = IndependentWitness(path, private)
    witness.attest("d" * 64, "backup")
    path.write_text("{}\n")
    with pytest.raises(WitnessVerificationError):
        witness.attest("e" * 64, "backup")
    assert path.read_text() == "{}\n"


def test_cli_rejects_reusing_backup_key_for_witness(tmp_path):
    assert main(["--data-dir", str(tmp_path), "registry-init"]) == 0
    assert main(["--data-dir", str(tmp_path), "backup-keygen"]) == 0
    assert main(["--data-dir", str(tmp_path), "backup"]) == 0
    backup = tmp_path / "backups" / "registry.sqlite3"
    with pytest.raises(ValueError, match="independent_witness_key_must_differ"):
        main([
            "--data-dir", str(tmp_path), "witness-backup", str(backup),
            "--signing-key", str(tmp_path / "backup-signing-key.pem"),
        ])


def test_cli_registry_signed_backup_verify_restore_and_witness(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "registry-init"]) == 0
    assert main(["--data-dir", str(tmp_path), "backup-keygen"]) == 0
    assert main([
        "--data-dir", str(tmp_path), "backup-keygen",
        "--private-key", str(tmp_path / "witness-signing-key.pem"),
        "--public-key", str(tmp_path / "witness-signing-key.pub.pem"),
    ]) == 0
    assert main(["--data-dir", str(tmp_path), "backup"]) == 0
    backup = tmp_path / "backups" / "registry.sqlite3"
    assert main(["--data-dir", str(tmp_path), "verify-backup", str(backup)]) == 0
    restored = tmp_path / "restored.sqlite3"
    assert main(["--data-dir", str(tmp_path), "restore", str(backup), str(restored)]) == 0
    assert restored.is_file()
    assert main(["--data-dir", str(tmp_path), "witness-backup", str(backup)]) == 0
    receipt_log = tmp_path / "witness" / "receipts.jsonl"
    assert main(["--data-dir", str(tmp_path), "verify-witness", str(receipt_log)]) == 0



def _append_witness_receipts(path, key_path, worker_id, count):
    witness = IndependentWitness(Path(path), Path(key_path))
    for index in range(count):
        event_hash = f"{worker_id * count + index + 1:064x}"
        witness.attest(event_hash, "multiprocess-test")


def test_witness_serializes_multiprocess_appends(tmp_path):
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("multiprocess fork test requires a POSIX fork context")
    private, public, _ = _keys(tmp_path, "parallel-witness")
    path = tmp_path / "parallel-receipts.jsonl"
    process_count = 4
    receipts_per_process = 5
    context = multiprocessing.get_context("fork")
    processes = [
        context.Process(
            target=_append_witness_receipts,
            args=(str(path), str(private), worker_id, receipts_per_process),
        )
        for worker_id in range(process_count)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join()
            pytest.fail("witness_append_process_timeout")
        assert process.exitcode == 0
    result = verify_witness_chain(path, public)
    assert result["valid"] is True
    assert result["count"] == process_count * receipts_per_process
    receipts = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["payload"]["sequence"] for row in receipts] == list(
        range(1, process_count * receipts_per_process + 1)
    )


def test_witness_rejects_truncated_final_receipt(tmp_path):
    private, public, _ = _keys(tmp_path, "truncated-witness")
    path = tmp_path / "truncated-receipts.jsonl"
    witness = IndependentWitness(path, private)
    witness.attest("f" * 64, "backup")
    with path.open("a", encoding="utf-8") as stream:
        stream.write('{"payload":')
    with pytest.raises(WitnessVerificationError, match="receipt_format_invalid:2"):
        witness.attest("e" * 64, "restore")
    with pytest.raises(WitnessVerificationError, match="receipt_format_invalid:2"):
        verify_witness_chain(path, public)



def test_backup_manifest_publish_failure_removes_unpaired_database(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, _, _ = _keys(tmp_path)
    original_publish = backup_module._publish_no_replace
    calls = 0

    def fail_manifest_publish(source_path, destination_path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BackupError("injected_manifest_publish_failure")
        return original_publish(source_path, destination_path)

    monkeypatch.setattr(backup_module, "_publish_no_replace", fail_manifest_publish)
    with pytest.raises(BackupError, match="injected_manifest_publish_failure"):
        create_backup(source, backup, signing_key=private)
    assert not backup.exists()
    assert not backup.with_name(backup.name + ".manifest.json").exists()
    assert not list(tmp_path.glob(".nexora-backup-*"))


def test_backup_publish_failure_leaves_no_partial_artifacts(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, _, _ = _keys(tmp_path)

    def fail_publish(_source, _destination):
        raise BackupError("injected_storage_publish_failure")

    monkeypatch.setattr(backup_module, "_publish_no_replace", fail_publish)
    with pytest.raises(BackupError, match="injected_storage_publish_failure"):
        create_backup(source, backup, signing_key=private)
    assert not backup.exists()
    assert not backup.with_name(backup.name + ".manifest.json").exists()
    assert not list(tmp_path.glob(".nexora-backup-*"))


def test_restore_validation_failure_removes_temporary_copy(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)
    destination = tmp_path / "restored.sqlite3"
    original_inspect = backup_module._inspect
    calls = 0

    def fail_restored_inspection(database):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BackupError("injected_restore_validation_failure")
        return original_inspect(database)

    monkeypatch.setattr(backup_module, "_inspect", fail_restored_inspection)
    with pytest.raises(BackupError, match="injected_restore_validation_failure"):
        restore_backup(backup, destination, trusted_public_key=public)
    assert not destination.exists()
    assert not list(tmp_path.glob(".nexora-restore-*"))


def test_backup_source_survives_snapshot_failure(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, _, _ = _keys(tmp_path)
    before = backup_module._inspect(source)
    with sqlite3.connect(source) as connection:
        before_rows = connection.execute("SELECT value FROM records ORDER BY value").fetchall()
    original_inspect = backup_module._inspect
    calls = 0

    def fail_snapshot_inspection(database):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BackupError("injected_snapshot_validation_failure")
        return original_inspect(database)

    monkeypatch.setattr(backup_module, "_inspect", fail_snapshot_inspection)
    with pytest.raises(BackupError, match="injected_snapshot_validation_failure"):
        create_backup(source, backup, signing_key=private)
    assert backup_module._inspect(source) == before
    with sqlite3.connect(source) as connection:
        after_rows = connection.execute("SELECT value FROM records ORDER BY value").fetchall()
    assert after_rows == before_rows
    assert not backup.exists()
    assert not backup.with_name(backup.name + ".manifest.json").exists()
    assert not list(tmp_path.glob(".nexora-backup-*"))



def test_backup_and_restore_are_standalone_sqlite_files(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)
    restored = tmp_path / "restored.sqlite3"
    restore_backup(backup, restored, trusted_public_key=public)
    for database in (backup, restored):
        assert not Path(str(database) + "-wal").exists()
        assert not Path(str(database) + "-shm").exists()
        with sqlite3.connect(database) as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def test_verify_backup_rejects_symlinked_database_without_following(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)
    original = backup.read_bytes()

    linked_backup = tmp_path / "linked.sqlite3"
    _symlink_or_skip(backup, linked_backup)
    linked_manifest = Path(str(linked_backup) + ".manifest.json")
    linked_manifest.write_bytes(Path(str(backup) + ".manifest.json").read_bytes())

    with pytest.raises(BackupError, match="backup_or_manifest_unsafe"):
        verify_backup(linked_backup, trusted_public_key=public)
    assert backup.read_bytes() == original


def test_verify_backup_rejects_symlinked_manifest_without_following(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)
    manifest = Path(str(backup) + ".manifest.json")
    original_manifest = tmp_path / "trusted-manifest.json"
    manifest.rename(original_manifest)
    original = original_manifest.read_bytes()
    _symlink_or_skip(original_manifest, manifest)

    with pytest.raises(BackupError, match="backup_or_manifest_unsafe"):
        verify_backup(backup, trusted_public_key=public)
    assert original_manifest.read_bytes() == original


def test_restore_rejects_existing_dangling_symlink_destination(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)
    destination = tmp_path / "restore-link.sqlite3"
    _symlink_or_skip(tmp_path / "missing-target.sqlite3", destination)

    with pytest.raises(BackupError, match="restore_destination_exists"):
        restore_backup(backup, destination, trusted_public_key=public)
    assert destination.is_symlink()


def test_restore_uses_exact_verified_snapshot_after_backup_path_swap(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    private, public, _ = _keys(tmp_path)
    create_backup(source, backup, signing_key=private)

    replacement_source = _database(tmp_path / "replacement-source.sqlite3")
    with sqlite3.connect(replacement_source) as db:
        db.execute("INSERT INTO records VALUES('replacement after verification')")
    replacement_backup = tmp_path / "replacement.sqlite3"
    create_backup(replacement_source, replacement_backup, signing_key=private)

    original_inspect = backup_module._inspect
    held_backup = tmp_path / "verified-original.sqlite3"
    swapped = False

    def replace_path_after_snapshot_inspection(database):
        nonlocal swapped
        result = original_inspect(database)
        path = Path(database)
        if not swapped and (
            path == backup or path.name.startswith(".nexora-verified-backup-")
        ):
            backup.rename(held_backup)
            replacement_backup.rename(backup)
            swapped = True
        return result

    monkeypatch.setattr(backup_module, "_inspect", replace_path_after_snapshot_inspection)
    destination = tmp_path / "restored.sqlite3"
    restore_backup(backup, destination, trusted_public_key=public)

    assert swapped is True
    with sqlite3.connect(destination) as db:
        rows = db.execute("SELECT value FROM records ORDER BY value").fetchall()
    assert rows == [("committed in WAL",)]


def test_create_backup_rejects_symlinked_source_without_following(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    linked_source = tmp_path / "linked-source.sqlite3"
    _symlink_or_skip(source, linked_source)
    private, _, _ = _keys(tmp_path)

    with pytest.raises(BackupError, match="source_database_unsafe"):
        create_backup(linked_source, tmp_path / "snapshot.sqlite3", signing_key=private)
    assert source.is_file()
    assert linked_source.is_symlink()
    assert not (tmp_path / "snapshot.sqlite3").exists()


def test_create_backup_rejects_non_regular_source(tmp_path):
    source_directory = tmp_path / "source-directory"
    source_directory.mkdir()
    private, _, _ = _keys(tmp_path)

    with pytest.raises(BackupError, match="source_database_unsafe"):
        create_backup(source_directory, tmp_path / "snapshot.sqlite3", signing_key=private)
    assert not (tmp_path / "snapshot.sqlite3").exists()


def test_create_backup_rejects_dangling_destination_symlink(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    _symlink_or_skip(tmp_path / "missing-database.sqlite3", backup)
    private, _, _ = _keys(tmp_path)

    with pytest.raises(BackupError, match="backup_destination_exists"):
        create_backup(source, backup, signing_key=private)
    assert backup.is_symlink()
    assert not Path(str(backup) + ".manifest.json").exists()


def test_create_backup_rejects_dangling_manifest_symlink(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    manifest = Path(str(backup) + ".manifest.json")
    _symlink_or_skip(tmp_path / "missing-manifest.json", manifest)
    private, _, _ = _keys(tmp_path)

    with pytest.raises(BackupError, match="backup_destination_exists"):
        create_backup(source, backup, signing_key=private)
    assert manifest.is_symlink()
    assert not backup.exists()


def test_create_backup_aborts_when_source_path_changes_after_open(tmp_path, monkeypatch):
    source = _database(tmp_path / "source.sqlite3")
    original_source = tmp_path / "source-original.sqlite3"
    backup = tmp_path / "snapshot.sqlite3"
    private, _, _ = _keys(tmp_path)
    original_check = backup_module._assert_path_matches_descriptor
    source_checks = 0

    def replace_source_before_sqlite_backup(path, descriptor, error_code):
        nonlocal source_checks
        if Path(path) == source:
            source_checks += 1
            if source_checks == 3:
                source.rename(original_source)
                _symlink_or_skip(original_source, source)
        return original_check(path, descriptor, error_code)

    monkeypatch.setattr(
        backup_module, "_assert_path_matches_descriptor", replace_source_before_sqlite_backup,
    )
    with pytest.raises(BackupError, match="source_database_changed"):
        create_backup(source, backup, signing_key=private)

    assert original_source.is_file()
    assert source.is_symlink()
    assert not backup.exists()
    assert not Path(str(backup) + ".manifest.json").exists()
    assert not list(tmp_path.glob(".nexora-backup-stage-*"))
