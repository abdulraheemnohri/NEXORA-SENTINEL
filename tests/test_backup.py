import json
import sqlite3

import pytest

from nexora.backup import BackupError, create_backup, restore_backup, verify_backup
from nexora.cli import main


def _database(path):
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA user_version=7")
        db.execute("CREATE TABLE records(value TEXT NOT NULL)")
        db.execute("INSERT INTO records VALUES('committed in WAL')")
    return path


def test_backup_includes_wal_commits_and_verifies(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    manifest = create_backup(source, backup)
    result = verify_backup(backup)
    assert result["valid"] is True
    assert result["user_version"] == 7
    assert result["tables"] == ["records"]
    assert manifest["sha256"] == result["sha256"]


def test_backup_detects_data_tampering(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    create_backup(source, backup)
    with backup.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(BackupError, match="backup_hash_mismatch"):
        verify_backup(backup)


def test_backup_rejects_invalid_database_and_missing_source(tmp_path):
    with pytest.raises(BackupError, match="source_database_not_found"):
        create_backup(tmp_path / "missing.db", tmp_path / "backup.db")
    bad = tmp_path / "bad.db"
    bad.write_text("not sqlite")
    with pytest.raises(BackupError):
        create_backup(bad, tmp_path / "bad-backup.db")


def test_restore_is_verified_and_non_destructive(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    create_backup(source, backup)
    destination = tmp_path / "restored.sqlite3"
    result = restore_backup(backup, destination)
    assert result["restored"] is True
    with sqlite3.connect(destination) as db:
        assert db.execute("SELECT value FROM records").fetchone()[0] == "committed in WAL"
    with pytest.raises(BackupError, match="restore_destination_exists"):
        restore_backup(backup, destination)


def test_manifest_tampering_is_detected(tmp_path):
    source = _database(tmp_path / "source.sqlite3")
    backup = tmp_path / "snapshot.sqlite3"
    create_backup(source, backup)
    manifest = backup.with_name(backup.name + ".manifest.json")
    data = json.loads(manifest.read_text())
    data["user_version"] = 99
    manifest.write_text(json.dumps(data))
    with pytest.raises(BackupError, match="backup_manifest_metadata_mismatch"):
        verify_backup(backup)


def test_cli_registry_init_backup_verify_restore(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "registry-init"]) == 0
    assert main(["--data-dir", str(tmp_path), "backup"]) == 0
    backup = tmp_path / "backups" / "registry.sqlite3"
    assert main(["--data-dir", str(tmp_path), "verify-backup", str(backup)]) == 0
    restored = tmp_path / "restored.sqlite3"
    assert main(["--data-dir", str(tmp_path), "restore", str(backup), str(restored)]) == 0
    assert restored.is_file()
