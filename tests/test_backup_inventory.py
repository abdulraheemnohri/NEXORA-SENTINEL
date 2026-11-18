import sqlite3
from datetime import UTC, datetime
from pathlib import Path
import pytest
from nexora.backup import create_backup, generate_backup_signing_key
from nexora.backup_inventory import BackupInventoryError, build_backup_inventory

def _source(path: Path) -> Path:
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sample(value TEXT)")
        db.execute("INSERT INTO sample VALUES('safe')")
    return path

def _keys(path: Path):
    private, public = path / "private.pem", path / "public.pem"
    generate_backup_signing_key(private, public)
    return private, public

def test_inventory_requires_existing_directory_and_is_read_only(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(BackupInventoryError):
        build_backup_inventory(missing)
    assert not missing.exists()
    directory = tmp_path / "backups"
    directory.mkdir()
    before = list(directory.iterdir())
    report = build_backup_inventory(directory)
    assert report["read_only"] is True and report["entry_count"] == 0
    assert list(directory.iterdir()) == before

def test_inventory_reports_orphan_database_and_manifest(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    (directory / "orphan.sqlite3").write_bytes(b"sqlite")
    (directory / "missing.sqlite3.manifest.json").write_text("{}")
    report = build_backup_inventory(directory)
    statuses = {item["name"]: item["status"] for item in report["entries"]}
    assert statuses == {"missing.sqlite3.manifest.json": "ORPHAN_MANIFEST", "orphan.sqlite3": "ORPHAN_DATABASE"}

def test_inventory_validates_signature_and_integrity_with_external_key(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    private, public = _keys(tmp_path)
    backup = directory / "daily.sqlite3"
    create_backup(_source(tmp_path / "source.sqlite3"), backup, signing_key=private)
    assert build_backup_inventory(directory)["entries"][0]["status"] == "TRUST_ANCHOR_REQUIRED"
    report = build_backup_inventory(directory, trusted_public_key=public, now=datetime.now(UTC))
    assert report["entries"][0]["status"] == "VALID"
    assert report["entries"][0]["table_count"] == 1

def test_inventory_detects_tampering_and_malformed_manifest(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    private, public = _keys(tmp_path)
    backup = directory / "tampered.sqlite3"
    create_backup(_source(tmp_path / "source.sqlite3"), backup, signing_key=private)
    with backup.open("ab") as stream:
        stream.write(b"tamper")
    malformed = directory / "broken.sqlite3"
    malformed.write_bytes(b"not sqlite")
    malformed.with_name(malformed.name + ".manifest.json").write_text("{")
    report = build_backup_inventory(directory, trusted_public_key=public)
    statuses = {item["name"]: item["status"] for item in report["entries"]}
    assert statuses["tampered.sqlite3"] == "INVALID"
    assert statuses["broken.sqlite3"] == "INVALID"

def test_inventory_does_not_follow_symlinks(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir()
    outside = _source(tmp_path / "outside.sqlite3")
    link = directory / "outside.sqlite3"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    report = build_backup_inventory(directory)
    assert report["entries"] == [{"name": "outside.sqlite3", "status": "UNSAFE_SYMLINK", "action": "manual_review"}]
