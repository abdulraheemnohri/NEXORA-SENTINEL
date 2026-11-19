from __future__ import annotations

import sqlite3

from nexora.lifecycle_chain import (
    LifecycleChainError,
    append_lifecycle_event,
    initialize_lifecycle_chain,
    verify_lifecycle_chain,
)


def _db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE lifecycle_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER,
            previous_state TEXT, requested_state TEXT
        );
        CREATE TABLE revocation_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER, reason TEXT
        );
        CREATE TABLE rollback_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER, reason TEXT
        );
        INSERT INTO lifecycle_events VALUES(1,1,NULL,'SPECIFIED');
    """)
    initialize_lifecycle_chain(db)
    return db


def test_legacy_rows_are_excluded_and_explicitly_unverified():
    db = _db()
    report = verify_lifecycle_chain(db)
    assert report["valid"] is True
    assert report["event_count"] == 0
    assert report["legacy_watermarks"]["lifecycle_events"] == 1
    assert report["legacy_unverified"] is True


def test_new_event_is_chained_and_verified():
    db = _db()
    db.execute("INSERT INTO lifecycle_events VALUES(2,1,'SPECIFIED','REGISTERED')")
    appended = append_lifecycle_event(db, "lifecycle_events", 2)
    report = verify_lifecycle_chain(db)
    assert report["valid"] is True
    assert report["head_hash"] == appended["event_hash"]
    assert report["event_count"] == 1


def test_source_event_tampering_is_detected():
    db = _db()
    db.execute("INSERT INTO lifecycle_events VALUES(2,1,'SPECIFIED','REGISTERED')")
    append_lifecycle_event(db, "lifecycle_events", 2)
    db.execute("UPDATE lifecycle_events SET requested_state='ENABLED' WHERE event_id=2")
    report = verify_lifecycle_chain(db)
    assert report["valid"] is False
    assert "source_event_mismatch:1" in report["errors"]


def test_missing_chain_entry_is_detected():
    db = _db()
    db.execute("INSERT INTO lifecycle_events VALUES(2,1,'SPECIFIED','REGISTERED')")
    report = verify_lifecycle_chain(db)
    assert report["valid"] is False
    assert "post_activation_source_events_missing_from_chain" in report["errors"]


def test_chain_update_and_delete_are_blocked():
    db = _db()
    db.execute("INSERT INTO lifecycle_events VALUES(2,1,'SPECIFIED','REGISTERED')")
    append_lifecycle_event(db, "lifecycle_events", 2)
    try:
        db.execute("DELETE FROM lifecycle_chain_events")
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("chain_delete_should_be_blocked")


def test_invalid_source_rejected():
    db = _db()
    try:
        append_lifecycle_event(db, "capabilities", 1)
    except LifecycleChainError:
        pass
    else:
        raise AssertionError("invalid_source_should_be_rejected")


def test_empty_chain_has_stable_genesis_head():
    report = verify_lifecycle_chain(_db())
    assert len(report["head_hash"]) == 64



def test_registry_writes_lifecycle_events_and_chain_atomically(tmp_path):
    from nexora.lifecycle_chain import verify_lifecycle_chain_file
    from nexora.registry import CapabilityRegistry

    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    registry.register(7, "Chain test", "A", source_record=True)
    registry.transition(7, "REGISTERED", ["source_record", "schema_validation"])
    registry.transition(7, "IMPLEMENTED", ["implementation_reference"])
    report = verify_lifecycle_chain_file(database)
    assert report["valid"] is True
    assert report["event_count"] == 3


def test_legacy_watermark_is_bound_to_chain_genesis(tmp_path):
    from nexora.lifecycle_chain import verify_lifecycle_chain_file
    from nexora.registry import CapabilityRegistry

    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    registry.register(7, "Chain test", "A", source_record=True)
    with sqlite3.connect(database) as db:
        db.execute("DROP TRIGGER lifecycle_chain_meta_no_update")
        db.execute(
            "UPDATE lifecycle_chain_meta SET legacy_max_event_id=legacy_max_event_id+1 "
            "WHERE source_table='lifecycle_events'"
        )
    report = verify_lifecycle_chain_file(database)
    assert report["valid"] is False
    assert any("previous_hash_mismatch" in error for error in report["errors"])


def test_external_witness_detects_chain_advance_after_checkpoint(tmp_path):
    from nexora.backup import generate_backup_signing_key
    from nexora.lifecycle_chain import verify_lifecycle_chain_anchor, verify_lifecycle_chain_file
    from nexora.oversight.witness import IndependentWitness
    from nexora.registry import CapabilityRegistry

    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    registry.register(7, "Chain test", "A", source_record=True)
    private_key = tmp_path / "witness-private.pem"
    public_key = tmp_path / "witness-public.pem"
    generate_backup_signing_key(private_key, public_key)
    witness_log = tmp_path / "external" / "witness.jsonl"
    before = verify_lifecycle_chain_file(database)
    IndependentWitness(witness_log, private_key).attest(
        before["head_hash"], "lifecycle_chain_head"
    )
    assert verify_lifecycle_chain_anchor(database, witness_log, public_key)["valid"] is True
    registry.register(8, "Second chain test", "A", source_record=True)
    result = verify_lifecycle_chain_anchor(database, witness_log, public_key)
    assert result["valid"] is False
    assert result["status"] == "ANCHOR_MISMATCH"



def test_existing_registry_rows_become_unverified_legacy_on_chain_activation(tmp_path):
    from nexora.lifecycle_chain import verify_lifecycle_chain_file
    from nexora.registry import CapabilityRegistry

    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    registry.register(7, "Old capability", "A", source_record=True)
    with sqlite3.connect(database) as db:
        db.execute("DROP TABLE lifecycle_chain_events")
        db.execute("DROP TABLE lifecycle_chain_meta")
    upgraded = CapabilityRegistry(database)
    report = verify_lifecycle_chain_file(database)
    assert report["valid"] is True
    assert report["event_count"] == 0
    assert report["legacy_watermarks"]["lifecycle_events"] == 1
    upgraded.register(8, "New capability", "A", source_record=True)
    report = verify_lifecycle_chain_file(database)
    assert report["valid"] is True
    assert report["event_count"] == 1



def test_legacy_event_cannot_be_retroactively_added_to_chain():
    db = _db()
    try:
        append_lifecycle_event(db, "lifecycle_events", 1)
    except LifecycleChainError as exc:
        assert str(exc) == "legacy_event_cannot_be_attested"
    else:
        raise AssertionError("legacy_event_must_not_be_attested")



def test_registry_event_and_chain_append_rollback_together(tmp_path):
    from nexora.registry import CapabilityRegistry

    database = tmp_path / "registry.sqlite3"
    registry = CapabilityRegistry(database)
    with sqlite3.connect(database) as db:
        db.execute("DROP TABLE lifecycle_chain_events")
    try:
        registry.register(9, "Must roll back", "A", source_record=True)
    except sqlite3.OperationalError:
        pass
    else:
        raise AssertionError("chain_write_failure_must_abort_registry_write")
    with sqlite3.connect(database) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM capabilities WHERE capability_id=9"
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM lifecycle_events WHERE capability_id=9"
        ).fetchone()[0] == 0



def test_cli_external_lifecycle_checkpoint_round_trip_and_staleness(tmp_path, capsys):
    from nexora.backup import generate_backup_signing_key
    from nexora.cli import main
    from nexora.registry import CapabilityRegistry

    data_dir = tmp_path / "data"
    registry = CapabilityRegistry(data_dir / "registry.sqlite3")
    registry.register(7, "CLI checkpoint test", "A", source_record=True)
    private_key = tmp_path / "witness-private.pem"
    public_key = tmp_path / "witness-public.pem"
    generate_backup_signing_key(private_key, public_key)
    witness_log = tmp_path / "separate-witness" / "lifecycle.jsonl"

    assert main([
        "--data-dir", str(data_dir), "lifecycle-chain-attest",
        "--witness-key", str(private_key),
        "--witness-log", str(witness_log), "--confirm",
    ]) == 0
    assert '"attested": true' in capsys.readouterr().out.lower()

    assert main([
        "--data-dir", str(data_dir), "lifecycle-chain-verify",
        "--witness-log", str(witness_log),
        "--trusted-witness-key", str(public_key),
    ]) == 0
    assert '"status": "ANCHORED"' in capsys.readouterr().out

    registry.register(8, "CLI checkpoint stale", "A", source_record=True)
    assert main([
        "--data-dir", str(data_dir), "lifecycle-chain-verify",
        "--witness-log", str(witness_log),
        "--trusted-witness-key", str(public_key),
    ]) == 2
    assert '"status": "ANCHOR_MISMATCH"' in capsys.readouterr().out
