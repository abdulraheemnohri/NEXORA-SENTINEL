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
    assert report["head_hash"] == "0" * 64
