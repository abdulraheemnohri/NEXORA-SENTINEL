from __future__ import annotations

import sqlite3

import pytest

from nexora.lifecycle_history import (
    LifecycleHistoryError,
    build_lifecycle_history,
)


def _database(path):
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE capabilities(
            capability_id INTEGER PRIMARY KEY, name TEXT, family TEXT,
            state TEXT, control_state TEXT
        );
        CREATE TABLE lifecycle_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER,
            previous_state TEXT, requested_state TEXT, evidence_json TEXT,
            approver_id TEXT, reason TEXT, created_at TEXT
        );
        CREATE TABLE revocation_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER, created_at TEXT
        );
        CREATE TABLE rollback_events(
            event_id INTEGER PRIMARY KEY, capability_id INTEGER, created_at TEXT
        );
    """)
    db.execute("INSERT INTO capabilities VALUES(1,'Test','A','IMPLEMENTED','ACTIVE')")
    db.executemany(
        "INSERT INTO lifecycle_events VALUES(?,?,?,?,?,?,?,?)",
        [
            (1, 1, None, "SPECIFIED", '["source_record"]', None, "registered", "t1"),
            (2, 1, "SPECIFIED", "REGISTERED", '["source_record"]', None, "eligible", "t2"),
            (3, 1, "REGISTERED", "IMPLEMENTED", '["implementation_reference"]', None, "eligible", "t3"),
        ],
    )
    db.commit()
    db.close()


def test_history_replays_valid_legacy_events_without_claiming_authenticity(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    report = build_lifecycle_history(path)
    assert report["status"] == "CHAIN_NOT_MIGRATED"
    assert report["capabilities"][0]["replayed_state"] == "IMPLEMENTED"
    assert report["integrity"]["history_authenticity"] == "UNVERIFIED_WITHOUT_EXTERNAL_ANCHOR"
    assert report["execution_enabled"] is False


def test_detects_state_divergence(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE capabilities SET state='TESTED' WHERE capability_id=1")
    report = build_lifecycle_history(path)
    assert "CURRENT_STATE_DOES_NOT_MATCH_HISTORY" in {
        issue["code"] for issue in report["regressions"]
    }


def test_detects_non_sequential_transition(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE lifecycle_events SET requested_state='ENABLED' WHERE event_id=3"
        )
    report = build_lifecycle_history(path)
    assert "NON_SEQUENTIAL_TRANSITION" in {
        issue["code"] for issue in report["regressions"]
    }


def test_detects_revocation_control_state_mismatch(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO revocation_events VALUES(1,1,'t4')")
    report = build_lifecycle_history(path)
    assert "REVOCATION_EVENT_WITH_ACTIVE_CONTROL_STATE" in {
        issue["code"] for issue in report["regressions"]
    }


def test_read_only_does_not_create_database_or_parent(tmp_path):
    missing = tmp_path / "missing" / "registry.sqlite3"
    with pytest.raises(LifecycleHistoryError):
        build_lifecycle_history(missing)
    assert not missing.parent.exists()


def test_invalid_capability_filter_rejected(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    with pytest.raises(LifecycleHistoryError):
        build_lifecycle_history(path, 265)


def test_report_does_not_mutate_database(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    before = path.read_bytes()
    build_lifecycle_history(path)
    assert path.read_bytes() == before


def test_unknown_capability_filter_is_not_reported_as_clean(tmp_path):
    path = tmp_path / "registry.sqlite3"
    _database(path)
    with pytest.raises(LifecycleHistoryError, match="capability_not_found"):
        build_lifecycle_history(path, 2)
