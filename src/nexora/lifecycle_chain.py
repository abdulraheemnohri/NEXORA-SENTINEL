"""Versioned-by-activation hash chain for new registry lifecycle events.

Legacy rows are explicitly excluded using immutable-at-initialization watermarks.
The chain is tamper-evident only when its head is independently witnessed.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

SOURCE_TABLES = ("lifecycle_events", "revocation_events", "rollback_events")
GENESIS = "0" * 64


class LifecycleChainError(RuntimeError):
    """Raised when lifecycle-chain schema or verification fails."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_hash(sequence: int, source_table: str, source_event_id: int,
                payload_json: str, previous_hash: str) -> str:
    envelope = {
        "sequence": sequence,
        "source_table": source_table,
        "source_event_id": source_event_id,
        "payload_json": payload_json,
        "previous_hash": previous_hash,
    }
    return hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()


def initialize_lifecycle_chain(db: sqlite3.Connection) -> None:
    """Create chain schema and capture legacy event watermarks exactly once."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS lifecycle_chain_meta (
            source_table TEXT PRIMARY KEY,
            legacy_max_event_id INTEGER NOT NULL CHECK(legacy_max_event_id >= 0)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS lifecycle_chain_events (
            sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
            source_table TEXT NOT NULL CHECK(source_table IN (
                'lifecycle_events','revocation_events','rollback_events'
            )),
            source_event_id INTEGER NOT NULL CHECK(source_event_id >= 1),
            payload_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL CHECK(length(previous_hash) = 64),
            event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash) = 64),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(source_table, source_event_id)
        )
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS lifecycle_chain_no_update
        BEFORE UPDATE ON lifecycle_chain_events BEGIN
            SELECT RAISE(ABORT, 'lifecycle chain is append-only');
        END
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS lifecycle_chain_no_delete
        BEFORE DELETE ON lifecycle_chain_events BEGIN
            SELECT RAISE(ABORT, 'lifecycle chain is append-only');
        END
    """)
    for table in SOURCE_TABLES:
        maximum = db.execute(f"SELECT COALESCE(MAX(event_id),0) FROM {table}").fetchone()[0]
        db.execute(
            "INSERT OR IGNORE INTO lifecycle_chain_meta(source_table,legacy_max_event_id) VALUES(?,?)",
            (table, maximum),
        )


def append_lifecycle_event(db: sqlite3.Connection, source_table: str, event_id: int) -> dict:
    """Append a source event to the chain inside the caller's transaction."""
    if source_table not in SOURCE_TABLES or type(event_id) is not int or event_id < 1:
        raise LifecycleChainError("lifecycle_chain_source_invalid")
    row = db.execute(
        f"SELECT * FROM {source_table} WHERE event_id=?", (event_id,)
    ).fetchone()
    if row is None:
        raise LifecycleChainError("lifecycle_chain_source_event_missing")
    payload_json = canonical_json(dict(row))
    previous = db.execute(
        "SELECT sequence,event_hash FROM lifecycle_chain_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    sequence = (previous["sequence"] + 1) if previous else 1
    previous_hash = previous["event_hash"] if previous else GENESIS
    digest = _event_hash(sequence, source_table, event_id, payload_json, previous_hash)
    db.execute(
        """INSERT INTO lifecycle_chain_events(
            sequence,source_table,source_event_id,payload_json,previous_hash,event_hash
        ) VALUES(?,?,?,?,?,?)""",
        (sequence, source_table, event_id, payload_json, previous_hash, digest),
    )
    return {"sequence": sequence, "event_hash": digest, "previous_hash": previous_hash}


def verify_lifecycle_chain(db: sqlite3.Connection) -> dict:
    """Verify chain continuity, event payloads and complete post-activation coverage."""
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not {"lifecycle_chain_meta", "lifecycle_chain_events"}.issubset(tables):
        return {
            "valid": False, "status": "NOT_MIGRATED", "event_count": 0,
            "head_hash": None, "legacy_unverified": True,
            "error": "lifecycle_chain_schema_missing",
        }
    metadata = {
        row["source_table"]: row["legacy_max_event_id"]
        for row in db.execute("SELECT source_table,legacy_max_event_id FROM lifecycle_chain_meta")
    }
    if set(metadata) != set(SOURCE_TABLES):
        return {
            "valid": False, "status": "INVALID", "event_count": 0,
            "head_hash": None, "legacy_unverified": True,
            "error": "lifecycle_chain_watermarks_incomplete",
        }

    previous_hash = GENESIS
    expected_sequence = 1
    covered: set[tuple[str, int]] = set()
    errors: list[str] = []
    head_hash = GENESIS
    rows = db.execute("SELECT * FROM lifecycle_chain_events ORDER BY sequence").fetchall()
    for row in rows:
        event = dict(row)
        if event["sequence"] != expected_sequence:
            errors.append(f"sequence_gap:{expected_sequence}")
            break
        if event["previous_hash"] != previous_hash:
            errors.append(f"previous_hash_mismatch:{expected_sequence}")
            break
        try:
            payload = json.loads(event["payload_json"])
        except (json.JSONDecodeError, TypeError):
            errors.append(f"payload_invalid:{expected_sequence}")
            break
        if not isinstance(payload, dict) or canonical_json(payload) != event["payload_json"]:
            errors.append(f"payload_not_canonical:{expected_sequence}")
            break
        digest = _event_hash(
            event["sequence"], event["source_table"], event["source_event_id"],
            event["payload_json"], event["previous_hash"],
        )
        if digest != event["event_hash"]:
            errors.append(f"event_hash_mismatch:{expected_sequence}")
            break
        source_table = event["source_table"]
        if source_table not in SOURCE_TABLES:
            errors.append(f"source_table_invalid:{expected_sequence}")
            break
        source = db.execute(
            f"SELECT * FROM {source_table} WHERE event_id=?",
            (event["source_event_id"],),
        ).fetchone()
        if source is None or canonical_json(dict(source)) != event["payload_json"]:
            errors.append(f"source_event_mismatch:{expected_sequence}")
            break
        key = (source_table, event["source_event_id"])
        if key in covered:
            errors.append(f"duplicate_source_event:{expected_sequence}")
            break
        covered.add(key)
        previous_hash = digest
        head_hash = digest
        expected_sequence += 1

    missing = []
    legacy_counts = {}
    if not errors:
        for table in SOURCE_TABLES:
            baseline = metadata[table]
            legacy_counts[table] = baseline
            source_ids = {
                row[0] for row in db.execute(
                    f"SELECT event_id FROM {table} WHERE event_id > ?", (baseline,)
                )
            }
            missing_ids = sorted(source_ids - {
                event_id for source, event_id in covered if source == table
            })
            if missing_ids:
                missing.append({"source_table": table, "event_ids": missing_ids[:100]})
    if missing:
        errors.append("post_activation_source_events_missing_from_chain")
    return {
        "valid": not errors,
        "status": "VALID" if not errors else "INVALID",
        "event_count": len(rows),
        "head_hash": head_hash,
        "legacy_unverified": True,
        "legacy_watermarks": legacy_counts,
        "missing_events": missing,
        "errors": errors,
        "external_anchor": "NOT_CHECKED",
        "warning": (
            "A local database hash chain is not an independent trust anchor. "
            "Retain signed checkpoints on a separately controlled system."
        ),
    }
