"""Durable local memory with provenance, deterministic retrieval and tombstones.

Memory is never written by inference. Callers must explicitly add records. Records
and events are append-only; deletion is represented by an auditable tombstone.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Any


class MemoryStore:
    """SQLite-backed memory store with source fingerprints and fail-closed reads."""

    def __init__(self, database: Path, *, create: bool = True):
        self.path = Path(database)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
        elif not self.path.is_file():
            raise FileNotFoundError("memory_database_not_found")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS memory_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS memory_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    memory_id INTEGER NOT NULL REFERENCES memory_records(id),
                    event_type TEXT NOT NULL CHECK(event_type IN ('CREATED','TOMBSTONED')),
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_memory_events_memory
                    ON memory_events(memory_id,event_id);
                CREATE TRIGGER IF NOT EXISTS memory_records_no_update
                    BEFORE UPDATE ON memory_records
                    BEGIN SELECT RAISE(ABORT,'memory_records_are_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS memory_records_no_delete
                    BEFORE DELETE ON memory_records
                    BEGIN SELECT RAISE(ABORT,'memory_records_are_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS memory_events_no_update
                    BEFORE UPDATE ON memory_events
                    BEGIN SELECT RAISE(ABORT,'memory_events_are_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS memory_events_no_delete
                    BEFORE DELETE ON memory_events
                    BEGIN SELECT RAISE(ABORT,'memory_events_are_append_only'); END;
                """
            )
            # One-time, idempotent import from the earlier simple memory table.
            legacy = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories'"
            ).fetchone()
            if legacy:
                columns = {row["name"] for row in db.execute("PRAGMA table_info(memories)")}
                if {"id", "content", "source"}.issubset(columns):
                    rows = db.execute(
                        "SELECT id,content,source FROM memories ORDER BY id"
                    ).fetchall()
                    for row in rows:
                        exists = db.execute(
                            "SELECT 1 FROM memory_records WHERE id=?", (row["id"],)
                        ).fetchone()
                        if not exists:
                            content = row["content"]
                            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
                            db.execute(
                                "INSERT INTO memory_records(id,content,source,sha256) VALUES(?,?,?,?)",
                                (row["id"], content, row["source"], digest),
                            )
                            db.execute(
                                "INSERT INTO memory_events(memory_id,event_type) VALUES(?,'CREATED')",
                                (row["id"],),
                            )

    @staticmethod
    def _validate_content(content: str, source: str) -> tuple[str, str]:
        if not isinstance(content, str) or not content.strip() or len(content) > 100_000:
            raise ValueError("memory_content_invalid")
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            raise ValueError("memory_source_required")
        return content.strip(), source.strip()

    def add(self, content: str, *, source: str) -> int:
        """Explicitly append a memory record; never called automatically by inference."""
        content, source = self._validate_content(content, source)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO memory_records(content,source,sha256) VALUES(?,?,?)",
                (content, source, digest),
            )
            memory_id = int(cursor.lastrowid)
            db.execute(
                "INSERT INTO memory_events(memory_id,event_type) VALUES(?,'CREATED')",
                (memory_id,),
            )
            return memory_id

    def get(self, memory_id: int, *, include_deleted: bool = False) -> dict[str, Any] | None:
        if type(memory_id) is not int or memory_id < 1:
            raise ValueError("memory_id_invalid")
        with self._connect() as db:
            row = db.execute(
                """SELECT r.*,e.event_type AS latest_event,e.reason AS event_reason
                   FROM memory_records r JOIN memory_events e ON e.event_id=(
                     SELECT MAX(e2.event_id) FROM memory_events e2 WHERE e2.memory_id=r.id
                   ) WHERE r.id=?""",
                (memory_id,),
            ).fetchone()
        if row is None or (row["latest_event"] == "TOMBSTONED" and not include_deleted):
            return None
        result = dict(row)
        result["provenance_valid"] = hashlib.sha256(
            result["content"].encode("utf-8")
        ).hexdigest() == result["sha256"]
        result["active"] = result["latest_event"] == "CREATED"
        return result

    def search(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        """Deterministic AND-term lexical retrieval; no model or embedding dependency."""
        if not isinstance(query, str) or not query.strip() or len(query) > 1000:
            raise ValueError("memory_query_invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("memory_limit_out_of_range")
        terms = re.findall(r"[\w-]{2,}", query.casefold(), flags=re.UNICODE)[:12]
        if not terms:
            raise ValueError("memory_query_has_no_search_terms")
        clauses = " AND ".join("lower(r.content) LIKE ?" for _ in terms)
        parameters = [f"%{term}%" for term in terms]
        parameters.append(limit)
        with self._connect() as db:
            rows = db.execute(
                f"""SELECT r.*,e.event_type AS latest_event
                    FROM memory_records r JOIN memory_events e ON e.event_id=(
                      SELECT MAX(e2.event_id) FROM memory_events e2 WHERE e2.memory_id=r.id
                    )
                    WHERE e.event_type='CREATED' AND {clauses}
                    ORDER BY r.id DESC LIMIT ?""",
                parameters,
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["provenance_valid"] = hashlib.sha256(
                item["content"].encode("utf-8")
            ).hexdigest() == item["sha256"]
            if not item["provenance_valid"]:
                raise RuntimeError("memory_provenance_verification_failed")
            results.append(item)
        return results

    def delete(self, memory_id: int, *, reason: str) -> None:
        """Append a tombstone; never physically erases the audit history."""
        if type(memory_id) is not int or memory_id < 1:
            raise ValueError("memory_id_invalid")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ValueError("memory_deletion_reason_required")
        with self._connect() as db:
            row = db.execute(
                """SELECT e.event_type FROM memory_events e
                   WHERE e.memory_id=? ORDER BY e.event_id DESC LIMIT 1""",
                (memory_id,),
            ).fetchone()
            if row is None:
                raise KeyError("memory_not_found")
            if row["event_type"] == "TOMBSTONED":
                raise ValueError("memory_already_deleted")
            db.execute(
                "INSERT INTO memory_events(memory_id,event_type,reason) VALUES(?,'TOMBSTONED',?)",
                (memory_id, reason.strip()),
            )

    def recent(self, limit: int = 50, *, include_deleted: bool = False) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("memory_limit_out_of_range")
        with self._connect() as db:
            rows = db.execute(
                """SELECT r.*,e.event_type AS latest_event,e.reason AS event_reason
                   FROM memory_records r JOIN memory_events e ON e.event_id=(
                     SELECT MAX(e2.event_id) FROM memory_events e2 WHERE e2.memory_id=r.id
                   ) ORDER BY r.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["active"] = item["latest_event"] == "CREATED"
            item["provenance_valid"] = hashlib.sha256(
                item["content"].encode("utf-8")
            ).hexdigest() == item["sha256"]
            if include_deleted or item["active"]:
                results.append(item)
        return results
