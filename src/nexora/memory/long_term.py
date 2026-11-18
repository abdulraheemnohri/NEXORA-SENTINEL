"""Append-only local memory store with bounded text records."""
import sqlite3
from pathlib import Path


class MemoryStore:
    def __init__(self, database: Path):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY, content TEXT NOT NULL,
                source TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def add(self, content: str, *, source: str) -> int:
        if not isinstance(content, str) or not content.strip() or len(content) > 100000:
            raise ValueError("memory_content_invalid")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("memory_source_required")
        with sqlite3.connect(self.path) as db:
            cursor = db.execute("INSERT INTO memories(content,source) VALUES(?,?)", (content, source))
            return int(cursor.lastrowid)

    def recent(self, limit: int = 50) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("memory_limit_out_of_range")
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(
                "SELECT * FROM memories ORDER BY id DESC LIMIT ?", (limit,)
            )]
