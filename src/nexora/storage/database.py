"""Consistent SQLite connection defaults for local data stores."""
import sqlite3
from pathlib import Path


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    target = Path(path)
    if readonly:
        db = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=10)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(target, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON")
    return db
