"""Persistent fail-closed resource budget accounting."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

class BudgetExceeded(RuntimeError):
    pass

class BudgetLedger:
    def __init__(self, database: Path):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY, category TEXT NOT NULL, amount INTEGER NOT NULL,
                created_at INTEGER NOT NULL, reference TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS usage_category_time ON usage(category,created_at)")

    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def consume(self, category: str, amount: int, *, limit: int, window_seconds: int = 3600,
                reference: str = "", now: int | None = None) -> int:
        if not category or type(amount) is not int or amount <= 0 or type(limit) is not int or limit < 1:
            raise ValueError("invalid_budget_request")
        if type(window_seconds) is not int or window_seconds < 1:
            raise ValueError("invalid_budget_window")
        current = int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute("SELECT COALESCE(SUM(amount),0) FROM usage WHERE category=? AND created_at>=?",
                              (category, current-window_seconds)).fetchone()[0]
            if used + amount > limit:
                raise BudgetExceeded(f"budget_exceeded:{category}:{used}:{amount}:{limit}")
            db.execute("INSERT INTO usage(category,amount,created_at,reference) VALUES(?,?,?,?)",
                       (category, amount, current, reference[:256]))
            return used + amount

    def usage(self, category: str, *, window_seconds: int = 3600, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        with self._db() as db:
            return db.execute("SELECT COALESCE(SUM(amount),0) FROM usage WHERE category=? AND created_at>=?",
                              (category,current-window_seconds)).fetchone()[0]
