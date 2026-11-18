"""Persistent proposal scheduler. Due jobs are never executed here."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

class Scheduler:
    def __init__(self, database: Path):
        self.path=Path(database); self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
              due_at INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('PENDING','CLAIMED','CANCELLED')),
              created_at INTEGER NOT NULL)""")
    def _db(self):
        db=sqlite3.connect(self.path,timeout=10); db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=FULL"); return db
    def schedule(self, kind: str, payload: dict, due_at: int, *, now: int|None=None) -> str:
        if not kind or not isinstance(payload,dict) or type(due_at) is not int: raise ValueError("invalid_job")
        job_id=uuid.uuid4().hex; current=int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?)",(job_id,kind,json.dumps(payload,sort_keys=True),due_at,"PENDING",current))
        return job_id
    def due(self, *, now: int|None=None, limit: int=50) -> list[dict]:
        current=int(time.time()) if now is None else int(now)
        if not 1<=limit<=500: raise ValueError("limit_out_of_range")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            rows=db.execute("SELECT id,kind,payload,due_at FROM jobs WHERE state='PENDING' AND due_at<=? ORDER BY due_at,id LIMIT ?",(current,limit)).fetchall()
            for row in rows: db.execute("UPDATE jobs SET state='CLAIMED' WHERE id=? AND state='PENDING'",(row[0],))
        return [{"id":r[0],"kind":r[1],"payload":json.loads(r[2]),"due_at":r[3]} for r in rows]
    def cancel(self, job_id: str) -> bool:
        with self._db() as db:
            cur=db.execute("UPDATE jobs SET state='CANCELLED' WHERE id=? AND state='PENDING'",(job_id,))
            return cur.rowcount==1
