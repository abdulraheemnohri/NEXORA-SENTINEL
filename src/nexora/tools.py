"""Tool contracts and approval queue; no tool implementation is invoked."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolContract:
    name: str
    risk: str
    description: str
    requires_approval: bool = True


class ToolBoundary:
    def __init__(self, database: Path):
        self.path=Path(database); self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS proposals(
              id TEXT PRIMARY KEY, tool TEXT NOT NULL, arguments TEXT NOT NULL,
              risk TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    def _db(self):
        db=sqlite3.connect(self.path,timeout=10); db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=FULL"); return db
    def propose(self, contract: ToolContract, arguments: dict) -> str:
        if contract.risk not in {"low","medium","high","critical"}: raise ValueError("unknown_risk_denied")
        if not isinstance(arguments,dict): raise TypeError("arguments_must_be_object")
        proposal=uuid.uuid4().hex
        with self._db() as db:
            db.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?)",
                       (proposal,contract.name,json.dumps(arguments,sort_keys=True),"critical" if contract.risk=="critical" else contract.risk,"PENDING_REVIEW",int(time.time())))
        return proposal
    def list_pending(self) -> list[dict]:
        with self._db() as db:
            return [{"id":r[0],"tool":r[1],"arguments":json.loads(r[2]),"risk":r[3]}
                    for r in db.execute("SELECT id,tool,arguments,risk FROM proposals WHERE state='PENDING_REVIEW' ORDER BY created_at")]
