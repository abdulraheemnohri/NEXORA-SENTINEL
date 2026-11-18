"""Exact-source catalog loading; no invented capability entries."""
import json
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[2] / "spec" / "capability_catalog.json"

def status(path: Path = CATALOG) -> dict:
    data=json.loads(path.read_text(encoding="utf-8")); rows=data.get("capabilities",[])
    ids=[x.get("id") for x in rows if isinstance(x,dict)]
    families={x.get("family") for x in rows if isinstance(x,dict)}
    valid=all(isinstance(x,dict) and x.get("id") and x.get("name") and x.get("status") in
      {"specified","registered","implemented","tested","shadowed","approved","enabled"} for x in rows)
    complete=len(rows)==264 and len(families)==40 and len(ids)==len(set(ids)) and valid
    return {"expected_capabilities":264,"registered_capabilities":len(rows),
      "expected_families":40,"represented_families":len(families),
      "unique_ids":len(ids)==len(set(ids)),"entries_valid":valid,"complete":complete,
      "status":data.get("status","unknown")}
