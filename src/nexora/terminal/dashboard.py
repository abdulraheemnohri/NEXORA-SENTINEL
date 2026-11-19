"""Read-only terminal dashboard for local NEXORA Sentinel state."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from nexora.catalog import status as catalog_status
from nexora.oversight import KillSwitch

MENU = """
NEXORA SENTINEL — READ-ONLY CONTROL DESK
1. System overview
2. Audit log
3. Self-family proposals
4. Capability registry
5. Evidence freshness\n6. Exit
"""


def _read_audit(path: Path) -> tuple[list[dict], bool]:
    """Read and verify the hash chain without creating or changing the log."""
    if not path.is_file():
        return [], True
    previous = "0" * 64
    entries: list[dict] = []
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    return entries, False
                body = {key: value for key, value in item.items() if key != "hash"}
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                expected = hashlib.sha256((previous + canonical).encode()).hexdigest()
                if item.get("previous_hash") != previous or item.get("hash") != expected:
                    return entries, False
                entries.append(item)
                previous = expected
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return entries, False
    return entries, True


def _read_rows(database: Path, query: str) -> list[dict]:
    if not database.is_file():
        return []
    uri = database.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=3)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query).fetchall()]
    finally:
        connection.close()


def render_overview(data_dir: Path) -> str:
    data_dir = Path(data_dir)
    kill = KillSwitch(data_dir / "KILL")
    _, audit_ok = _read_audit(data_dir / "audit.jsonl")
    try:
        catalogue = catalog_status()
        catalog_line = (
            f"Catalogue: {catalogue['registered_capabilities']}/"
            f"{catalogue['expected_capabilities']} records; complete={catalogue['complete']}"
        )
    except (OSError, ValueError, KeyError) as exc:
        catalog_line = f"Catalogue: unavailable ({type(exc).__name__})"
    return "\n".join((
        "SYSTEM OVERVIEW",
        f"Emergency stop: {'ENGAGED' if kill.is_engaged() else 'clear'}",
        f"Audit chain: {'VALID' if audit_ok else 'INVALID'}",
        catalog_line,
        "Autonomy: L0 default; this dashboard has no action controls.",
    ))


def render_audit(data_dir: Path) -> str:
    entries, valid = _read_audit(Path(data_dir) / "audit.jsonl")
    lines = [f"AUDIT LOG — chain {'VALID' if valid else 'INVALID'}", f"Entries: {len(entries)}"]
    for item in entries[-20:]:
        lines.append(
            f"#{item.get('sequence', '?')} {item.get('event', 'unknown')} "
            f"hash={str(item.get('hash', ''))[:12]}"
        )
    if not entries:
        lines.append("(no entries)")
    return "\n".join(lines)


def render_proposals(data_dir: Path) -> str:
    try:
        rows = _read_rows(
            Path(data_dir) / "registry.sqlite3",
            """SELECT p.proposal_id,p.family,p.summary,p.execution,
                      (SELECT decision FROM self_family_review_events e
                       WHERE e.proposal_id=p.proposal_id ORDER BY event_id DESC LIMIT 1) AS status
               FROM self_family_proposals p ORDER BY p.created_at DESC LIMIT 50""",
        )
    except sqlite3.Error as exc:
        return f"SELF-FAMILY PROPOSALS — read failed closed ({type(exc).__name__})"
    lines = ["SELF-FAMILY PROPOSALS — READ ONLY"]
    if not rows:
        lines.append("(no stored proposals)")
    for row in rows:
        lines.append(
            f"{row['proposal_id']} [{row['family']}] {row['status']} "
            f"execution={row['execution']} — {row['summary']}"
        )
    return "\n".join(lines)


def render_registry(data_dir: Path) -> str:
    try:
        rows = _read_rows(
            Path(data_dir) / "registry.sqlite3",
            "SELECT capability_id,name,family,state,control_state FROM capabilities "
            "ORDER BY capability_id LIMIT 100",
        )
    except sqlite3.Error as exc:
        return f"CAPABILITY REGISTRY — read failed closed ({type(exc).__name__})"
    lines = ["CAPABILITY REGISTRY — READ ONLY"]
    if not rows:
        lines.append("(registry not initialized or empty)")
    for row in rows:
        lines.append(
            f"{row['capability_id']:03d} {row['family']} "
            f"{row['state']}/{row['control_state']} — {row['name']}"
        )
    return "\n".join(lines)


def render_evidence_freshness(data_dir: Path) -> str:
    from nexora.evidence_freshness import build_freshness_report

    database = Path(data_dir) / "registry.sqlite3"
    if not database.is_file():
        return "EVIDENCE FRESHNESS — ledger not configured"
    try:
        report = build_freshness_report(database)
    except (OSError, ValueError, sqlite3.Error) as exc:
        return f"EVIDENCE FRESHNESS — read failed closed ({type(exc).__name__})"
    counts = report["counts"]
    lines = [
        "EVIDENCE FRESHNESS — READ ONLY",
        f"Ledger integrity: {'VALID' if report['ledger_integrity']['valid'] else 'INVALID'}",
        f"Records: {report['reported_records']}/{report['total_records']}",
    ]
    lines.extend(f"{name}: {count}" for name, count in counts.items())
    lines.append("UNKNOWN does not mean valid; expiry is operator-declared only.")
    return "\\n".join(lines)


def run_read_only_tui(
    data_dir: Path,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO,
) -> int:
    """Run a simple dependency-free menu; it exposes no mutation commands."""
    views = {
        "1": render_overview,
        "2": render_audit,
        "3": render_proposals,
        "4": render_registry,\n        "5": render_evidence_freshness,
    }
    while True:
        print(MENU, file=output)
        try:
            choice = input_fn("Select a view (1-6): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Leaving read-only dashboard.", file=output)
            return 0
        if choice == "6":
            print("Leaving read-only dashboard.", file=output)
            return 0
        view = views.get(choice)
        if view is None:
            print("Invalid selection; no action taken.", file=output)
            continue
        print("\n" + view(Path(data_dir)) + "\n", file=output)
