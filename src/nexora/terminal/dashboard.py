"""Read-only terminal dashboard for local NEXORA Sentinel state."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Callable, TextIO

from nexora.catalog import status as catalog_status
from nexora.oversight import AuditLog, KillSwitch
from nexora.self_families import SELF_FAMILIES

MENU = """
NEXORA SENTINEL — READ-ONLY CONTROL DESK
1. System overview
2. Audit log
3. Self-family proposals
4. Capability registry
5. Exit
"""


def _read_rows(database: Path, query: str, parameters: tuple = ()) -> list[dict]:
    if not database.is_file():
        return []
    uri = database.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=3)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query, parameters).fetchall()]
    finally:
        connection.close()


def render_overview(data_dir: Path) -> str:
    data_dir = Path(data_dir)
    kill = KillSwitch(data_dir / "KILL")
    audit = AuditLog(data_dir / "audit.jsonl")
    try:
        catalogue = catalog_status()
        catalog_line = (
            f"Catalogue: {catalogue['registered_capabilities']}/"
            f"{catalogue['expected_capabilities']} records; complete={catalogue['complete']}"
        )
    except (OSError, ValueError, KeyError) as exc:
        catalog_line = f"Catalogue: unavailable ({type(exc).__name__})"
    audit_ok = audit.verify()
    return "\n".join((
        "SYSTEM OVERVIEW",
        f"Emergency stop: {'ENGAGED' if kill.is_engaged() else 'clear'}",
        f"Audit chain: {'VALID' if audit_ok else 'INVALID'}",
        catalog_line,
        "Autonomy: L0 default; this dashboard has no action controls.",
    ))


def render_audit(data_dir: Path) -> str:
    audit = AuditLog(Path(data_dir) / "audit.jsonl")
    entries = audit.entries()
    lines = [f"AUDIT LOG — chain {'VALID' if audit.verify() else 'INVALID'}",
             f"Entries: {len(entries)}"]
    for item in entries[-20:]:
        lines.append(
            f"#{item.get('sequence', '?')} {item.get('event', 'unknown')} "
            f"hash={str(item.get('hash', ''))[:12]}"
        )
    if not entries:
        lines.append("(no entries)")
    return "\n".join(lines)


def render_proposals(data_dir: Path) -> str:
    database = Path(data_dir) / "registry.sqlite3"
    try:
        rows = _read_rows(
            database,
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
        "4": render_registry,
    }
    while True:
        print(MENU, file=output)
        try:
            choice = input_fn("Select a view (1-5): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Leaving read-only dashboard.", file=output)
            return 0
        if choice == "5":
            print("Leaving read-only dashboard.", file=output)
            return 0
        view = views.get(choice)
        if view is None:
            print("Invalid selection; no action taken.", file=output)
            continue
        print("\n" + view(Path(data_dir)) + "\n", file=output)
