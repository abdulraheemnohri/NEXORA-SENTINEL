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
5. Evidence freshness
6. Evidence provenance
7. Specification and matrix readiness
8. Doctor diagnostics
9. Capability family explorer
10. Explicit dependency graph
11. Settings authorization readiness
12. Exit
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
    from nexora.proposals import ProposalReadError, read_proposals

    try:
        report = read_proposals(Path(data_dir) / "registry.sqlite3", limit=50)
    except (ProposalReadError, OSError, ValueError, TypeError, sqlite3.Error) as exc:
        return f"SELF-FAMILY PROPOSALS — read failed closed ({type(exc).__name__})"

    lines = ["SELF-FAMILY PROPOSALS — READ ONLY"]
    if report["status"] == "NOT_CONFIGURED":
        lines.append("(no stored proposals; proposal store not configured)")
    elif report["status"] != "VALID":
        lines.append(f"Store status: {report['status']}")
    elif not report["proposals"]:
        lines.append("(no stored proposals)")
    for proposal in report.get("proposals", []):
        lines.append(
            f"{proposal['proposal_id']} [{proposal['family']}] "
            f"{proposal['review_state']} execution={proposal['execution']} "
            f"— {proposal['summary']}"
        )
        signed = proposal.get("signed_review")
        if signed is None:
            lines.append("  signed review: NOT_RECORDED")
        else:
            lines.append(
                f"  signed review: {signed['status']} / {signed['decision']} "
                f"({signed['signer_count']} reviewers)"
            )
    lines.append("Signed review is not lifecycle approval or execution authorization.")
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
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        return f"EVIDENCE FRESHNESS — read failed closed ({type(exc).__name__})"
    counts = report["counts"]
    lines = [
        "EVIDENCE FRESHNESS — READ ONLY",
        f"Ledger integrity: {'VALID' if report['ledger_integrity']['valid'] else 'INVALID'}",
        f"Records: {report['reported_records']}/{report['total_records']}",
    ]
    lines.extend(f"{name}: {count}" for name, count in counts.items())
    lines.append("UNKNOWN does not mean valid; expiry is operator-declared only.")
    return "\n".join(lines)


def render_evidence_provenance(data_dir: Path) -> str:
    from nexora.evidence_provenance import build_provenance_report

    database = Path(data_dir) / "registry.sqlite3"
    if not database.is_file():
        return "EVIDENCE PROVENANCE — ledger not configured"
    try:
        report = build_provenance_report(database)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        return f"EVIDENCE PROVENANCE — read failed closed ({type(exc).__name__})"
    lines = [
        "EVIDENCE PROVENANCE — READ ONLY",
        f"Ledger integrity: {'VALID' if report['ledger_integrity']['valid'] else 'INVALID'}",
        f"Records: {report['reported_records']}/{report['total_records']}",
    ]
    lines.extend(f"{name}: {count}" for name, count in report["counts"].items())
    lines.append("Declarations are not independent source authentication.")
    return "\n".join(lines)




def render_specification_readiness(_data_dir: Path) -> str:
    """Render exact-source, matrix and settings-policy readiness without mutation."""
    from nexora.readiness import build_spec_status

    try:
        report = build_spec_status()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return f"SPECIFICATION READINESS — unavailable ({type(exc).__name__})"

    source = report.get("source_recovery", {})
    capabilities = source.get("capabilities", {})
    meta_rules = source.get("meta_rules", {})
    matrix = report.get("interaction_matrix", {})
    catalogue = report.get("capability_catalogue", {})
    settings = report.get("settings_authorization", {})
    lines = [
        "SPECIFICATION READINESS — READ ONLY",
        f"Overall: {report.get('status', 'UNKNOWN')}",
        (
            "Capability source: "
            f"{capabilities.get('source_backed', '?')}/"
            f"{capabilities.get('expected', 264)}; "
            f"missing={capabilities.get('missing_count', '?')}"
        ),
        (
            "Meta-rule source: "
            f"{meta_rules.get('source_backed', '?')}/"
            f"{meta_rules.get('expected', 45)}; "
            f"missing={meta_rules.get('missing_count', '?')}"
        ),
        (
            "Catalogue families: "
            f"{catalogue.get('represented_families', '?')}/"
            f"{catalogue.get('expected_families', 40)} represented"
        ),
        (
            "Interaction matrix: "
            f"{matrix.get('declared_pairs', '?')}/"
            f"{matrix.get('possible_pairs', 264 * 264)} declared; "
            f"unknown={matrix.get('unknown_pairs', '?')}"
        ),
        f"Settings authorization: {settings.get('status', 'UNKNOWN')}",
        f"Blockers: {len(report.get('blockers', []))}",
    ]
    for blocker in report.get("blockers", []):
        if isinstance(blocker, dict):
            lines.append(
                f"- {blocker.get('id', 'unknown')}: "
                f"{blocker.get('status', 'BLOCKED')}"
            )
    lines.append(
        "Unknown relationships remain BLOCK_AND_ESCALATE; "
        "no source or policy is inferred."
    )
    lines.append("Execution, settings mutation and policy mutation: DISABLED")
    return "\n".join(lines)


def render_doctor(data_dir: Path) -> str:
    """Render read-only subsystem health diagnostics without initializing storage."""
    from nexora.diagnostics import build_doctor_report

    try:
        report = build_doctor_report(Path(data_dir))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return f"DOCTOR — diagnostic failed closed ({type(exc).__name__})"

    lines = [
        "DOCTOR — READ ONLY",
        f"Overall: {report.get('status', 'UNKNOWN')}",
    ]
    for name, item in report.get("checks", {}).items():
        if isinstance(item, dict):
            lines.append(f"{name}: {item.get('status', 'UNKNOWN')}")
    blockers = report.get("blocking_checks", [])
    gaps = report.get("known_gaps", [])
    lines.append(
        f"Blocking checks: {', '.join(blockers) if blockers else 'none reported'}"
    )
    lines.append(f"Known gaps: {', '.join(gaps) if gaps else 'none reported'}")
    lines.append("Diagnostics do not initialize, repair, enable or execute components.")
    return "\n".join(lines)


def render_family_map(_data_dir: Path) -> str:
    """Render only source-backed family labels and assignments."""
    from nexora.family_inventory import build_family_inventory

    try:
        report = build_family_inventory()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return f"CAPABILITY FAMILY MAP — unavailable ({type(exc).__name__})"

    lines = [
        "CAPABILITY FAMILY MAP — SOURCE-BACKED, READ ONLY",
        f"Inventory: {report.get('status', 'UNKNOWN')}",
        (
            f"Families represented: {report.get('represented_family_count', 0)}/"
            f"{report.get('expected_family_count', 40)}"
        ),
        (
            "Source-backed capability records: "
            f"{report.get('source_backed_capability_count', 0)}"
        ),
    ]
    for family in report.get("families", []):
        code = family.get("family_code", "?")
        state = family.get("family_name_status", "UNKNOWN")
        name = family.get("family_name") or state
        count = family.get("source_backed_capability_count", 0)
        lines.append(f"{code}: {name}; source-backed capabilities={count}")
    lines.append(
        f"Missing capability IDs: {len(report.get('missing_capability_ids', []))}"
    )
    lines.append(
        "Cross-cutting records: "
        f"{report.get('cross_cutting_capability_count', 0)}"
    )
    lines.append("No missing capability is assigned to a family by inference.")
    return "\n".join(lines)


def render_dependency_graph(_data_dir: Path) -> str:
    """Render only explicitly declared directed depends_on relationships."""
    from nexora.governance.validation import build_dependency_graph

    try:
        report = build_dependency_graph()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return f"DEPENDENCY GRAPH — unavailable ({type(exc).__name__})"

    lines = [
        "GOVERNANCE DEPENDENCY GRAPH — READ ONLY",
        f"Status: {report.get('status', 'UNKNOWN')}",
        f"Nodes: {report.get('nodes', 264)}",
        f"Declared relation pairs: {report.get('declared_relation_pairs', 0)}",
        (
            "Unknown relation pairs: "
            f"{report.get('unknown_relation_pairs', 264 * 264)}"
        ),
        f"Explicit dependency edges: {report.get('dependency_edge_count', 0)}",
        f"Dependency cycles: {report.get('cycle_count', 0)}",
    ]
    edges = report.get("dependency_edges", [])
    for edge in edges[:20]:
        lines.append(
            f"{edge.get('capability_id', '?')} -> "
            f"requires {edge.get('requires', '?')}"
        )
    if len(edges) > 20:
        lines.append(f"... {len(edges) - 20} more explicit edges omitted")
    for cycle in report.get("dependency_cycles", [])[:10]:
        lines.append(f"Cycle requiring review: {cycle}")
    lines.append(
        "Only declared directed edges are shown; unknown pairs block and escalate."
    )
    lines.append("No dependency is inferred, repaired or used to enable a capability.")
    return "\n".join(lines)


def render_settings_policy(_data_dir: Path) -> str:
    """Render authorization and rollback gaps without interpreting a policy file."""
    from nexora.readiness import build_settings_policy_status

    try:
        report = build_settings_policy_status()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return f"SETTINGS AUTHORIZATION — unavailable ({type(exc).__name__})"

    lines = [
        "SETTINGS AUTHORIZATION READINESS — READ ONLY",
        f"Policy status: {report.get('status', 'UNKNOWN')}",
        f"Policy file present: {report.get('policy_file_present', False)}",
        (
            "Settings without approved authorization: "
            f"{report.get('settings_count', 0)}"
        ),
    ]
    for name in report.get("settings_without_approved_authorization", []):
        lines.append(f"- {name}: NOT_AUTHORIZED")
    lines.append("Missing governance controls:")
    for control in report.get("missing_policy_controls", []):
        lines.append(f"- {control}")
    proposed = report.get("proposed_settings_not_implemented", [])
    lines.append(f"Proposed settings not implemented: {len(proposed)}")
    for item in proposed:
        if isinstance(item, dict):
            lines.append(f"- {item.get('name', 'unknown')}: NOT_IMPLEMENTED")
    lines.append("Authorization: NOT_EVALUATED; apply: DISABLED; rollback: UNSUPPORTED")
    lines.append("A policy file's presence is not owner approval.")
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
        "5": render_evidence_freshness,
        "6": render_evidence_provenance,
        "7": render_specification_readiness,
        "8": render_doctor,
        "9": render_family_map,
        "10": render_dependency_graph,
        "11": render_settings_policy,
    }
    while True:
        print(MENU, file=output)
        try:
            choice = input_fn("Select a view (1-12): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Leaving read-only dashboard.", file=output)
            return 0
        if choice == "12":
            print("Leaving read-only dashboard.", file=output)
            return 0
        view = views.get(choice)
        if view is None:
            print("Invalid selection; no action taken.", file=output)
            continue
        print("\n" + view(Path(data_dir)) + "\n", file=output)
