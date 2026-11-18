"""Evidence-bound conflict arbitration; outcomes are proposals for human review only."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexora.governance.deadlock import has_cycle
from nexora.governance.validation import DEFAULT_MATRIX, inspect_relation
from nexora.lifecycle import Precedence, resolve_conflict


class ArbitrationError(ValueError):
    """Malformed arbitration input; fail closed."""


_PRIORITY = {
    "SAFETY": Precedence.SAFETY,
    "GOVERNANCE": Precedence.GOVERNANCE,
    "OPERATIONAL": Precedence.OPERATIONAL,
    "CONVENIENCE": Precedence.CONVENIENCE,
}


def arbitrate_conflict(
    left_id: int,
    right_id: int,
    *,
    left_priority: str,
    right_priority: str,
    matrix_path: Path = DEFAULT_MATRIX,
    wait_graph: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Propose a precedence winner only for an explicitly declared conflict.

    This function never authorizes, schedules, executes, suppresses, or mutates
    either proposal. A human review remains mandatory even when priorities differ.
    """
    if type(left_id) is not int or type(right_id) is not int:
        raise ArbitrationError("capability_ids_must_be_integers")
    if not (1 <= left_id <= 264 and 1 <= right_id <= 264) or left_id == right_id:
        raise ArbitrationError("capability_pair_invalid")
    if not isinstance(left_priority, str) or not isinstance(right_priority, str):
        raise ArbitrationError("priority_must_be_string")

    relation = inspect_relation(left_id, right_id, matrix_path)
    base = {
        "left_capability_id": left_id,
        "right_capability_id": right_id,
        "relation": relation,
        "human_review_required": True,
        "proposal_authorized": False,
        "execution_enabled": False,
        "lifecycle_mutation": False,
    }
    if not relation["known"]:
        return {
            **base,
            "decision": "BLOCK_AND_ESCALATE",
            "reason": "relationship_unknown",
            "winner_proposal": None,
        }
    if relation.get("entry", {}).get("relation") != "conflicts":
        return {
            **base,
            "decision": "BLOCK_AND_ESCALATE",
            "reason": "explicit_conflicts_relation_required",
            "winner_proposal": None,
        }

    graph = wait_graph if wait_graph is not None else {}
    if not isinstance(graph, dict):
        raise ArbitrationError("wait_graph_must_be_object")
    if any(
        not isinstance(node, str)
        or not isinstance(edges, list)
        or any(not isinstance(edge, str) for edge in edges)
        for node, edges in graph.items()
    ):
        raise ArbitrationError("wait_graph_invalid")
    try:
        deadlock = has_cycle(graph)
    except ValueError as exc:
        return {
            **base,
            "decision": "BLOCK_AND_ESCALATE",
            "reason": str(exc),
            "winner_proposal": None,
            "deadlock_detected": None,
        }
    if deadlock:
        return {
            **base,
            "decision": "BLOCK_AND_ESCALATE",
            "reason": "wait_graph_deadlock_detected",
            "winner_proposal": None,
            "deadlock_detected": True,
        }

    left = _PRIORITY.get(left_priority)
    right = _PRIORITY.get(right_priority)
    priorities = {}
    if left is not None:
        priorities["left"] = left
    if right is not None:
        priorities["right"] = right
    decision = resolve_conflict("left", "right", priorities)
    if not decision.allowed:
        return {
            **base,
            "decision": "BLOCK_AND_ESCALATE",
            "reason": decision.reason,
            "winner_proposal": None,
            "deadlock_detected": False,
        }
    return {
        **base,
        "decision": "PRECEDENCE_WINNER_PROPOSED_REVIEW_REQUIRED",
        "reason": decision.reason,
        "winner_proposal": (
            left_id if decision.winner == "left" else right_id
        ),
        "deadlock_detected": False,
        "priority_order": ["SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"],
    }


def load_wait_graph(path: Path | None) -> dict[str, list[str]]:
    """Load a declared wait-for graph from JSON; absent means no declared waits."""
    if path is None:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArbitrationError("wait_graph_read_failed") from exc
    if not isinstance(payload, dict):
        raise ArbitrationError("wait_graph_must_be_object")
    return payload
