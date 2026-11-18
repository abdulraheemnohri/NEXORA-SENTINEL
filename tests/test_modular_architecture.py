from pathlib import Path

import pytest

from nexora.capabilities.families import FAMILY_CODES, validate_family
from nexora.core.agent import AgentKernel
from nexora.evolution.canary import evaluate_canary
from nexora.governance.deadlock import has_cycle
from nexora.governance.interaction_matrix import InteractionMatrix
from nexora.memory.provenance import ProvenanceRecord
from nexora.oversight.kill_switch import KillSwitch
from nexora.oversight.policy_kernel import PolicyKernel
from nexora.runtime.executor import ExecutionDisabled, execute
from nexora.terminal.command_parser import parse_command
from nexora.terminal.sanitizer import sanitize_text


def test_family_codes_match_forty_canonical_families():
    assert len(FAMILY_CODES) == 40
    assert FAMILY_CODES[-14:] == tuple("A" + x for x in "ABCDEFGHIJKLMN")
    assert validate_family("AN") == "AN"
    with pytest.raises(ValueError):
        validate_family("AO")


def test_unknown_interaction_is_blocked():
    path = Path(__file__).resolve().parents[1] / "spec" / "interaction_matrix.json"
    matrix = InteractionMatrix(path)
    assert matrix.relation(1, 2) == {"known": False, "decision": "BLOCK_AND_ESCALATE"}


def test_wait_graph_cycle_and_unknown_node():
    assert has_cycle({"a": ["b"], "b": ["a"]})
    assert not has_cycle({"a": ["b"], "b": []})
    with pytest.raises(ValueError, match="wait_graph_unknown_node"):
        has_cycle({"a": ["missing"]})


def test_agent_proposes_but_does_not_execute(tmp_path):
    policy = PolicyKernel(KillSwitch(tmp_path / "KILL"))
    result = AgentKernel(policy).propose("Check status", "system.status", "low")
    assert result.plan.status == "PROPOSED_FOR_REVIEW"
    assert result.decision["allowed"] is True


def test_execution_boundary_is_explicitly_disabled():
    with pytest.raises(ExecutionDisabled):
        execute("echo unsafe")


def test_provenance_digest_and_canary_gate():
    record = ProvenanceRecord.from_content("doc:1", b"source")
    assert record.verify(b"source")
    assert not record.verify(b"changed")
    assert evaluate_canary(sample_count=100, failures=0)["eligible_for_human_review"]
    assert not evaluate_canary(sample_count=100, failures=1)["eligible_for_human_review"]


def test_terminal_parser_blocks_shell_syntax_and_control_text():
    assert parse_command("status") == ["status"]
    with pytest.raises(ValueError, match="shell_metacharacter_denied"):
        parse_command("status; rm -rf /")
    with pytest.raises(ValueError, match="shell_metacharacter_denied"):
        parse_command("status\nkill")
    assert sanitize_text("hello\nworld") == "hello\nworld"
    with pytest.raises(ValueError, match="terminal_control_character_denied"):
        sanitize_text("bad\x00text")


def test_output_evaluation_is_bounded():
    from nexora.intelligence.evaluation import evaluate_output

    assert evaluate_output("valid").accepted_for_review
    assert not evaluate_output("x" * 10, max_chars=5).accepted_for_review
