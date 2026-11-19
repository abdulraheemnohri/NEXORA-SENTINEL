from io import StringIO

from nexora.terminal.dashboard import (
    render_overview,
    render_proposals,
    render_registry,
    run_read_only_tui,
)


def test_tui_is_read_only_and_exits_cleanly(tmp_path):
    output = StringIO()
    answers = iter(["1", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"])
    assert run_read_only_tui(
        tmp_path, input_fn=lambda _: next(answers), output=output
    ) == 0
    text = output.getvalue()
    assert "SYSTEM OVERVIEW" in text
    assert "SELF-FAMILY PROPOSALS" in text
    assert "CAPABILITY REGISTRY" in text
    assert "EVIDENCE FRESHNESS" in text
    assert "EVIDENCE PROVENANCE" in text
    assert "SPECIFICATION READINESS" in text
    assert "DOCTOR — READ ONLY" in text
    assert "CAPABILITY FAMILY MAP" in text
    assert "GOVERNANCE DEPENDENCY GRAPH" in text
    assert "SETTINGS AUTHORIZATION READINESS" in text
    assert not (tmp_path / "registry.sqlite3").exists()


def test_registry_and_proposal_views_do_not_create_database(tmp_path):
    assert "not initialized" in render_registry(tmp_path)
    assert "no stored proposals" in render_proposals(tmp_path)
    assert not (tmp_path / "registry.sqlite3").exists()


def test_overview_reports_safe_defaults(tmp_path):
    result = render_overview(tmp_path)
    assert "Emergency stop: clear" in result
    assert "Autonomy: L0" in result


def test_dashboard_does_not_create_audit_or_data_directory(tmp_path):
    from nexora.terminal.dashboard import render_audit

    absent = tmp_path / "not-created"
    assert "Entries: 0" in render_audit(absent)
    assert not absent.exists()



def test_extended_tui_reports_are_read_only_and_fail_closed(tmp_path):
    from nexora.terminal.dashboard import (
        render_dependency_graph,
        render_doctor,
        render_family_map,
        render_settings_policy,
        render_specification_readiness,
    )

    specification = render_specification_readiness(tmp_path)
    assert "SPECIFICATION READINESS — READ ONLY" in specification
    assert "BLOCKED" in specification

    assert "DOCTOR — READ ONLY" in render_doctor(tmp_path)
    assert "CAPABILITY FAMILY MAP" in render_family_map(tmp_path)
    assert "GOVERNANCE DEPENDENCY GRAPH" in render_dependency_graph(tmp_path)
    assert "SETTINGS AUTHORIZATION READINESS" in render_settings_policy(tmp_path)
    assert not (tmp_path / "registry.sqlite3").exists()
