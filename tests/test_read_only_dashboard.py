from io import StringIO

from nexora.terminal.dashboard import (
    render_overview,
    render_proposals,
    render_registry,
    run_read_only_tui,
)


def test_tui_is_read_only_and_exits_cleanly(tmp_path):
    output = StringIO()
    answers = iter(["1", "3", "4", "5"])
    assert run_read_only_tui(
        tmp_path, input_fn=lambda _: next(answers), output=output
    ) == 0
    text = output.getvalue()
    assert "SYSTEM OVERVIEW" in text
    assert "SELF-FAMILY PROPOSALS" in text
    assert "CAPABILITY REGISTRY" in text
    assert not (tmp_path / "registry.sqlite3").exists()


def test_registry_and_proposal_views_do_not_create_database(tmp_path):
    assert "not initialized" in render_registry(tmp_path)
    assert "no stored proposals" in render_proposals(tmp_path)
    assert not (tmp_path / "registry.sqlite3").exists()


def test_overview_reports_safe_defaults(tmp_path):
    result = render_overview(tmp_path)
    assert "Emergency stop: clear" in result
    assert "Autonomy: L0" in result
