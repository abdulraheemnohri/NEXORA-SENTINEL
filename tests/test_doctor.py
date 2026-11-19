from nexora.self_tests import run_kill_switch_self_test


def test_kill_switch_self_test_uses_temporary_marker_only():
    report = run_kill_switch_self_test()

    assert report["status"] == "PASS"
    assert all(report["checks"].values())
    assert report["production_marker_touched"] is False
    assert report["temporary_workspace_cleaned"] is True
    assert report["execution_enabled"] is False
