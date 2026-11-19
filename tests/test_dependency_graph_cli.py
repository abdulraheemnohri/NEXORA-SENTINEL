import json

from nexora.cli import main


def test_governance_dependencies_cli_reports_unknown_edges_as_blocking(capsys):
    result = main(["governance-dependencies"])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] == "UNPOPULATED_BLOCKING"
    assert report["unknown_relation_pairs"] == 264 * 264
    assert report["dependency_edges"] == []
    assert report["relationship_inference_enabled"] is False
    assert report["execution_enabled"] is False
