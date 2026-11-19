import json

from nexora.cli import main


def test_family_map_cli_reports_source_gaps_without_writing(tmp_path, capsys):
    data_dir = tmp_path / "no-data"
    result = main(["--data-dir", str(data_dir), "family-map"])
    report = json.loads(capsys.readouterr().out)

    assert result == 3
    assert report["status"] == "SOURCE_INVENTORY_REVIEW_REQUIRED"
    assert len(report["families"]) == 40
    assert report["missing_capability_ids"][:3] == [1, 2, 3]
    assert report["controls"]["family_assignment_inference_enabled"] is False
    assert report["controls"]["execution_enabled"] is False
    assert not data_dir.exists()
