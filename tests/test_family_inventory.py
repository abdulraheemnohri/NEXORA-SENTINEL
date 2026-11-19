import json

import pytest

from nexora.family_inventory import FamilyInventoryError, build_family_inventory


def _write(path, capabilities):
    path.write_text(json.dumps({"capabilities": capabilities}), encoding="utf-8")


def test_family_inventory_reports_all_40_codes_without_assigning_missing_ids(tmp_path):
    catalog = tmp_path / "catalog.json"
    _write(catalog, [
        {"id": 85, "name": "Observation", "family": "A",
         "family_name": "Cognitive", "source": "Original Addendum",
         "status": "specified"},
        {"id": 86, "name": "Diagnostics", "family": "B",
         "family_name": "Operational", "source": "Original Addendum",
         "status": "specified"},
        {"id": 87, "name": "Cross-cutting", "family": "CROSS-CUTTING",
         "family_name": "Cross-cutting", "source": "Original Addendum",
         "status": "specified"},
    ])

    report = build_family_inventory(catalog)

    assert len(report["families"]) == 40
    assert report["represented_family_count"] == 2
    assert report["source_backed_capability_count"] == 3
    assert report["missing_capability_ids"][:3] == [1, 2, 3]
    assert report["cross_cutting_capability_ids"] == [87]
    assert report["unrepresented_family_codes"]
    assert report["controls"]["family_assignment_inference_enabled"] is False
    assert report["controls"]["relationship_inference_enabled"] is False
    assert report["controls"]["execution_enabled"] is False


def test_family_inventory_preserves_conflicting_source_names_as_conflict(tmp_path):
    catalog = tmp_path / "catalog.json"
    _write(catalog, [
        {"id": 85, "name": "One", "family": "A", "family_name": "Cognitive",
         "source": "Source One", "status": "specified"},
        {"id": 86, "name": "Two", "family": "A", "family_name": "Cognition",
         "source": "Source Two", "status": "specified"},
    ])

    report = build_family_inventory(catalog)
    family = next(row for row in report["families"] if row["family_code"] == "A")

    assert "A" in report["conflicting_family_name_codes"]
    assert family["family_name"] is None
    assert family["family_name_status"] == "CONFLICTING_SOURCE_NAMES"


def test_family_inventory_rejects_duplicate_capability_ids(tmp_path):
    catalog = tmp_path / "catalog.json"
    row = {"id": 85, "name": "One", "family": "A", "family_name": "Cognitive",
           "source": "Source", "status": "specified"}
    _write(catalog, [row, row])

    with pytest.raises(FamilyInventoryError, match="capability_id_duplicate"):
        build_family_inventory(catalog)


def test_family_inventory_rejects_missing_source_name(tmp_path):
    catalog = tmp_path / "catalog.json"
    _write(catalog, [
        {"id": 85, "name": "One", "family": "A", "family_name": "Cognitive",
         "source": "", "status": "specified"},
    ])

    with pytest.raises(FamilyInventoryError, match="capability_source_missing"):
        build_family_inventory(catalog)
