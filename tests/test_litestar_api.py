import json

import pytest
from litestar.testing import TestClient

from nexora.cli import main
from nexora.litestar_api import ControlPlaneError, create_litestar_app


def test_health_endpoint_returns_explicit_read_only_controls(tmp_path):
    app = create_litestar_app(tmp_path / "missing-data")

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    payload = response.json()
    assert payload["read_only"] is True
    assert payload["view"]["mode"] == "READ_ONLY_DIAGNOSTICS"
    assert all(value is False for value in payload["controls"].values())


def test_specification_validation_endpoint_reports_partial_without_granting_authority(tmp_path):
    app = create_litestar_app(tmp_path / "missing-data")

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/v1/specification/validation")

    assert response.status_code == 200
    payload = response.json()
    assert payload["read_only"] is True
    assert payload["view"]["status"] == "VALID_PARTIAL_BLOCKED"
    assert payload["view"]["complete"] is False
    assert payload["view"]["controls"]["execution_enabled"] is False
    assert payload["view"]["controls"]["policy_mutation_enabled"] is False


def test_proposals_endpoint_does_not_initialize_missing_storage(tmp_path):
    data_dir = tmp_path / "not-created"
    app = create_litestar_app(data_dir)

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/v1/proposals")

    assert response.status_code == 200
    payload = response.json()
    assert payload["read_only"] is True
    assert payload["view"]["status"] == "NOT_CONFIGURED"
    assert payload["view"]["count"] == 0
    assert not data_dir.exists()


def test_control_plane_has_no_post_handler_or_mutation_route(tmp_path):
    data_dir = tmp_path / "not-created"
    app = create_litestar_app(data_dir)

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.post("/api/v1/proposals", json={"approve": True})

    assert response.status_code == 405
    assert not data_dir.exists()


def test_control_plane_rejects_untrusted_host_header(tmp_path):
    app = create_litestar_app(tmp_path / "missing-data")

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.get("/healthz", headers={"host": "attacker.example"})

    assert response.status_code == 400


def test_control_plane_rejects_symlink_data_root(tmp_path):
    target = tmp_path / "real-data"
    target.mkdir()
    link = tmp_path / "linked-data"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")

    with pytest.raises(ControlPlaneError, match="real_directory"):
        create_litestar_app(link)


def test_api_cli_rejects_invalid_port_without_starting_server(capsys):
    result = main(["api", "--port", "0"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 2
    assert payload["started"] is False
    assert payload["error"] == "control_plane_port_out_of_range"
    assert payload["execution_enabled"] is False
