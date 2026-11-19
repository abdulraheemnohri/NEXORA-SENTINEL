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


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_control_plane_rejects_all_mutating_http_methods(tmp_path, method):
    data_dir = tmp_path / "not-created"
    app = create_litestar_app(data_dir)

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        request = getattr(client, method)
        response = request("/api/v1/proposals")

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



def test_api_launcher_hard_binds_to_ipv4_loopback(tmp_path, monkeypatch):
    import uvicorn

    from nexora.litestar_api import run_litestar_api

    captured = {}

    def fake_run(app, **kwargs):
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    run_litestar_api(tmp_path / "missing-data", port=8765)

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8765
    assert captured["access_log"] is False
    assert not (tmp_path / "missing-data").exists()



def test_proposal_detail_route_reads_one_existing_proposal(tmp_path):
    from nexora.self_families import SelfFamily, SelfFamilyManager
    from nexora.self_family_store import SelfFamilyProposalStore

    data_dir = tmp_path / "data"
    database = data_dir / "registry.sqlite3"
    proposal = SelfFamilyManager().propose(
        SelfFamily.OBSERVATION,
        "Read-only local inventory",
        evidence=("source:operator",),
    )
    submitted = SelfFamilyProposalStore(database).submit(proposal)
    app = create_litestar_app(data_dir)

    with TestClient(app=app, base_url="http://127.0.0.1") as client:
        response = client.get(f"/api/v1/proposals/{submitted['proposal_id']}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["read_only"] is True
    assert payload["view"]["status"] == "VALID"
    assert payload["view"]["count"] == 1
    record = payload["view"]["proposals"][0]
    assert record["proposal_id"] == submitted["proposal_id"]
    assert record["execution"] == "DISABLED"
    assert record["authorization"] == "NOT_GRANTED"
    assert payload["controls"]["tool_execution_enabled"] is False



def test_provider_and_model_endpoints_are_read_only_and_do_not_create_model_storage(tmp_path):
    app = create_litestar_app(tmp_path / "missing-data")
    model_dir = tmp_path / "models"
    config = tmp_path / "models.yaml"
    config.write_text(
        "version: 1\n"
        "runtime_enabled: false\n"
        "network_downloads_enabled: false\n"
        "default_provider: null\n"
        "models: []\n",
        encoding="utf-8",
    )

    from nexora.intelligence import model_catalog

    original = model_catalog._DEFAULT_CONFIG
    model_catalog._DEFAULT_CONFIG = config
    try:
        with TestClient(app=app, base_url="http://127.0.0.1") as client:
            provider_response = client.get("/api/v1/providers")
            model_response = client.get("/api/v1/models")
    finally:
        model_catalog._DEFAULT_CONFIG = original

    assert provider_response.status_code == 200
    assert provider_response.json()["view"]["automatic_execution"] is False
    assert model_response.status_code == 200
    assert model_response.json()["view"]["status"] == "EMPTY"
    assert model_response.json()["controls"]["tool_execution_enabled"] is False
    assert not model_dir.exists()
