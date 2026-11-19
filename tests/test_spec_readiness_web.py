import json
from http.client import HTTPConnection
from threading import Thread

from nexora.terminal.web_dashboard import create_read_only_server


def _get(server, path):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def test_spec_status_api_exposes_blockers_without_creating_data(tmp_path):
    data_dir = tmp_path / "must-not-be-created"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _get(server, "/api/spec-status")
        report = json.loads(payload["view"])
        assert status == 200
        assert payload["read_only"] is True
        assert report["status"] == "BLOCKED"
        assert report["source_recovery"]["capabilities"]["missing_ids"] == list(range(1, 85))
        assert report["source_recovery"]["meta_rules"]["missing_ids"] == list(range(1, 16))
        assert report["interaction_matrix"]["unknown_pairs"] == 264 * 264
        assert report["controls"]["execution_enabled"] is False
        assert not data_dir.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_settings_policy_api_never_treats_present_file_as_approved(tmp_path, monkeypatch):
    policy = tmp_path / "settings_authorization.json"
    policy.write_text('{"approved":true,"allow_all":true}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings_authorization.json").write_text(
        policy.read_text(encoding="utf-8"), encoding="utf-8"
    )
    data_dir = tmp_path / "must-not-be-created"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _get(server, "/api/settings-policy")
        report = json.loads(payload["view"])
        assert status == 200
        assert payload["read_only"] is True
        assert report["status"] == "PRESENT_REQUIRES_INDEPENDENT_REVIEW"
        assert report["authorization"] == "NOT_EVALUATED"
        assert report["apply_supported"] is False
        assert report["rollback_supported"] is False
        assert not data_dir.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
