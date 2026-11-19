import json
from http.client import HTTPConnection
from threading import Thread

from nexora.terminal.web_dashboard import create_read_only_server


def test_family_map_api_lists_40_source_backed_family_slots_read_only(tmp_path):
    data_dir = tmp_path / "no-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/api/family-map")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        report = json.loads(payload["view"])

        assert response.status == 200
        assert payload["read_only"] is True
        assert len(report["families"]) == 40
        assert report["status"] == "SOURCE_INVENTORY_REVIEW_REQUIRED"
        assert report["controls"]["family_assignment_inference_enabled"] is False
        assert report["controls"]["execution_enabled"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_family_map_dashboard_card_is_rendered(tmp_path):
    server = create_read_only_server(tmp_path / "no-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Source-backed 40-family explorer" in body
        assert "/api/family-map" in body
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
