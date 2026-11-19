import json
from http.client import HTTPConnection
from threading import Thread

from nexora.terminal.web_dashboard import create_read_only_server


def test_doctor_api_is_read_only_and_does_not_initialize_storage(tmp_path):
    data_dir = tmp_path / "not-created"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/doctor")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        report = json.loads(payload["view"])

        assert response.status == 200
        assert payload["read_only"] is True
        assert report["read_only"] is True
        assert report["controls"]["storage_created"] is False
        assert report["controls"]["execution_enabled"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
