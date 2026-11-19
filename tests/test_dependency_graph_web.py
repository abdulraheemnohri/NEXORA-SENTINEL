import json
from http.client import HTTPConnection
from threading import Thread

from nexora.terminal.web_dashboard import create_read_only_server


def test_dependency_graph_api_is_read_only_and_preserves_unknown_pairs(tmp_path):
    data_dir = tmp_path / "not-created"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/dependency-graph")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        report = json.loads(payload["view"])

        assert response.status == 200
        assert payload["read_only"] is True
        assert report["status"] == "UNPOPULATED_BLOCKING"
        assert report["unknown_relation_pairs"] == 264 * 264
        assert report["dependency_edges"] == []
        assert report["execution_enabled"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
