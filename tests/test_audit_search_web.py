import json
from http.client import HTTPConnection
from threading import Thread

from nexora._oversight_impl import AuditLog
from nexora.terminal.web_dashboard import create_read_only_server


def test_audit_search_api_filters_verified_log_without_mutation(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    path = data_dir / "audit.jsonl"
    log = AuditLog(path)
    log.append("proposal.created", {"id": "a"})
    log.append("policy.denied", {"reason": "unknown"})
    original = path.read_bytes()

    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/audit-search?event=proposal.created")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        report = payload["view"]

        assert response.status == 200
        assert payload["read_only"] is True
        assert report["valid"] is True
        assert report["matched_entries"] == 1
        assert report["results"][0]["event"] == "proposal.created"
        assert path.read_bytes() == original
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_audit_search_api_rejects_duplicate_filter_parameters(tmp_path):
    server = create_read_only_server(tmp_path / "missing-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/audit-search?limit=2&limit=3")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))

        assert response.status == 400
        assert payload["error"] == "invalid_audit_search_query"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
