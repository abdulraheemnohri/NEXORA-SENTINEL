import json
from http.client import HTTPConnection
from threading import Thread

from nexora.terminal.web_dashboard import create_read_only_server


def test_web_dashboard_serves_read_only_views_without_creating_storage(tmp_path):
    data_dir = tmp_path / "missing-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/overview")
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert '"read_only":true' in body
        assert "Autonomy: L0" in body
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_rejects_nonlocal_host_header(tmp_path):
    server = create_read_only_server(tmp_path, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/", headers={"Host": "attacker.example"})
        response = connection.getresponse()
        assert response.status == 400
        assert b"local_host_required" in response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_has_no_mutation_methods(tmp_path):
    data_dir = tmp_path / "missing-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/overview")
        response = connection.getresponse()
        assert response.status == 405
        assert b"method_not_allowed" in response.read()
        connection.close()
        assert not data_dir.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_root_escapes_rendered_content(tmp_path):
    server = create_read_only_server(tmp_path, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert "GET-only diagnostics" in body
        assert "No control or execution endpoints" in body
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)



def test_web_dashboard_exposes_read_only_runtime_page(tmp_path):
    server = create_read_only_server(tmp_path / "no-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/runtime")
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        payload = json.loads(body)
        runtime = json.loads(payload["view"])
        assert runtime["provider"] == "LiteRT-LM"
        assert runtime["network_downloads_enabled"] is False
        assert not (tmp_path / "no-data").exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_exposes_source_backed_self_capabilities(tmp_path):
    server = create_read_only_server(tmp_path / "no-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/self-capabilities")
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        assert response.status == 200
        assert payload["read_only"] is True
        report = json.loads(payload["view"])
        assert report["catalogue"]["source_backed_capabilities"] == 180
        assert report["catalogue"]["missing_capability_count"] == 84
        assert report["meta_rules"]["missing_rule_count"] == 15
        assert report["execution_enabled"] is False
        assert not (tmp_path / "no-data").exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_exposes_family_evaluation_without_creating_storage(tmp_path):
    data_dir = tmp_path / "no-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/family-evaluation?family=O")
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        assert response.status == 200
        assert payload["read_only"] is True
        report = json.loads(payload["view"])
        assert report["scope"] == "source_backed_catalogue_records_only"
        assert report["ledger"]["status"] == "NOT_FOUND"
        assert report["filter"]["family"] == "O"
        assert len(report["families"]) == 1
        assert report["families"][0]["family"] == "O"
        assert report["execution_enabled"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_rejects_duplicate_family_filters(tmp_path):
    server = create_read_only_server(tmp_path, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/family-evaluation?family=O&family=P")
        response = connection.getresponse()
        assert response.status == 400
        assert b"at_most_one_family" in response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_web_dashboard_exposes_recovery_readiness_without_trust_anchor_or_storage(tmp_path):
    data_dir = tmp_path / "no-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/recovery-readiness")
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        report = json.loads(payload["view"])
        assert response.status == 200
        assert payload["read_only"] is True
        assert report["status"] == "NO_BACKUP_DIRECTORY"
        assert report["automatic_restore"] is False
        assert report["automatic_deletion"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)



def test_web_dashboard_exposes_fail_closed_governance_report_without_storage(tmp_path):
    data_dir = tmp_path / "no-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/api/governance")
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        report = json.loads(payload["view"])
        assert response.status == 200
        assert payload["read_only"] is True
        assert report["status"] == "UNPOPULATED_BLOCKING"
        assert report["matrix"]["unknown_pairs"] == 264 * 264
        assert report["controls"]["policy_mutation_enabled"] is False
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
