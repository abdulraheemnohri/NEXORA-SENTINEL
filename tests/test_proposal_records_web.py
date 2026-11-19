import json
from http.client import HTTPConnection
from threading import Thread

from nexora.self_families import SelfFamily, SelfFamilyManager
from nexora.self_family_store import SelfFamilyProposalStore
from nexora.terminal.web_dashboard import create_read_only_server


def test_structured_proposal_api_returns_review_history_without_mutation(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    database = data_dir / "registry.sqlite3"
    store = SelfFamilyProposalStore(database)
    proposal = SelfFamilyManager().propose(
        SelfFamily.OBSERVATION,
        "Read-only operator state inventory",
        evidence=("source:operator",),
    )
    submitted = store.submit(proposal)
    original = database.read_bytes()

    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "GET",
            f"/api/proposal-records?proposal_id={submitted['proposal_id']}",
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        report = payload["view"]

        assert response.status == 200
        assert payload["read_only"] is True
        assert report["status"] == "VALID"
        assert report["proposals"][0]["proposal_id"] == submitted["proposal_id"]
        assert report["proposals"][0]["execution"] == "DISABLED"
        assert report["proposals"][0]["authorization"] == "NOT_GRANTED"
        assert database.read_bytes() == original
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_structured_proposal_api_missing_store_does_not_create_database(tmp_path):
    data_dir = tmp_path / "missing-data"
    server = create_read_only_server(data_dir, 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/api/proposal-records")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert payload["view"]["status"] == "NOT_CONFIGURED"
        assert not data_dir.exists()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_structured_proposal_api_rejects_duplicate_and_invalid_filters(tmp_path):
    server = create_read_only_server(tmp_path / "missing-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/api/proposal-records?limit=1&limit=2")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 400
        assert payload["error"] == "invalid_proposal_query"

        connection.request("GET", "/api/proposal-records?limit=-2")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 400
        assert payload["error"] == "invalid_proposal_query"

        connection.request("GET", "/api/proposal-records?proposal_id=../../x")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 400
        assert payload["error"] == "invalid_proposal_query"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_proposal_records_dashboard_card_is_rendered(tmp_path):
    server = create_read_only_server(tmp_path / "missing-data", 0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Structured proposal records and review history" in body
        assert "/api/proposal-records" in body
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
