import json
import sqlite3

import pytest

from nexora.memory.long_term import MemoryStore


def test_memory_add_search_and_provenance(tmp_path):
    store = MemoryStore(tmp_path / "memory.sqlite3")
    memory_id = store.add("NEXORA must fail closed on unknown permissions", source="operator-note")
    assert memory_id == 1
    results = store.search("fail closed permissions")
    assert len(results) == 1
    assert results[0]["id"] == memory_id
    assert results[0]["provenance_valid"] is True
    assert store.get(memory_id)["source"] == "operator-note"


def test_memory_search_requires_all_terms_and_is_bounded(tmp_path):
    store = MemoryStore(tmp_path / "memory.sqlite3")
    store.add("Android Debian local runtime", source="test")
    store.add("Windows desktop runtime", source="test")
    assert [row["content"] for row in store.search("Android Debian")] == [
        "Android Debian local runtime"
    ]
    with pytest.raises(ValueError, match="memory_limit_out_of_range"):
        store.search("runtime", limit=0)
    with pytest.raises(ValueError, match="memory_query_has_no_search_terms"):
        store.search("!?")


def test_memory_tombstone_hides_record_but_preserves_audit(tmp_path):
    store = MemoryStore(tmp_path / "memory.sqlite3")
    memory_id = store.add("A record to retire", source="operator")
    store.delete(memory_id, reason="Operator requested removal from retrieval")
    assert store.get(memory_id) is None
    deleted = store.get(memory_id, include_deleted=True)
    assert deleted["active"] is False
    assert deleted["event_reason"] == "Operator requested removal from retrieval"
    assert store.search("record retire") == []
    with pytest.raises(ValueError, match="memory_already_deleted"):
        store.delete(memory_id, reason="duplicate")


def test_memory_records_and_events_are_append_only(tmp_path):
    path = tmp_path / "memory.sqlite3"
    store = MemoryStore(path)
    memory_id = store.add("Immutable record", source="test")
    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append_only"):
            db.execute("UPDATE memory_records SET content='changed' WHERE id=?", (memory_id,))
        with pytest.raises(sqlite3.IntegrityError, match="append_only"):
            db.execute("DELETE FROM memory_events WHERE memory_id=?", (memory_id,))


def test_read_only_memory_open_does_not_create_database(tmp_path):
    path = tmp_path / "missing" / "memory.sqlite3"
    with pytest.raises(FileNotFoundError, match="memory_database_not_found"):
        MemoryStore(path, create=False)
    assert not path.parent.exists()


def test_legacy_memory_records_are_imported_once(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE memories(id INTEGER PRIMARY KEY, content TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT)"
        )
        db.execute(
            "INSERT INTO memories(id,content,source) VALUES(1,'legacy record','legacy-source')"
        )
    store = MemoryStore(path)
    assert store.get(1)["provenance_valid"] is True
    MemoryStore(path)
    assert len(store.recent()) == 1



def test_memory_tombstone_cli_reports_no_physical_erasure(tmp_path, capsys):
    from nexora.cli import main

    data_dir = tmp_path / "data"
    store = MemoryStore(data_dir / "memory.sqlite3")
    memory_id = store.add("CLI tombstone test", source="test")
    assert main([
        "--data-dir", str(data_dir), "memory-tombstone", str(memory_id),
        "--reason", "operator request", "--confirm",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tombstoned"] is True
    assert result["physical_erasure"] is False
    assert store.get(memory_id) is None


def test_memory_delete_compatibility_alias_reports_no_physical_erasure(tmp_path, capsys):
    from nexora.cli import main

    data_dir = tmp_path / "data"
    store = MemoryStore(data_dir / "memory.sqlite3")
    memory_id = store.add("CLI legacy alias test", source="test")
    assert main([
        "--data-dir", str(data_dir), "memory-delete", str(memory_id),
        "--reason", "operator request", "--confirm",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tombstoned"] is True
    assert result["physical_erasure"] is False
