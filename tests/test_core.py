import json
from pathlib import Path

from nexora.catalog import status
from nexora.oversight import AuditLog, KillSwitch, PolicyKernel

def test_audit_chain_and_tamper_detection(tmp_path):
    path=tmp_path/"audit.jsonl"; log=AuditLog(path); log.append("a",{"x":1}); log.append("b",{"x":2})
    assert log.verify()
    row=json.loads(path.read_text().splitlines()[0]); row["payload"]["x"]=7
    path.write_text(json.dumps(row)+"\n"+path.read_text().splitlines()[1]+"\n")
    assert not log.verify()

def test_corrupt_audit_refuses_append(tmp_path):
    p=tmp_path/"audit.jsonl"; p.write_text("{bad\n")
    try: AuditLog(p).append("x",{})
    except RuntimeError: pass
    else: assert False

def test_unknown_action_denied(tmp_path):
    assert not PolicyKernel(KillSwitch(tmp_path/"KILL")).evaluate("shell.exec","low").allowed

def test_approval_and_kill_switch(tmp_path):
    stop=KillSwitch(tmp_path/"KILL"); kernel=PolicyKernel(stop)
    assert not kernel.evaluate("filesystem.read","medium").allowed
    assert kernel.evaluate("filesystem.read","medium",True).allowed
    stop.engage("test"); assert not kernel.evaluate("system.status","low").allowed

def test_runtime_registration_locked(tmp_path):
    try: PolicyKernel(KillSwitch(tmp_path/"KILL")).register_action("x","low")
    except PermissionError: pass
    else: assert False

def test_catalog_incomplete_is_explicit():
    result = status()
    assert result["expected_capabilities"] == 264
    assert result["expected_families"] == 40
    assert result["registered_capabilities"] == 180
    assert not result["complete"]


def test_addendum_v_capabilities_are_registered():
    catalog_path = Path(__file__).resolve().parents[1] / "spec" / "capability_catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    rows = {item["id"]: item for item in catalog["capabilities"]}
    assert set(range(216, 265)).issubset(rows)
    assert rows[216]["family"] == "AG"
    assert rows[264]["family"] == "AN"
    assert all(rows[i].get("mechanism") and rows[i].get("gate") for i in range(216, 265))


def test_addendum_v_meta_rules_are_registered():
    rules_path = Path(__file__).resolve().parents[1] / "spec" / "meta_rules.json"
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in rules["rules"]}
    assert set(range(36, 46)).issubset(by_id)
    assert all(by_id[i]["mutable_by_agent"] is False for i in range(36, 46))


def test_interaction_matrix_targets_264():
    matrix_path = Path(__file__).resolve().parents[1] / "spec" / "interaction_matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    assert matrix["dimensions"] == [264, 264]
    assert matrix["capability_id_range"] == [1, 264]
    assert matrix["entries"] == []
