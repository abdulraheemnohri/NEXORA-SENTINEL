import json

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
    result=status(); assert result["expected_capabilities"]==264 and not result["complete"]
