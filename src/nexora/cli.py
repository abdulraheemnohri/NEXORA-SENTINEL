"""NEXORA Sentinel CLI."""
import argparse,json
from pathlib import Path
from nexora.oversight import AuditLog,KillSwitch,PolicyKernel
from nexora.catalog import status

def main(argv=None):
    p=argparse.ArgumentParser(prog="nexora"); p.add_argument("--data-dir",type=Path,default=Path("data"))
    s=p.add_subparsers(dest="cmd",required=True)
    for name in ("status","catalog-check","kill","resume","audit"): s.add_parser(name)
    c=s.add_parser("check"); c.add_argument("action"); c.add_argument("--risk",choices=("low","medium","high","critical"),default="medium"); c.add_argument("--approved",action="store_true")
    a=p.parse_args(argv); a.data_dir.mkdir(parents=True,exist_ok=True)
    log=AuditLog(a.data_dir/"audit.jsonl"); stop=KillSwitch(a.data_dir/"KILL"); policy=PolicyKernel(stop)
    if a.cmd=="status":
        ok=log.verify(); print(json.dumps({"version":"0.1.0","kill_switch":"engaged" if stop.is_engaged() else "clear","audit_valid":ok,"catalog":status(),"autonomy_default":"L0"},indent=2)); return 0 if ok else 2
    if a.cmd=="catalog-check":
        result=status(); print(json.dumps(result,indent=2)); return 0 if result["complete"] else 2
    if a.cmd=="kill": stop.engage(); log.append("kill.engaged",{"source":"cli"}); print("Emergency stop engaged."); return 0
    if a.cmd=="resume": stop.clear(); log.append("kill.cleared",{"human_initiated":True}); print("Emergency stop cleared."); return 0
    if a.cmd=="audit": print(json.dumps({"valid":log.verify(),"entries":log.entries()},indent=2)); return 0 if log.verify() else 2
    decision=policy.evaluate(a.action,a.risk,a.approved); record=log.append("policy.decision",decision.to_dict()); print(json.dumps(decision.to_dict(),indent=2)); return 0 if decision.allowed else 3

if __name__=="__main__": raise SystemExit(main())
