"""NEXORA Sentinel command-line interface."""
import argparse
import json
from pathlib import Path

from nexora.backup import create_backup, restore_backup, verify_backup
from nexora.catalog import status
from nexora.oversight import AuditLog, KillSwitch, PolicyKernel
from nexora.registry import CapabilityRegistry


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nexora")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "catalog-check", "kill", "resume", "audit", "registry-init"):
        sub.add_parser(name)
    check = sub.add_parser("check")
    check.add_argument("action")
    check.add_argument("--risk", choices=("low", "medium", "high", "critical"), default="medium")
    check.add_argument("--approved", action="store_true")
    backup = sub.add_parser("backup")
    backup.add_argument("destination", nargs="?", type=Path)
    verify = sub.add_parser("verify-backup")
    verify.add_argument("backup", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("destination", type=Path)

    args = parser.parse_args(argv)
    args.data_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(args.data_dir / "audit.jsonl")
    stop = KillSwitch(args.data_dir / "KILL")
    policy = PolicyKernel(stop)

    if args.cmd == "status":
        valid = log.verify()
        print(json.dumps({
            "version": "0.2.0",
            "kill_switch": "engaged" if stop.is_engaged() else "clear",
            "audit_valid": valid,
            "catalog": status(),
            "autonomy_default": "L0",
        }, indent=2))
        return 0 if valid else 2
    if args.cmd == "catalog-check":
        result = status()
        print(json.dumps(result, indent=2))
        return 0 if result["complete"] else 2
    if args.cmd == "kill":
        stop.engage()
        log.append("kill.engaged", {"source": "cli"})
        print("Emergency stop engaged.")
        return 0
    if args.cmd == "resume":
        log.append("kill.cleared", {"human_initiated": True})
        stop.clear()
        print("Emergency stop cleared.")
        return 0
    if args.cmd == "audit":
        valid = log.verify()
        print(json.dumps({"valid": valid, "entries": log.entries()}, indent=2))
        return 0 if valid else 2
    if args.cmd == "registry-init":
        database = args.data_dir / "registry.sqlite3"
        CapabilityRegistry(database)
        print(json.dumps({"initialized": True, "database": str(database)}, indent=2))
        return 0
    if args.cmd == "backup":
        source = args.data_dir / "registry.sqlite3"
        destination = args.destination or (args.data_dir / "backups" / "registry.sqlite3")
        result = create_backup(source, destination)
        print(json.dumps({"backup": str(destination), **result}, indent=2))
        return 0
    if args.cmd == "verify-backup":
        print(json.dumps(verify_backup(args.backup), indent=2))
        return 0
    if args.cmd == "restore":
        print(json.dumps(restore_backup(args.backup, args.destination), indent=2))
        return 0

    decision = policy.evaluate(args.action, args.risk, args.approved)
    log.append("policy.decision", decision.to_dict())
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())
