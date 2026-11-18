"""NEXORA Sentinel command-line interface."""
import argparse
import json
from pathlib import Path

from nexora.backup import (
    create_backup,
    generate_backup_signing_key,
    restore_backup,
    signing_key_fingerprint,
    verify_backup,
)
from nexora.catalog import status
from nexora.oversight import AuditLog, KillSwitch, PolicyKernel
from nexora.oversight.witness import IndependentWitness, verify_witness_chain
from nexora.registry import CapabilityRegistry
from nexora.terminal.dashboard import run_read_only_tui


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nexora")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "catalog-check", "kill", "resume", "audit", "registry-init", "tui"):
        sub.add_parser(name)
    check = sub.add_parser("check")
    check.add_argument("action")
    check.add_argument("--risk", choices=("low", "medium", "high", "critical"), default="medium")
    check.add_argument("--approved", action="store_true")
    keygen = sub.add_parser("backup-keygen")
    keygen.add_argument("--private-key", type=Path)
    keygen.add_argument("--public-key", type=Path)
    backup = sub.add_parser("backup")
    backup.add_argument("destination", nargs="?", type=Path)
    backup.add_argument("--signing-key", type=Path)
    verify = sub.add_parser("verify-backup")
    verify.add_argument("backup", type=Path)
    verify.add_argument("--trusted-key", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument("--trusted-key", type=Path)
    witness = sub.add_parser("witness-backup")
    witness.add_argument("backup", type=Path)
    witness.add_argument("--signing-key", type=Path)
    witness.add_argument("--trusted-key", type=Path, help="Trusted public key for the backup signature")
    witness.add_argument("--receipt-log", type=Path)
    witness_verify = sub.add_parser("verify-witness")
    witness_verify.add_argument("receipt_log", type=Path)
    witness_verify.add_argument("--trusted-key", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "tui":
        import sys
        return run_read_only_tui(args.data_dir, output=sys.stdout)
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
    private_default = args.data_dir / "backup-signing-key.pem"
    public_default = args.data_dir / "backup-signing-key.pub.pem"
    if args.cmd == "backup-keygen":
        private = args.private_key or private_default
        public = args.public_key or public_default
        fingerprint = generate_backup_signing_key(private, public)
        print(json.dumps({
            "created": True, "fingerprint": fingerprint,
            "private_key": str(private), "public_key": str(public),
            "warning": "Keep the private key secret; distribute the public key through a separate trusted channel.",
        }, indent=2))
        return 0
    if args.cmd == "backup":
        source = args.data_dir / "registry.sqlite3"
        destination = args.destination or (args.data_dir / "backups" / "registry.sqlite3")
        signing_key = args.signing_key or private_default
        result = create_backup(source, destination, signing_key=signing_key)
        print(json.dumps({"backup": str(destination), **result}, indent=2))
        return 0
    if args.cmd == "verify-backup":
        trusted_key = args.trusted_key or public_default
        print(json.dumps(verify_backup(args.backup, trusted_public_key=trusted_key), indent=2))
        return 0
    if args.cmd == "restore":
        trusted_key = args.trusted_key or public_default
        print(json.dumps(
            restore_backup(args.backup, args.destination, trusted_public_key=trusted_key), indent=2
        ))
        return 0
    if args.cmd == "witness-backup":
        backup_trust_key = args.trusted_key or public_default
        witness_private = args.signing_key or (args.data_dir / "witness-signing-key.pem")
        witness_fingerprint = signing_key_fingerprint(witness_private)
        backup_result = verify_backup(args.backup, trusted_public_key=backup_trust_key)
        if witness_fingerprint == backup_result["signer_fingerprint"]:
            raise ValueError("independent_witness_key_must_differ_from_backup_signing_key")
        receipt_log = args.receipt_log or (args.data_dir / "witness" / "receipts.jsonl")
        receipt = IndependentWitness(receipt_log, witness_private).attest(
            backup_result["sha256"], "sqlite_backup",
        )
        print(json.dumps({
            "attested": True, "event_hash": backup_result["sha256"],
            "receipt_log": str(receipt_log), "witness_fingerprint": receipt["payload"]["signer_fingerprint"],
        }, indent=2))
        return 0
    if args.cmd == "verify-witness":
        trusted_key = args.trusted_key or (args.data_dir / "witness-signing-key.pub.pem")
        print(json.dumps(verify_witness_chain(args.receipt_log, trusted_key), indent=2))
        return 0

    decision = policy.evaluate(args.action, args.risk, args.approved)
    log.append("policy.decision", decision.to_dict())
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())
