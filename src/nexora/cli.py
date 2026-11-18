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
from nexora.terminal.web_dashboard import run_read_only_web_dashboard


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nexora")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "catalog-check", "kill", "resume", "audit", "registry-init", "tui", "web"):
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

    web = sub.choices["web"]
    web.add_argument("--port", type=int, default=8765)
    memory_add = sub.add_parser("memory-add")
    memory_add.add_argument("content")
    memory_add.add_argument("--source", required=True)
    memory_search = sub.add_parser("memory-search")
    memory_search.add_argument("query")
    memory_search.add_argument("--limit", type=int, default=10)
    update = sub.add_parser("update")
    update_sub = update.add_subparsers(dest="update_cmd", required=True)
    update_sub.add_parser("check")
    update_install = update_sub.add_parser("install")
    update_install.add_argument("--confirm", action="store_true", required=True)
    update_sign = update_sub.add_parser("sign-manifest")
    update_sign.add_argument("--commit-sha", required=True)
    update_sign.add_argument("--version", required=True)
    update_sign.add_argument("--signing-key", type=Path, required=True)
    update_sign.add_argument("--output", type=Path, required=True)
    update_verify = update_sub.add_parser("verify-manifest")
    update_verify.add_argument("manifest", type=Path)
    update_verify.add_argument("--trusted-key", type=Path, required=True)

    settings = sub.add_parser("settings")
    settings_sub = settings.add_subparsers(dest="settings_cmd", required=True)
    settings_show = settings_sub.add_parser("show")
    settings_show.add_argument("--config", type=Path, default=Path("config/settings.yaml"))
    settings_validate = settings_sub.add_parser("validate")
    settings_validate.add_argument("--config", type=Path, default=Path("config/settings.yaml"))

    memory_delete = sub.add_parser("memory-delete")
    memory_delete.add_argument("memory_id", type=int)
    memory_delete.add_argument("--reason", required=True)
    memory_delete.add_argument("--confirm", action="store_true", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "update":
        from nexora.updater import UpdateError, main_result
        if args.update_cmd in ("sign-manifest", "verify-manifest"):
            from nexora.update_signing import (
                UpdateSignatureError, create_manifest, verify_manifest,
            )
            try:
                if args.update_cmd == "sign-manifest":
                    result = create_manifest(
                        commit_sha=args.commit_sha, version=args.version,
                        signing_key=args.signing_key, output=args.output,
                    )
                else:
                    result = verify_manifest(args.manifest, args.trusted_key)
            except (UpdateSignatureError, OSError, ValueError) as exc:
                print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
                return 2
            print(json.dumps(result, indent=2))
            return 0
        try:
            result = main_result(args.update_cmd, Path.cwd(), getattr(args, "confirm", False))
        except (UpdateError, OSError) as exc:
            print(json.dumps({"updated": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, indent=2))
        return 0
    if args.cmd == "settings":
        from nexora.settings_manager import render_settings
        try:
            print(render_settings(args.config))
        except (OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        return 0
    if args.cmd == "web":
        return run_read_only_web_dashboard(args.data_dir, port=args.port)
    if args.cmd == "tui":
        import sys
        return run_read_only_tui(args.data_dir, output=sys.stdout)
    if args.cmd == "memory-search":
        from nexora.memory.long_term import MemoryStore
        store = MemoryStore(args.data_dir / "memory.sqlite3", create=False)
        print(json.dumps(store.search(args.query, limit=args.limit), indent=2))
        return 0
    if args.cmd == "memory-add":
        from nexora.memory.long_term import MemoryStore
        memory_id = MemoryStore(args.data_dir / "memory.sqlite3").add(
            args.content, source=args.source
        )
        print(json.dumps({"created": True, "memory_id": memory_id}, indent=2))
        return 0
    if args.cmd == "memory-delete":
        from nexora.memory.long_term import MemoryStore
        MemoryStore(args.data_dir / "memory.sqlite3", create=False).delete(
            args.memory_id, reason=args.reason
        )
        print(json.dumps({"tombstoned": True, "memory_id": args.memory_id}, indent=2))
        return 0
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
