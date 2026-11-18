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
from nexora.registry import CapabilityRegistry, RegistryError
from nexora.terminal.dashboard import run_read_only_tui
from nexora.terminal.web_dashboard import run_read_only_web_dashboard


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nexora")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "catalog-check", "kill", "resume", "audit", "registry-init", "tui", "web"):
        sub.add_parser(name)
    capabilities = sub.add_parser("capabilities", help="Inspect source-backed self-capability coverage")
    capabilities.add_argument("--family")
    capabilities.add_argument("--include-records", action="store_true")
    approval = sub.add_parser("approval", help="Manage independently pinned lifecycle approval keys")
    approval_sub = approval.add_subparsers(dest="approval_cmd", required=True)
    approval_keygen = approval_sub.add_parser("keygen")
    approval_keygen.add_argument("--private-key", type=Path, required=True)
    approval_keygen.add_argument("--public-key", type=Path, required=True)
    approval_enroll = approval_sub.add_parser("enroll")
    approval_enroll.add_argument("--public-key", type=Path, required=True)
    approval_enroll.add_argument("--label", required=True)
    approval_rotate = approval_sub.add_parser("rotate")
    approval_rotate.add_argument("--old-fingerprint", required=True)
    approval_rotate.add_argument("--new-public-key", type=Path, required=True)
    approval_rotate.add_argument("--new-label", required=True)
    approval_rotate.add_argument("--reason", required=True)
    approval_revoke = approval_sub.add_parser("revoke")
    approval_revoke.add_argument("--fingerprint", required=True)
    approval_revoke.add_argument("--reason", required=True)
    approval_sub.add_parser("keys")
    approval_history = approval_sub.add_parser("history")
    approval_history.add_argument("--fingerprint")
    approval_issue = approval_sub.add_parser("issue")
    approval_issue.add_argument("--private-key", type=Path, required=True)
    approval_issue.add_argument("--capability-id", type=int, required=True)
    approval_issue.add_argument("--transition", choices=("APPROVED", "ENABLED"), required=True)
    approval_issue.add_argument("--evidence", nargs="+", required=True)
    approval_issue.add_argument("--approver-id", required=True)
    approval_issue.add_argument("--ttl-seconds", type=int, default=900)
    approval_issue.add_argument("--output", type=Path, required=True)
    evidence = sub.add_parser("evidence", help="Record and verify capability evidence references")
    evidence_sub = evidence.add_subparsers(dest="evidence_cmd", required=True)
    evidence_add = evidence_sub.add_parser("add")
    evidence_add.add_argument("capability_id", type=int)
    evidence_add.add_argument("--type", dest="evidence_type", required=True)
    evidence_add.add_argument("--reference", required=True)
    evidence_add.add_argument("--sha256", required=True)
    evidence_add.add_argument("--operator", required=True)
    evidence_add.add_argument("--note", default="")
    evidence_add.add_argument("--confirm", action="store_true", required=True)
    evidence_list = evidence_sub.add_parser("list")
    evidence_list.add_argument("--capability-id", type=int)
    evidence_list.add_argument("--limit", type=int, default=100)
    evidence_sub.add_parser("verify")
    evidence_evaluate = evidence_sub.add_parser("evaluate", help="Report evidence readiness without changing lifecycle state")
    evidence_evaluate.add_argument("capability_id", type=int)
    registry_transition = sub.add_parser("registry-transition", help="Apply an evidence-gated capability transition")
    registry_transition.add_argument("capability_id", type=int)
    registry_transition.add_argument("state", choices=("REGISTERED", "IMPLEMENTED", "TESTED", "SHADOWED", "APPROVED", "ENABLED"))
    registry_transition.add_argument("--evidence", nargs="+", required=True)
    registry_transition.add_argument("--approver-id")
    registry_transition.add_argument("--approval-receipt", type=Path)
    source_status = sub.add_parser("source-status", help="Report missing exact-source catalogue records")
    source_status.add_argument("--catalog", type=Path)
    source_status.add_argument("--rules", type=Path)
    source_preview = sub.add_parser("source-import-preview", help="Validate exact-source import candidates without writing")
    source_preview.add_argument("artifact", type=Path)
    source_preview.add_argument("--kind", choices=("capability", "meta-rule"), required=True)
    source_preview.add_argument("--source-ref", required=True)
    source_preview.add_argument("--catalog", type=Path)
    source_preview.add_argument("--rules", type=Path)
    family_eval = sub.add_parser("family-evaluation", help="Evaluate source-backed capability families")
    family_eval.add_argument("--family")
    family_eval.add_argument("--database", type=Path)
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
    inventory = sub.add_parser("backup-inventory", help="Read-only inventory of a backup directory")
    inventory.add_argument("--directory", type=Path, default=Path("data/backups"))
    inventory.add_argument("--trusted-key", type=Path)
    recovery_compare = sub.add_parser("recovery-compare", help="Compare two independently verified recovery points")
    recovery_compare.add_argument("older_backup", type=Path)
    recovery_compare.add_argument("newer_backup", type=Path)
    recovery_compare.add_argument("--trusted-key", type=Path, required=True)
    recovery_plan = sub.add_parser("recovery-plan", help="Rank verified recovery points and propose retention")
    recovery_plan.add_argument("--directory", type=Path, default=Path("data/backups"))
    recovery_plan.add_argument("--trusted-key", type=Path, required=True)
    recovery_plan.add_argument("--retention-days", type=int, default=30)
    recovery_plan.add_argument("--keep-latest", type=int, default=3)
    recovery_simulate = sub.add_parser("recovery-simulate", help="Simulate restore in temporary isolated storage")
    recovery_simulate.add_argument("backup", type=Path)
    recovery_simulate.add_argument("--config", type=Path, default=Path("config/recovery.json"))
    recovery_simulate.add_argument("--trusted-key", type=Path)
    recovery_simulate.add_argument("--confirm-simulation", action="store_true", required=True)
    recovery_simulate.add_argument("--witness-key", type=Path)
    recovery_simulate.add_argument("--witness-log", type=Path)
    recovery_simulate.add_argument("--history-log", type=Path)
    recovery_simulate.add_argument("--audit-log", type=Path)
    recovery_history = sub.add_parser("recovery-history", help="Verify and inspect witnessed recovery simulations")
    recovery_history.add_argument("--config", type=Path, default=Path("config/recovery.json"))
    recovery_history.add_argument("--history-log", type=Path)
    recovery_history.add_argument("--witness-log", type=Path)
    recovery_history.add_argument("--trusted-witness-key", type=Path)
    recovery_history.add_argument("--limit", type=int, default=50)
    recovery_readiness = sub.add_parser("recovery-readiness", help="Score verified backup readiness without changing data")
    recovery_readiness.add_argument("--config", type=Path, default=Path("config/recovery.json"))
    recovery_readiness.add_argument("--directory", type=Path)
    recovery_readiness.add_argument("--trusted-key", type=Path)
    recovery_readiness.add_argument("--max-backup-age-hours", type=int)
    recovery_readiness.add_argument("--min-verified-points", type=int)
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
    update_keygen = update_sub.add_parser("keygen")
    update_keygen.add_argument("--private-key", type=Path, required=True)
    update_keygen.add_argument("--public-key", type=Path, required=True)
    update_install = update_sub.add_parser("install")
    update_install.add_argument("--confirm", action="store_true", required=True)
    update_install.add_argument("--manifest", type=Path, required=True)
    update_install.add_argument("--trusted-key", type=Path, required=True)
    update_sign = update_sub.add_parser("sign-manifest")
    update_sign.add_argument("--commit-sha", required=True)
    update_sign.add_argument("--version", required=True)
    update_sign.add_argument("--signing-key", type=Path, required=True)
    update_sign.add_argument("--output", type=Path, required=True)
    update_verify = update_sub.add_parser("verify-manifest")
    update_verify.add_argument("manifest", type=Path)
    update_verify.add_argument("--trusted-key", type=Path, required=True)

    litertlm = sub.add_parser("litertlm", help="Manage the optional local LiteRT-LM runtime")
    litertlm_sub = litertlm.add_subparsers(dest="litertlm_cmd", required=True)
    litertlm_sub.add_parser("doctor")
    litertlm_sub.add_parser("models")
    litertlm_install = litertlm_sub.add_parser("install")
    litertlm_install.add_argument("--confirm", action="store_true", required=True)
    for command_name in ("run", "chat"):
        runtime_command = litertlm_sub.add_parser(command_name)
        model_source = runtime_command.add_mutually_exclusive_group(required=True)
        model_source.add_argument("--model", type=Path)
        model_source.add_argument("--from-huggingface-repo", dest="huggingface_repo")
        runtime_command.add_argument("--backend", choices=("cpu", "gpu"))
        runtime_command.add_argument("--config", type=Path, default=Path("config/litertlm.yaml"))
        runtime_command.add_argument("--timeout", type=int)
        runtime_command.add_argument("--confirm-inference", action="store_true", required=True)
        runtime_command.add_argument("--confirm-download", action="store_true")
        if command_name == "run":
            runtime_command.add_argument("--prompt", required=True)

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
    if args.cmd == "approval":
        from nexora.approval import (
            ApprovalError,
            ApprovalReceiptStore,
            create_receipt,
            generate_keypair,
            load_private_key,
            load_public_key,
        )
        try:
            if args.approval_cmd == "keygen":
                fingerprint = generate_keypair(args.private_key, args.public_key)
                result = {"created": True, "fingerprint": fingerprint,
                          "private_key": str(args.private_key), "public_key": str(args.public_key)}
            elif args.approval_cmd == "issue":
                receipt = create_receipt(
                    load_private_key(args.private_key),
                    capability_id=args.capability_id, transition=args.transition,
                    evidence=args.evidence, approver_id=args.approver_id,
                    ttl_seconds=args.ttl_seconds,
                )
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("x", encoding="utf-8") as stream:
                    json.dump(receipt, stream, ensure_ascii=False, sort_keys=True, indent=2)
                    stream.write("\\n")
                result = {"created": True, "output": str(args.output),
                          "capability_id": args.capability_id, "transition": args.transition}
            else:
                store = ApprovalReceiptStore(args.data_dir / "registry.sqlite3")
                if args.approval_cmd == "enroll":
                    fingerprint = store.enroll_key(load_public_key(args.public_key), label=args.label)
                    result = {"enrolled": True, "fingerprint": fingerprint}
                elif args.approval_cmd == "rotate":
                    fingerprint = store.rotate_key(
                        args.old_fingerprint, load_public_key(args.new_public_key),
                        new_label=args.new_label, reason=args.reason,
                    )
                    result = {"rotated": True, "new_fingerprint": fingerprint}
                elif args.approval_cmd == "revoke":
                    store.revoke_key(args.fingerprint, reason=args.reason)
                    result = {"revoked": True, "fingerprint": args.fingerprint}
                elif args.approval_cmd == "keys":
                    result = {"keys": store.list_keys()}
                else:
                    result = {"events": store.key_history(args.fingerprint)}
        except (ApprovalError, OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "evidence":
        from nexora.evidence import EvidenceError, EvidenceLedger
        ledger = (
            None if args.evidence_cmd == "evaluate"
            else EvidenceLedger(args.data_dir / "registry.sqlite3")
        )
        try:
            if args.evidence_cmd == "add":
                result = ledger.add(
                    args.capability_id, args.evidence_type, args.reference,
                    args.sha256, args.operator, args.note,
                )
                print(json.dumps({"recorded": True, **result}, indent=2))
                return 0
            if args.evidence_cmd == "list":
                print(json.dumps(ledger.list(args.capability_id, args.limit), indent=2))
                return 0
            if args.evidence_cmd == "evaluate":
                from nexora.capability_evaluation import evaluate_from_ledger
                result = evaluate_from_ledger(
                    args.data_dir / "registry.sqlite3", args.capability_id,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["assessment"] != "BLOCKED_LEDGER_INTEGRITY" else 2
            result = ledger.verify()
            print(json.dumps(result, indent=2))
            return 0 if result["valid"] else 2
        except (EvidenceError, OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 2
    if args.cmd == "capabilities":
        from nexora.self_capability_report import build_report
        try:
            print(json.dumps(build_report(
                family=args.family, include_records=args.include_records,
            ), ensure_ascii=False, indent=2))
        except (OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        return 0
    if args.cmd == "source-status":
        from nexora.source_status import build_source_status
        try:
            kwargs = {}
            if args.catalog is not None:
                kwargs["catalog_path"] = args.catalog
            if args.rules is not None:
                kwargs["rules_path"] = args.rules
            result = build_source_status(**kwargs)
        except (OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "source-import-preview":
        from nexora.source_import import SourceImportError, preview_source_import
        try:
            kwargs = {}
            if args.catalog is not None:
                kwargs["catalog_path"] = args.catalog
            if args.rules is not None:
                kwargs["rules_path"] = args.rules
            result = preview_source_import(
                args.artifact, kind=args.kind, source_ref=args.source_ref, **kwargs,
            )
        except (SourceImportError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "family-evaluation":
        from nexora.family_evaluation import FamilyEvaluationError, build_family_evaluation
        try:
            result = build_family_evaluation(
                args.database or (args.data_dir / "registry.sqlite3"),
                family=args.family,
            )
        except (FamilyEvaluationError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ledger"]["status"] != "INVALID" else 2
    if args.cmd == "update":
        from nexora.updater import UpdateError, main_result
        if args.update_cmd in ("keygen", "sign-manifest", "verify-manifest"):
            from nexora.update_signing import (
                UpdateSignatureError,
                create_manifest,
                generate_update_signing_keypair,
                verify_manifest,
            )
            try:
                if args.update_cmd == "keygen":
                    result = {
                        "created": True,
                        "signer_fingerprint": generate_update_signing_keypair(
                            args.private_key, args.public_key
                        ),
                        "private_key": str(args.private_key),
                        "public_key": str(args.public_key),
                        "warning": "Back up the private key securely. Never commit or share it; distribute the public key through an independent trusted channel.",
                    }
                elif args.update_cmd == "sign-manifest":
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
            result = main_result(
                args.update_cmd, Path.cwd(), getattr(args, "confirm", False),
                getattr(args, "manifest", None), getattr(args, "trusted_key", None),
            )
        except (UpdateError, OSError) as exc:
            print(json.dumps({"updated": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, indent=2))
        return 0
    if args.cmd == "litertlm":
        from nexora.intelligence.litertlm import (
            LiteRTLMError,
            install_cli,
            load_settings,
            model_inventory,
            run_huggingface_repo,
            run_local_model,
            runtime_status,
        )
        try:
            if args.litertlm_cmd == "install":
                result = install_cli(confirm=args.confirm)
                print(json.dumps(result, indent=2))
                return 0
            if args.litertlm_cmd == "doctor":
                result = runtime_status()
                print(json.dumps(result, indent=2))
                return 0 if result["installed"] else 2
            if args.litertlm_cmd == "models":
                settings = load_settings()
                print(json.dumps(model_inventory(Path(settings["model_directory"])), indent=2))
                return 0
            settings = load_settings(args.config)
            if args.huggingface_repo:
                return run_huggingface_repo(
                    args.huggingface_repo,
                    getattr(args, "prompt", None),
                    backend=args.backend or settings["default_backend"],
                    executable=settings["executable"],
                    timeout=args.timeout or settings["timeout_seconds"],
                    confirm_download=args.confirm_download,
                    confirm_inference=args.confirm_inference,
                    runtime_enabled=settings["runtime_enabled"],
                    network_downloads_enabled=settings["network_downloads_enabled"],
                    interactive=args.litertlm_cmd == "chat",
                )
            model_path = args.model
            if not model_path.is_absolute() and not model_path.is_file():
                model_path = Path(settings["model_directory"]) / model_path
            return run_local_model(
                model_path,
                getattr(args, "prompt", None),
                backend=args.backend or settings["default_backend"],
                executable=settings["executable"],
                timeout=args.timeout or settings["timeout_seconds"],
                confirm_inference=args.confirm_inference,
                runtime_enabled=settings["runtime_enabled"],
                interactive=args.litertlm_cmd == "chat",
            )
        except (LiteRTLMError, OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 2
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
    if args.cmd == "registry-transition":
        try:
            receipt = None
            if args.approval_receipt is not None:
                receipt = json.loads(args.approval_receipt.read_text(encoding="utf-8"))
            result = CapabilityRegistry(args.data_dir / "registry.sqlite3").transition(
                args.capability_id, args.state, args.evidence,
                approver_id=args.approver_id, approval_receipt=receipt,
            )
        except (OSError, ValueError, RegistryError) as exc:
            print(json.dumps({"transitioned": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({"transitioned": True, "capability": result}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "registry-init":
        database = args.data_dir / "registry.sqlite3"
        CapabilityRegistry(database)
        print(json.dumps({"initialized": True, "database": str(database)}, indent=2))
        return 0
    private_default = args.data_dir / "backup-signing-key.pem"
    public_default = args.data_dir / "backup-signing-key.pub.pem"
    if args.cmd == "recovery-compare":
        from nexora.recovery_compare import RecoveryComparisonError, compare_recovery_points
        try:
            result = compare_recovery_points(
                args.older_backup, args.newer_backup, trusted_public_key=args.trusted_key,
            )
        except (RecoveryComparisonError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "recovery-plan":
        from nexora.recovery_planner import RecoveryPlanningError, build_recovery_plan
        try:
            result = build_recovery_plan(
                args.directory, trusted_public_key=args.trusted_key,
                retention_days=args.retention_days, keep_latest=args.keep_latest,
            )
        except (RecoveryPlanningError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "recovery-simulate":
        from nexora.recovery_history import RecoveryHistoryError, record_recovery_simulation
        from nexora.recovery_readiness import RecoverySettings
        try:
            settings = RecoverySettings.load(args.config) if args.config.is_file() else RecoverySettings().validate()
            backup_key = args.trusted_key or (Path(settings.trusted_public_key) if settings.trusted_public_key else None)
            if backup_key is None:
                raise RecoveryHistoryError("backup_trust_anchor_required")
            result = record_recovery_simulation(
                args.backup, backup_trusted_key=backup_key,
                witness_private_key=args.witness_key or Path(settings.witness_private_key),
                witness_receipt_log=args.witness_log or Path(settings.witness_receipt_log),
                history_log=args.history_log or Path(settings.history_log),
                audit_log=args.audit_log or Path(settings.audit_log),
            )
        except (RecoveryHistoryError, OSError, ValueError) as exc:
            print(json.dumps({"simulation": "FAILED", "recorded": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "recovery-history":
        from nexora.recovery_history import RecoveryHistoryError, read_recovery_history
        from nexora.recovery_readiness import RecoverySettings
        try:
            settings = RecoverySettings.load(args.config) if args.config.is_file() else RecoverySettings().validate()
            result = read_recovery_history(
                args.history_log or Path(settings.history_log),
                args.witness_log or Path(settings.witness_receipt_log),
                trusted_witness_public_key=args.trusted_witness_key or Path(settings.witness_public_key),
                limit=args.limit,
            )
        except (RecoveryHistoryError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "recovery-readiness":
        from nexora.recovery_readiness import (
            RecoveryReadinessError,
            RecoverySettings,
            build_recovery_readiness,
        )
        try:
            settings = RecoverySettings.load(args.config) if args.config.is_file() else RecoverySettings().validate()
            directory = args.directory or Path(settings.backup_directory)
            key = args.trusted_key or (Path(settings.trusted_public_key) if settings.trusted_public_key else None)
            result = build_recovery_readiness(
                directory, trusted_public_key=key,
                retention_days=settings.retention_days,
                keep_latest=settings.keep_latest,
                max_backup_age_hours=args.max_backup_age_hours or settings.max_backup_age_hours,
                min_verified_points=args.min_verified_points or settings.min_verified_points,
                history_log=Path(settings.history_log),
                witness_receipt_log=Path(settings.witness_receipt_log),
                trusted_witness_public_key=Path(settings.witness_public_key),
            )
        except (RecoveryReadinessError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "READY" else 2
    if args.cmd == "backup-inventory":
        from nexora.backup_inventory import BackupInventoryError, build_backup_inventory
        try:
            result = build_backup_inventory(args.directory, trusted_public_key=args.trusted_key)
        except (BackupInventoryError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if not result["counts"].get("INVALID") and not result["counts"].get("UNSAFE_SYMLINK") else 2
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
