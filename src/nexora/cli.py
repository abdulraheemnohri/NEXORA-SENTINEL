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
    for name in ("status", "catalog-check", "kill", "resume", "audit", "registry-init", "tui", "web", "sandbox-check", "doctor", "kill-switch-test"):
        sub.add_parser(name)
    lifecycle_history = sub.add_parser(
        "lifecycle-history", help="Replay existing lifecycle events read-only"
    )
    lifecycle_history.add_argument("--capability-id", type=int)
    lifecycle_history.add_argument("--database", type=Path)
    regression = sub.add_parser(
        "regression-report", help="Detect structural lifecycle history regressions read-only"
    )
    regression.add_argument("--capability-id", type=int)
    regression.add_argument("--database", type=Path)
    chain_attest = sub.add_parser(
        "lifecycle-chain-attest", help="Sign and append an external lifecycle-chain checkpoint"
    )
    chain_attest.add_argument("--database", type=Path)
    chain_attest.add_argument("--witness-key", type=Path, required=True)
    chain_attest.add_argument("--witness-log", type=Path, required=True)
    chain_attest.add_argument("--confirm", action="store_true", required=True)
    chain_verify = sub.add_parser(
        "lifecycle-chain-verify", help="Verify local lifecycle chain against an external witness"
    )
    chain_verify.add_argument("--database", type=Path)
    chain_verify.add_argument("--witness-log", type=Path, required=True)
    chain_verify.add_argument("--trusted-witness-key", type=Path, required=True)
    maturity = sub.add_parser("maturity-report", help="Report lifecycle evidence and explicit L0-L4 source gaps")
    maturity.add_argument("--capability-id", type=int)
    maturity.add_argument("--database", type=Path)
    maturity.add_argument("--catalog", type=Path)
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
    approval_enroll.add_argument("--validity-days", type=int, default=365)
    approval_rotate = approval_sub.add_parser("rotate")
    approval_rotate.add_argument("--old-fingerprint", required=True)
    approval_rotate.add_argument("--new-public-key", type=Path, required=True)
    approval_rotate.add_argument("--new-label", required=True)
    approval_rotate.add_argument("--reason", required=True)
    approval_rotate.add_argument("--validity-days", type=int, default=365)
    approval_renew = approval_sub.add_parser("renew")
    approval_renew.add_argument("--old-fingerprint", required=True)
    approval_renew.add_argument("--new-public-key", type=Path, required=True)
    approval_renew.add_argument("--new-label", required=True)
    approval_renew.add_argument("--reason", required=True)
    approval_renew.add_argument("--validity-days", type=int, default=365)
    approval_revoke = approval_sub.add_parser("revoke")
    approval_revoke.add_argument("--fingerprint", required=True)
    approval_revoke.add_argument("--reason", required=True)
    approval_sub.add_parser("keys")
    approval_history = approval_sub.add_parser("history")
    approval_history.add_argument("--fingerprint")
    approval_issue = approval_sub.add_parser("issue")
    approval_issue.add_argument("--private-key", type=Path, required=True)
    approval_issue.add_argument("--capability-id", type=int, required=True)
    approval_issue.add_argument("--transition", choices=("APPROVED", "ENABLED", "REVOKE", "ROLLBACK"), required=True)
    approval_issue.add_argument("--evidence", nargs="+", required=True)
    approval_issue.add_argument("--approver-id", required=True)
    approval_issue.add_argument("--ttl-seconds", type=int, default=900)
    approval_issue.add_argument("--output", type=Path, required=True)
    recovery_enroll = approval_sub.add_parser("recovery-enroll")
    recovery_enroll.add_argument("--public-key", type=Path, required=True)
    recovery_enroll.add_argument("--authority-id", required=True)
    recovery_enroll.add_argument("--label", required=True)
    recovery_enroll.add_argument("--validity-days", type=int, default=365)
    recovery_issue = approval_sub.add_parser("recovery-issue")
    recovery_issue.add_argument("--private-key", type=Path, required=True)
    recovery_issue.add_argument("--authority-id", required=True)
    recovery_issue.add_argument("--old-fingerprint", required=True)
    recovery_issue.add_argument("--new-public-key", type=Path, required=True)
    recovery_issue.add_argument("--new-label", required=True)
    recovery_issue.add_argument("--reason", required=True)
    recovery_issue.add_argument("--ttl-seconds", type=int, default=600)
    recovery_issue.add_argument("--output", type=Path, required=True)
    recovery_apply = approval_sub.add_parser("recover")
    recovery_apply.add_argument("--old-fingerprint", required=True)
    recovery_apply.add_argument("--new-public-key", type=Path, required=True)
    recovery_apply.add_argument("--new-label", required=True)
    recovery_apply.add_argument("--reason", required=True)
    recovery_apply.add_argument("--authorization", type=Path, nargs="+", required=True)
    recovery_apply.add_argument("--validity-days", type=int, default=365)
    approval_sub.add_parser("recovery-authorities")
    recovery_revoke = approval_sub.add_parser("recovery-revoke")
    recovery_revoke.add_argument("--fingerprint", required=True)
    recovery_revoke.add_argument("--reason", required=True)
    approval_sub.add_parser("recovery-history")
    evidence = sub.add_parser("evidence", help="Record and verify capability evidence references")
    evidence_sub = evidence.add_subparsers(dest="evidence_cmd", required=True)
    evidence_add = evidence_sub.add_parser("add")
    evidence_add.add_argument("capability_id", type=int)
    evidence_add.add_argument("--type", dest="evidence_type", required=True)
    evidence_add.add_argument("--reference", required=True)
    evidence_add.add_argument("--sha256", required=True)
    evidence_add.add_argument("--operator", required=True)
    evidence_add.add_argument("--note", default="")
    evidence_add.add_argument("--expires-at", help="Optional operator-declared ISO-8601 expiry with timezone")
    evidence_add.add_argument("--source-uri", help="Operator-declared source URI or repository URL")
    evidence_add.add_argument("--source-revision", help="Operator-declared commit, version, or immutable source revision")
    evidence_add.add_argument("--collected-at", help="Optional timezone-aware ISO-8601 collection time")
    evidence_add.add_argument("--confirm", action="store_true", required=True)
    evidence_list = evidence_sub.add_parser("list")
    evidence_list.add_argument("--capability-id", type=int)
    evidence_list.add_argument("--limit", type=int, default=100)
    evidence_sub.add_parser("verify")
    evidence_freshness = evidence_sub.add_parser("freshness", help="Report operator-declared evidence expiry read-only")
    evidence_freshness.add_argument("--capability-id", type=int)
    evidence_provenance = evidence_sub.add_parser("provenance", help="Read-only source provenance inventory")
    evidence_provenance.add_argument("--capability-id", type=int)
    evidence_provenance.add_argument("--limit", type=int, default=500)
    evidence_evaluate = evidence_sub.add_parser("evaluate", help="Report evidence readiness without changing lifecycle state")
    evidence_evaluate.add_argument("capability_id", type=int)
    evidence_verify_artifact = evidence_sub.add_parser(
        "verify-artifact", help="Hash a local file against one exact evidence ledger record"
    )
    evidence_verify_artifact.add_argument("capability_id", type=int)
    evidence_verify_artifact.add_argument("sequence", type=int)
    evidence_verify_artifact.add_argument("--path", type=Path, required=True)
    evidence_verify_artifact.add_argument("--reference")
    registry_transition = sub.add_parser("registry-transition", help="Apply an evidence-gated capability transition")
    registry_transition.add_argument("capability_id", type=int)
    registry_transition.add_argument("state", choices=("REGISTERED", "IMPLEMENTED", "TESTED", "SHADOWED", "APPROVED", "ENABLED"))
    registry_transition.add_argument("--evidence", nargs="+", required=True)
    registry_transition.add_argument("--approver-id", nargs="+")
    registry_transition.add_argument("--approval-receipt", type=Path, nargs="+")
    registry_revoke = sub.add_parser("registry-revoke", help="Immediately revoke a capability using independent signed approvals")
    registry_revoke.add_argument("capability_id", type=int)
    registry_revoke.add_argument("--reason", required=True)
    registry_revoke.add_argument("--evidence", nargs="+", required=True)
    registry_revoke.add_argument("--approver-id", nargs="+", required=True)
    registry_revoke.add_argument("--approval-receipt", type=Path, nargs="+", required=True)
    rollback_record = sub.add_parser("rollback-record", help="Record a signed rollback authorization; does not execute it")
    rollback_record.add_argument("capability_id", type=int)
    rollback_record.add_argument("--from-release", required=True)
    rollback_record.add_argument("--target-release", required=True)
    rollback_record.add_argument("--reason", required=True)
    rollback_record.add_argument("--evidence", nargs="+", required=True)
    rollback_record.add_argument("--approver-id", nargs="+", required=True)
    rollback_record.add_argument("--approval-receipt", type=Path, nargs="+", required=True)
    revocation_verify = sub.add_parser("registry-revocation-verify", help="Cryptographically verify signed revocation history")
    revocation_verify.add_argument("capability_id", type=int)
    rollback_verify = sub.add_parser("rollback-verify", help="Cryptographically verify signed rollback authorization history")
    rollback_verify.add_argument("capability_id", type=int)
    governance_check = sub.add_parser("governance-check", help="Validate governance artifacts without changing policy")
    governance_check.add_argument("--matrix", type=Path)
    governance_check.add_argument("--precedence", type=Path)
    governance_impact = sub.add_parser(
        "governance-impact", help="Analyze explicitly declared dependents of a capability"
    )
    governance_impact.add_argument("capability_id", type=int)
    governance_impact.add_argument("--matrix", type=Path)
    governance_relation = sub.add_parser("governance-relation", help="Inspect one directed capability relationship")
    governance_relation.add_argument("source", type=int)
    governance_relation.add_argument("target", type=int)
    governance_relation.add_argument("--matrix", type=Path)
    governance_arbitrate = sub.add_parser(
        "governance-arbitrate",
        help="Propose a fixed-precedence winner for an explicitly declared conflict",
    )
    governance_arbitrate.add_argument("left_id", type=int)
    governance_arbitrate.add_argument("right_id", type=int)
    governance_arbitrate.add_argument(
        "--left-priority",
        choices=("SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"),
        required=True,
    )
    governance_arbitrate.add_argument(
        "--right-priority",
        choices=("SAFETY", "GOVERNANCE", "OPERATIONAL", "CONVENIENCE"),
        required=True,
    )
    governance_arbitrate.add_argument("--matrix", type=Path)
    governance_arbitrate.add_argument("--wait-graph", type=Path)
    spec_status = sub.add_parser(
        "spec-status", help="Report source, matrix and settings-governance readiness"
    )
    spec_status.add_argument("--catalog", type=Path)
    spec_status.add_argument("--rules", type=Path)
    spec_status.add_argument("--matrix", type=Path)
    spec_status.add_argument("--precedence", type=Path)
    spec_status.add_argument("--settings-policy", type=Path)
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
    settings_diff = settings_sub.add_parser("diff", help="Preview settings changes without applying them")
    settings_diff.add_argument("--config", type=Path, default=Path("config/settings.yaml"))
    settings_diff.add_argument("--candidate", type=Path, required=True)
    settings_policy = settings_sub.add_parser(
        "policy-status", help="Report per-setting authorization and rollback policy readiness"
    )
    settings_policy.add_argument(
        "--policy", type=Path, default=Path("config/settings_authorization.json")
    )

    memory_delete = sub.add_parser("memory-delete", aliases=["memory-tombstone", "memory-hide"])
    memory_delete.add_argument("memory_id", type=int)
    memory_delete.add_argument("--reason", required=True)
    memory_delete.add_argument("--confirm", action="store_true", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "doctor":
        from nexora.doctor import build_doctor_report
        try:
            result = build_doctor_report(args.data_dir)
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            print(json.dumps({
                "status": "CRITICAL",
                "error": type(exc).__name__,
                "read_only": True,
                "execution_enabled": False,
            }, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if result["status"] == "CRITICAL" else (3 if result["status"] == "BLOCKED" else 0)
    if args.cmd == "kill-switch-test":
        from nexora.self_tests import run_kill_switch_self_test
        result = run_kill_switch_self_test()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "PASS" else 2
    if args.cmd == "sandbox-check":
        from nexora.sandbox_readiness import inspect_sandbox_readiness
        result = inspect_sandbox_readiness()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "READY" else 3
    if args.cmd == "approval":
        from nexora.approval import (
            ApprovalError,
            ApprovalReceiptStore,
            create_receipt,
            generate_keypair,
            load_private_key,
            load_public_key,
        )
        from nexora.emergency_recovery import (
            EmergencyRecoveryError,
            EmergencyRecoveryStore,
            create_recovery_authorization,
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
            elif args.approval_cmd == "recovery-issue":
                authorization = create_recovery_authorization(
                    load_private_key(args.private_key),
                    authority_id=args.authority_id,
                    old_fingerprint=args.old_fingerprint,
                    new_public_key=load_public_key(args.new_public_key),
                    new_label=args.new_label, reason=args.reason,
                    ttl_seconds=args.ttl_seconds,
                )
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("x", encoding="utf-8") as stream:
                    json.dump(authorization, stream, ensure_ascii=False, sort_keys=True, indent=2)
                    stream.write("\\n")
                result = {"created": True, "output": str(args.output),
                          "authority_id": args.authority_id, "expires_at": authorization["payload"]["expires_at"]}
            else:
                database = args.data_dir / "registry.sqlite3"
                store = ApprovalReceiptStore(database)
                recovery = EmergencyRecoveryStore(database)
                if args.approval_cmd == "recovery-enroll":
                    fingerprint = recovery.enroll_authority(
                        load_public_key(args.public_key), authority_id=args.authority_id,
                        label=args.label, validity_days=args.validity_days,
                    )
                    result = {"enrolled": True, "authority_fingerprint": fingerprint}
                elif args.approval_cmd == "recover":
                    authorizations = [json.loads(path.read_text(encoding="utf-8")) for path in args.authorization]
                    fingerprint = recovery.recover_approval_key(
                        old_fingerprint=args.old_fingerprint,
                        new_public_key=load_public_key(args.new_public_key),
                        new_label=args.new_label, reason=args.reason,
                        authorizations=authorizations, validity_days=args.validity_days,
                    )
                    result = {"recovered": True, "new_fingerprint": fingerprint}
                elif args.approval_cmd == "recovery-authorities":
                    result = {"authorities": recovery.list_authorities()}
                elif args.approval_cmd == "recovery-revoke":
                    recovery.revoke_authority(args.fingerprint, reason=args.reason)
                    result = {"revoked": True, "authority_fingerprint": args.fingerprint}
                elif args.approval_cmd == "recovery-history":
                    result = {"events": recovery.history()}
                elif args.approval_cmd == "enroll":
                    fingerprint = store.enroll_key(
                        load_public_key(args.public_key), label=args.label,
                        validity_days=args.validity_days,
                    )
                    result = {"enrolled": True, "fingerprint": fingerprint}
                elif args.approval_cmd == "rotate":
                    fingerprint = store.rotate_key(
                        args.old_fingerprint, load_public_key(args.new_public_key),
                        new_label=args.new_label, reason=args.reason,
                        validity_days=args.validity_days,
                    )
                    result = {"rotated": True, "new_fingerprint": fingerprint}
                elif args.approval_cmd == "renew":
                    fingerprint = store.rotate_key(
                        args.old_fingerprint, load_public_key(args.new_public_key),
                        new_label=args.new_label, reason=args.reason,
                        validity_days=args.validity_days,
                    )
                    result = {"renewed": True, "new_fingerprint": fingerprint}
                elif args.approval_cmd == "revoke":
                    store.revoke_key(args.fingerprint, reason=args.reason)
                    result = {"revoked": True, "fingerprint": args.fingerprint}
                elif args.approval_cmd == "keys":
                    result = {"keys": store.list_keys()}
                else:
                    result = {"events": store.key_history(args.fingerprint)}
        except (ApprovalError, EmergencyRecoveryError, OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "evidence":
        from nexora.evidence import EvidenceError, EvidenceLedger
        ledger = (
            None if args.evidence_cmd in {"evaluate", "verify-artifact", "freshness", "provenance"}
            else EvidenceLedger(args.data_dir / "registry.sqlite3")
        )
        try:
            if args.evidence_cmd == "add":
                result = ledger.add(
                    args.capability_id, args.evidence_type, args.reference,
                    args.sha256, args.operator, args.note, args.expires_at,
                    args.source_uri, args.source_revision, args.collected_at,
                )
                print(json.dumps({"recorded": True, **result}, indent=2))
                return 0
            if args.evidence_cmd == "list":
                print(json.dumps(ledger.list(args.capability_id, args.limit), indent=2))
                return 0
            if args.evidence_cmd == "freshness":
                from nexora.evidence_freshness import build_freshness_report
                result = build_freshness_report(
                    args.data_dir / "registry.sqlite3", capability_id=args.capability_id,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["ledger_integrity"]["valid"] else 2
            if args.evidence_cmd == "provenance":
                from nexora.evidence_provenance import build_provenance_report
                result = build_provenance_report(
                    args.data_dir / "registry.sqlite3",
                    capability_id=args.capability_id, limit=args.limit,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["ledger_integrity"]["valid"] else 2
            if args.evidence_cmd == "verify-artifact":
                from nexora.artifact_integrity import verify_artifact_file
                result = verify_artifact_file(
                    args.data_dir / "registry.sqlite3",
                    args.capability_id,
                    args.sequence,
                    args.path,
                    expected_reference=args.reference,
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["verified"] else 3
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
    if args.cmd in {"lifecycle-history", "regression-report"}:
        from nexora.lifecycle_history import LifecycleHistoryError, build_lifecycle_history
        database = args.database or (args.data_dir / "registry.sqlite3")
        try:
            result = build_lifecycle_history(database, args.capability_id)
        except (LifecycleHistoryError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc), "read_only": True}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "STRUCTURALLY_CONSISTENT" else 2

    if args.cmd == "lifecycle-chain-attest":
        from nexora.lifecycle_chain import LifecycleChainError, verify_lifecycle_chain_file
        database = args.database or (args.data_dir / "registry.sqlite3")
        try:
            chain = verify_lifecycle_chain_file(database)
            if not chain.get("valid"):
                raise LifecycleChainError("lifecycle_chain_not_valid")
            receipt = IndependentWitness(args.witness_log, args.witness_key).attest(
                chain["head_hash"], "lifecycle_chain_head",
            )
        except (LifecycleChainError, OSError, ValueError, RuntimeError) as exc:
            print(json.dumps({"attested": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({
            "attested": True, "event_count": chain["event_count"],
            "head_hash": chain["head_hash"], "witness_log": str(args.witness_log),
            "signer_fingerprint": receipt["payload"]["signer_fingerprint"],
            "warning": "Store the witness log and trusted public key independently from the registry database.",
        }, indent=2))
        return 0
    if args.cmd == "lifecycle-chain-verify":
        from nexora.lifecycle_chain import LifecycleChainError, verify_lifecycle_chain_anchor
        database = args.database or (args.data_dir / "registry.sqlite3")
        try:
            result = verify_lifecycle_chain_anchor(
                database, args.witness_log, args.trusted_witness_key,
            )
        except (LifecycleChainError, OSError, ValueError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["valid"] else 2

    if args.cmd == "maturity-report":
        from nexora.maturity_report import MaturityReportError, build_maturity_report
        try:
            result = build_maturity_report(
                args.database or args.data_dir / "registry.sqlite3",
                catalog_path=args.catalog,
                capability_id=args.capability_id,
            )
        except (MaturityReportError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ledger"]["status"] != "INVALID" else 3
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
    if args.cmd == "governance-arbitrate":
        from nexora.governance.arbitration import (
            ArbitrationError,
            arbitrate_conflict,
            load_wait_graph,
        )
        from nexora.governance.validation import DEFAULT_MATRIX
        try:
            result = arbitrate_conflict(
                args.left_id,
                args.right_id,
                left_priority=args.left_priority,
                right_priority=args.right_priority,
                matrix_path=args.matrix or DEFAULT_MATRIX,
                wait_graph=load_wait_graph(args.wait_graph),
            )
        except (ArbitrationError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({
                "decision": "BLOCK_AND_ESCALATE",
                "valid": False,
                "error": str(exc),
                "proposal_authorized": False,
                "execution_enabled": False,
            }, indent=2))
            return 3
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["decision"] == "PRECEDENCE_WINNER_PROPOSED_REVIEW_REQUIRED" else 3
    if args.cmd == "governance-impact":
        from nexora.governance.validation import (
            DEFAULT_MATRIX,
            GovernanceValidationError,
            analyze_revocation_impact,
        )
        try:
            result = analyze_revocation_impact(
                args.capability_id, args.matrix or DEFAULT_MATRIX,
            )
        except (GovernanceValidationError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd in ("governance-check", "governance-relation"):
        from nexora.governance.validation import (
            GovernanceValidationError,
            build_governance_report,
            inspect_relation,
        )
        try:
            if args.cmd == "governance-check":
                kwargs = {}
                if args.matrix is not None:
                    kwargs["matrix_path"] = args.matrix
                if args.precedence is not None:
                    kwargs["precedence_path"] = args.precedence
                result = build_governance_report(**kwargs)
            else:
                from nexora.governance.validation import DEFAULT_MATRIX
                result = inspect_relation(
                    args.source, args.target, args.matrix or DEFAULT_MATRIX,
                )
        except (GovernanceValidationError, OSError, ValueError, TypeError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.cmd == "governance-check":
            return 0 if result["valid"] else 2
        return 0 if result["known"] else 3
    if args.cmd == "spec-status":
        from nexora.readiness import build_spec_status
        try:
            kwargs = {}
            for argument, key in (
                ("catalog", "catalog_path"),
                ("rules", "rules_path"),
                ("matrix", "matrix_path"),
                ("precedence", "precedence_path"),
                ("settings_policy", "settings_policy_path"),
            ):
                value = getattr(args, argument)
                if value is not None:
                    kwargs[key] = value
            result = build_spec_status(**kwargs)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(json.dumps({
                "status": "INVALID",
                "valid": False,
                "error": str(exc),
                "execution_enabled": False,
            }, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "READY_FOR_INDEPENDENT_REVIEW" else 3
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
        from nexora.readiness import build_settings_policy_status
        from nexora.settings_manager import render_settings, settings_diff_report
        try:
            if args.settings_cmd == "policy-status":
                result = build_settings_policy_status(args.policy)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["status"] == "POLICY_APPROVED" else 3
            if args.settings_cmd == "diff":
                result = settings_diff_report(args.config, args.candidate)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result["status"] == "NO_CHANGES" else 3
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
    if args.cmd in {"memory-delete", "memory-tombstone", "memory-hide"}:
        from nexora.memory.long_term import MemoryStore
        MemoryStore(args.data_dir / "memory.sqlite3", create=False).delete(
            args.memory_id, reason=args.reason
        )
        print(json.dumps({
            "tombstoned": True, "memory_id": args.memory_id,
            "physical_erasure": False,
            "note": "The record is hidden from retrieval; append-only content and audit history remain on disk.",
        }, indent=2))
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
            receipts = None
            receipt = None
            if args.approval_receipt is not None:
                loaded = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in args.approval_receipt
                ]
                if args.state == "ENABLED":
                    receipts = loaded
                elif len(loaded) == 1:
                    receipt = loaded[0]
                else:
                    raise ValueError("APPROVED accepts exactly one receipt")
            approver_id = None
            approver_ids = None
            if args.approver_id is not None:
                if args.state == "ENABLED":
                    approver_ids = args.approver_id
                elif len(args.approver_id) == 1:
                    approver_id = args.approver_id[0]
                else:
                    raise ValueError("APPROVED accepts exactly one approver ID")
            result = CapabilityRegistry(args.data_dir / "registry.sqlite3").transition(
                args.capability_id, args.state, args.evidence,
                approver_id=approver_id, approval_receipt=receipt,
                approval_receipts=receipts, approver_ids=approver_ids,
            )
        except (OSError, ValueError, RegistryError) as exc:
            print(json.dumps({"transitioned": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({"transitioned": True, "capability": result}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "registry-revoke":
        try:
            receipts = [json.loads(path.read_text(encoding="utf-8")) for path in args.approval_receipt]
            result = CapabilityRegistry(args.data_dir / "registry.sqlite3").revoke(
                args.capability_id, args.reason, args.evidence,
                approval_receipts=receipts, approver_ids=args.approver_id,
            )
        except (OSError, ValueError, RegistryError) as exc:
            print(json.dumps({"revoked": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({"revoked": True, "capability": result}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "rollback-record":
        try:
            receipts = [json.loads(path.read_text(encoding="utf-8")) for path in args.approval_receipt]
            result = CapabilityRegistry(args.data_dir / "registry.sqlite3").record_rollback(
                args.capability_id, args.from_release, args.target_release,
                args.reason, args.evidence,
                approval_receipts=receipts, approver_ids=args.approver_id,
            )
        except (OSError, ValueError, RegistryError) as exc:
            print(json.dumps({"authorized": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({"authorized": True, "rollback": result,
                          "executed": False}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd in {"registry-revocation-verify", "rollback-verify"}:
        try:
            kind = "revocation" if args.cmd == "registry-revocation-verify" else "rollback"
            result = CapabilityRegistry(args.data_dir / "registry.sqlite3").verify_signed_history(
                args.capability_id, kind=kind,
            )
        except (OSError, ValueError, RegistryError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["valid"] else 2
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
