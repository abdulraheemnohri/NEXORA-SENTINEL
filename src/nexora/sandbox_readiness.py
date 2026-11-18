"""Read-only OS sandbox readiness checks. This module never launches a sandbox or code."""
import platform
import shutil
import sys


_AUTO_DETECT = object()


def inspect_sandbox_readiness(
    *,
    system: str | None = None,
    release: str | None = None,
    bubblewrap_path: str | None | object = _AUTO_DETECT,
) -> dict:
    """Report prerequisites without attempting namespace creation or execution.

    Presence of bubblewrap is not proof that its isolation guarantees work.
    A READY state is deliberately impossible until a separately audited,
    adversarially tested backend integration exists.
    """
    detected_system = system or platform.system()
    detected_release = release if release is not None else platform.release()
    is_android = (
        "android" in detected_release.lower()
        or hasattr(sys, "getandroidapilevel")
    )
    backend = shutil.which("bwrap") if bubblewrap_path is _AUTO_DETECT else bubblewrap_path

    checks = {
        "linux_host": {
            "status": "PASS" if detected_system == "Linux" and not is_android else "FAIL",
            "detail": "Linux desktop/server host required; Android/Termux is not currently qualified.",
        },
        "bubblewrap_binary": {
            "status": "PASS" if backend else "FAIL",
            "detail": str(backend) if backend else "bwrap_not_found",
        },
        "user_namespace_creation": {
            "status": "UNVERIFIED",
            "detail": "Not probed; namespace creation requires a dedicated isolated test.",
        },
        "mount_namespace_isolation": {
            "status": "UNVERIFIED",
            "detail": "Not tested; host mount visibility has not been audited.",
        },
        "pid_namespace_isolation": {
            "status": "UNVERIFIED",
            "detail": "Not tested; process isolation has not been audited.",
        },
        "network_namespace_isolation": {
            "status": "UNVERIFIED",
            "detail": "Not tested; network isolation has not been audited.",
        },
        "read_only_root_and_workspace_mounts": {
            "status": "UNVERIFIED",
            "detail": "No execution profile or mount policy is configured.",
        },
        "credential_and_host_socket_exclusion": {
            "status": "UNVERIFIED",
            "detail": "No mount allowlist has been implemented or tested.",
        },
        "resource_and_time_limits": {
            "status": "UNVERIFIED",
            "detail": "No OS-enforced cgroup, rlimit and wall-clock profile is integrated.",
        },
        "environment_scrubbing": {
            "status": "UNVERIFIED",
            "detail": "No executor exists to construct a controlled environment.",
        },
        "adversarial_backend_validation": {
            "status": "UNVERIFIED",
            "detail": "No independent sandbox escape test suite has qualified a backend.",
        },
    }
    blockers = [
        name for name, item in checks.items()
        if item["status"] != "PASS"
    ]
    available = (
        checks["linux_host"]["status"] == "PASS"
        and checks["bubblewrap_binary"]["status"] == "PASS"
    )
    return {
        "schema_version": 1,
        "status": "UNVERIFIED" if available else "UNAVAILABLE",
        "backend": "bubblewrap" if backend else None,
        "backend_path": str(backend) if backend else None,
        "checks": checks,
        "blockers": blockers,
        "execution_enabled": False,
        "execution_authorized": False,
        "fallback_to_unsandboxed_execution": False,
        "note": (
            "This is a read-only prerequisite report, not a sandbox test or security "
            "certification. A detected backend does not establish isolation. "
            "Execution remains disabled in every state."
        ),
    }
