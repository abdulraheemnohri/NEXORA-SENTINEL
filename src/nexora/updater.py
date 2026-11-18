"""Explicit, fast-forward-only updater for the official GitHub repository."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

OWNER = "abdulraheemnohri"
REPOSITORY = "NEXORA-SENTINEL"
REMOTE_URLS = {
    f"https://github.com/{OWNER}/{REPOSITORY}.git",
    f"git@github.com:{OWNER}/{REPOSITORY}.git",
}
API_ROOT = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}"
API_URL = f"{API_ROOT}/commits/main"


class UpdateError(RuntimeError):
    """An update was refused or could not be completed safely."""


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True,
    )
    if result.returncode:
        raise UpdateError(
            f"git_{args[0]}_failed: {(result.stderr or result.stdout).strip()}"
        )
    return result.stdout.strip()


def _github_json(url: str, timeout: float = 10.0) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "NEXORA-Sentinel-Updater",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise UpdateError(f"github_request_failed: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise UpdateError("github_response_not_an_object")
    return payload


def latest_commit(timeout: float = 10.0) -> dict[str, str]:
    payload = _github_json(API_URL, timeout)
    sha = payload.get("sha")
    if not isinstance(sha, str) or len(sha) != 40 or any(
        char not in "0123456789abcdef" for char in sha.lower()
    ):
        raise UpdateError("github_response_missing_valid_commit_sha")
    commit = payload.get("commit", {})
    message = commit.get("message", "") if isinstance(commit, dict) else ""
    return {"sha": sha, "message": str(message).splitlines()[0][:200]}


def change_preview(local_sha: str, latest_sha: str) -> dict[str, object]:
    """Return bounded changed-file metadata; never download or execute patch content."""
    payload = _github_json(f"{API_ROOT}/compare/{local_sha}...{latest_sha}")
    files = payload.get("files", [])
    if not isinstance(files, list):
        files = []
    preview = []
    for item in files[:100]:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            continue
        preview.append({
            "path": item["filename"][:300],
            "status": str(item.get("status", "unknown"))[:30],
            "additions": max(0, int(item.get("additions", 0) or 0)),
            "deletions": max(0, int(item.get("deletions", 0) or 0)),
        })
    return {
        "ahead_by": max(0, int(payload.get("ahead_by", 0) or 0)),
        "behind_by": max(0, int(payload.get("behind_by", 0) or 0)),
        "files": preview,
        "files_truncated": len(files) > 100,
    }


def ci_summary(commit_sha: str) -> dict[str, object]:
    """Summarize the latest Actions run for this exact commit SHA."""
    url = f"{API_ROOT}/actions/runs?head_sha={commit_sha}&per_page=20"
    payload = _github_json(url)
    runs = payload.get("workflow_runs", [])
    matching = [
        run for run in runs
        if isinstance(run, dict) and run.get("head_sha") == commit_sha
    ]
    if not matching:
        return {"state": "unknown", "runs": []}
    matching.sort(key=lambda run: str(run.get("created_at", "")), reverse=True)
    summaries = [{
        "name": str(run.get("name", "workflow"))[:100],
        "status": str(run.get("status", "unknown")),
        "conclusion": run.get("conclusion"),
        "url": str(run.get("html_url", ""))[:500],
    } for run in matching[:10]]
    if any(run["conclusion"] == "failure" for run in summaries):
        state = "failure"
    elif any(run["status"] != "completed" for run in summaries):
        state = "pending"
    elif all(run["conclusion"] == "success" for run in summaries):
        state = "success"
    else:
        state = "unknown"
    return {"state": state, "runs": summaries}


def check_update(root: Path | None = None) -> dict[str, object]:
    root = Path.cwd() if root is None else Path(root)
    root = root.resolve()
    branch = _git(root, "branch", "--show-current")
    remote = _git(root, "remote", "get-url", "origin")
    if branch != "main" or remote not in REMOTE_URLS:
        raise UpdateError("update_requires_official_origin_on_main_branch")
    local_sha = _git(root, "rev-parse", "HEAD")
    latest = latest_commit()
    available = local_sha != latest["sha"]
    report: dict[str, object] = {
        "repository": f"{OWNER}/{REPOSITORY}",
        "branch": branch,
        "local_sha": local_sha,
        "latest_sha": latest["sha"],
        "latest_message": latest["message"],
        "update_available": available,
        "install_requires_confirmation": True,
    }
    if available:
        try:
            report["change_preview"] = change_preview(local_sha, latest["sha"])
        except UpdateError as exc:
            report["change_preview"] = {"state": "unavailable", "reason": str(exc)}
    try:
        report["ci"] = ci_summary(latest["sha"])
    except UpdateError as exc:
        report["ci"] = {"state": "unavailable", "reason": str(exc), "runs": []}
    return report


def install_update(root: Path | None = None, *, confirm: bool = False) -> dict[str, object]:
    if confirm is not True:
        raise UpdateError("explicit_confirmation_required")
    root = Path.cwd() if root is None else Path(root)
    root = root.resolve()
    state = check_update(root)
    if _git(root, "status", "--porcelain"):
        raise UpdateError("working_tree_not_clean; commit_or_stash_changes_first")
    previous = str(state["local_sha"])
    if not state["update_available"]:
        return {"updated": False, "reason": "already_up_to_date", "sha": previous}
    ci = state.get("ci", {})
    if isinstance(ci, dict) and ci.get("state") == "failure":
        raise UpdateError("latest_commit_ci_failed; update_install_blocked")
    _git(root, "fetch", "--no-tags", "origin", "main")
    target = _git(root, "rev-parse", "FETCH_HEAD")
    if target != state["latest_sha"]:
        raise UpdateError("remote_changed_during_update_check; run_check_again")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", previous, target],
        cwd=root, check=False, capture_output=True, text=True,
    )
    if ancestry.returncode != 0:
        raise UpdateError("update_is_not_a_fast_forward; manual_review_required")

    _git(root, "merge", "--ff-only", target)
    install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", "."],
        cwd=root, check=False, capture_output=True, text=True,
    )
    if install.returncode:
        _git(root, "reset", "--hard", previous)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", "."],
            cwd=root, check=False, capture_output=True, text=True,
        )
        raise UpdateError("package_install_failed; source_checkout_rolled_back")
    return {"updated": True, "previous_sha": previous, "installed_sha": target}


def main_result(action: str, root: Path | None = None, confirm: bool = False) -> dict[str, object]:
    if action == "check":
        return check_update(root)
    if action == "install":
        return install_update(root, confirm=confirm)
    raise UpdateError("unknown_update_action")
