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
API_URL = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/commits/main"


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


def latest_commit(timeout: float = 10.0) -> dict[str, str]:
    request = Request(API_URL, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "NEXORA-Sentinel-Updater",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise UpdateError(f"github_update_check_failed: {type(exc).__name__}") from exc
    sha = payload.get("sha")
    if not isinstance(sha, str) or len(sha) != 40 or any(
        char not in "0123456789abcdef" for char in sha.lower()
    ):
        raise UpdateError("github_response_missing_valid_commit_sha")
    commit = payload.get("commit", {})
    message = commit.get("message", "") if isinstance(commit, dict) else ""
    return {"sha": sha, "message": str(message).splitlines()[0][:200]}


def check_update(root: Path = Path.cwd()) -> dict[str, object]:
    root = Path(root).resolve()
    branch = _git(root, "branch", "--show-current")
    remote = _git(root, "remote", "get-url", "origin")
    if branch != "main" or remote not in REMOTE_URLS:
        raise UpdateError("update_requires_official_origin_on_main_branch")
    local_sha = _git(root, "rev-parse", "HEAD")
    latest = latest_commit()
    return {
        "repository": f"{OWNER}/{REPOSITORY}",
        "branch": branch,
        "local_sha": local_sha,
        "latest_sha": latest["sha"],
        "latest_message": latest["message"],
        "update_available": local_sha != latest["sha"],
        "install_requires_confirmation": True,
    }


def install_update(root: Path = Path.cwd(), *, confirm: bool = False) -> dict[str, object]:
    if confirm is not True:
        raise UpdateError("explicit_confirmation_required")
    root = Path(root).resolve()
    state = check_update(root)
    if _git(root, "status", "--porcelain"):
        raise UpdateError("working_tree_not_clean; commit_or_stash_changes_first")
    previous = str(state["local_sha"])
    if not state["update_available"]:
        return {"updated": False, "reason": "already_up_to_date", "sha": previous}

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


def main_result(action: str, root: Path, confirm: bool = False) -> dict[str, object]:
    if action == "check":
        return check_update(root)
    if action == "install":
        return install_update(root, confirm=confirm)
    raise UpdateError("unknown_update_action")
