from __future__ import annotations

import subprocess

import pytest

from nexora import updater


def git(path, *args):
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.email", "tests@example.invalid")
    git(root, "config", "user.name", "NEXORA tests")
    (root / "README.md").write_text("test\n")
    git(root, "add", "README.md")
    git(root, "commit", "-m", "initial")
    git(root, "remote", "add", "origin", "https://github.com/abdulraheemnohri/NEXORA-SENTINEL.git")
    return root


def stub_remote(monkeypatch, sha, message="new version", ci_state="success"):
    monkeypatch.setattr(updater, "latest_commit", lambda: {"sha": sha, "message": message})
    monkeypatch.setattr(
        updater, "change_preview",
        lambda *_: {"ahead_by": 1, "behind_by": 0, "files": [
            {"path": "src/example.py", "status": "modified", "additions": 2, "deletions": 1}
        ], "files_truncated": False},
    )
    monkeypatch.setattr(
        updater, "ci_summary",
        lambda *_: {"state": ci_state, "runs": [{"name": "CI", "status": "completed",
                                                "conclusion": ci_state, "url": ""}]},
    )


def test_latest_commit_rejects_invalid_github_response(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b'{"sha":"not-a-commit"}'

    monkeypatch.setattr(updater, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(updater.UpdateError, match="github_response_missing_valid_commit_sha"):
        updater.latest_commit()


def test_check_reports_current_commit(monkeypatch, tmp_path):
    root = repository(tmp_path)
    local = updater._git(root, "rev-parse", "HEAD")
    stub_remote(monkeypatch, local, "current")
    report = updater.check_update(root)
    assert report["update_available"] is False
    assert report["branch"] == "main"
    assert report["install_requires_confirmation"] is True
    assert report["ci"]["state"] == "success"


def test_check_includes_change_preview(monkeypatch, tmp_path):
    root = repository(tmp_path)
    stub_remote(monkeypatch, "a" * 40)
    report = updater.check_update(root)
    assert report["change_preview"]["ahead_by"] == 1
    assert report["change_preview"]["files"][0]["path"] == "src/example.py"


def test_install_requires_explicit_confirmation(tmp_path):
    with pytest.raises(updater.UpdateError, match="explicit_confirmation_required"):
        updater.install_update(tmp_path, confirm=False)


def test_check_rejects_non_official_remote(monkeypatch, tmp_path):
    root = repository(tmp_path)
    git(root, "remote", "set-url", "origin", "https://example.invalid/fork.git")
    with pytest.raises(updater.UpdateError, match="official_origin"):
        updater.check_update(root)


def test_check_rejects_non_main_branch(monkeypatch, tmp_path):
    root = repository(tmp_path)
    git(root, "checkout", "-b", "feature")
    with pytest.raises(updater.UpdateError, match="official_origin"):
        updater.check_update(root)


def test_install_refuses_dirty_worktree(monkeypatch, tmp_path):
    root = repository(tmp_path)
    local = updater._git(root, "rev-parse", "HEAD")
    stub_remote(monkeypatch, "a" * 40)
    (root / "uncommitted.txt").write_text("keep me")
    with pytest.raises(updater.UpdateError, match="working_tree_not_clean"):
        updater.install_update(root, confirm=True)
    assert (root / "uncommitted.txt").read_text() == "keep me"
    assert updater._git(root, "rev-parse", "HEAD") == local


def test_install_blocks_known_failed_ci(monkeypatch, tmp_path):
    root = repository(tmp_path)
    local = updater._git(root, "rev-parse", "HEAD")
    monkeypatch.setattr(updater, "check_update", lambda *_: {
        "local_sha": local, "latest_sha": "a" * 40, "update_available": True,
        "ci": {"state": "failure"},
    })
    with pytest.raises(updater.UpdateError, match="latest_commit_ci_failed"):
        updater.install_update(root, confirm=True)
