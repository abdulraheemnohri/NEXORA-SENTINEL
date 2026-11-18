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


def test_check_reports_latest_commit(monkeypatch, tmp_path):
    root = repository(tmp_path)
    local = updater._git(root, "rev-parse", "HEAD")
    monkeypatch.setattr(updater, "latest_commit", lambda: {"sha": local, "message": "current"})
    report = updater.check_update(root)
    assert report["update_available"] is False
    assert report["branch"] == "main"
    assert report["install_requires_confirmation"] is True


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
    monkeypatch.setattr(
        updater, "latest_commit",
        lambda: {"sha": "a" * 40, "message": "new version"},
    )
    (root / "uncommitted.txt").write_text("keep me")
    with pytest.raises(updater.UpdateError, match="working_tree_not_clean"):
        updater.install_update(root, confirm=True)
    assert (root / "uncommitted.txt").read_text() == "keep me"
    assert updater._git(root, "rev-parse", "HEAD") == local
