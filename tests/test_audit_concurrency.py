"""Concurrency regressions for the append-only audit and kill-switch boundary."""
from __future__ import annotations

import multiprocessing
import os
import stat
from pathlib import Path

import pytest

from nexora.oversight import AuditLog, KillSwitch


def _append_audit_records(path: str, worker: int, count: int) -> None:
    log = AuditLog(Path(path))
    for item in range(count):
        log.append("concurrency.test", {"worker": worker, "item": item})


def _resume_with_pause(
    marker: str, audit_path: str, entered, release
) -> None:
    class PausingAudit:
        def append(self, event: str, payload: dict) -> dict:
            record = AuditLog(Path(audit_path)).append(event, payload)
            entered.set()
            if not release.wait(30):
                raise TimeoutError("resume test release timed out")
            return record

    KillSwitch(Path(marker)).clear_and_record(
        PausingAudit(), payload={"human_initiated": True}
    )


def _engage_and_signal(
    marker: str, audit_path: str, started, entered
) -> None:
    class SignallingAudit:
        def append(self, event: str, payload: dict) -> dict:
            entered.set()
            return AuditLog(Path(audit_path)).append(event, payload)

    started.set()
    KillSwitch(Path(marker)).engage_and_record(
        SignallingAudit(), reason="concurrency-test", payload={"source": "test"}
    )


def _join(processes: list[multiprocessing.Process]) -> None:
    for process in processes:
        process.join(30)
        if process.is_alive():
            process.terminate()
            process.join()
    assert [process.exitcode for process in processes] == [0] * len(processes)


def test_audit_append_serializes_multiple_processes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("spawn")
    workers = 4
    records_per_worker = 20
    processes = [
        context.Process(
            target=_append_audit_records,
            args=(str(path), worker, records_per_worker),
        )
        for worker in range(workers)
    ]
    for process in processes:
        process.start()
    _join(processes)

    log = AuditLog(path)
    entries = log.entries()
    expected_count = workers * records_per_worker
    assert log.verify()
    assert len(entries) == expected_count
    assert [entry["sequence"] for entry in entries] == list(
        range(1, expected_count + 1)
    )
    assert len({entry["hash"] for entry in entries}) == expected_count


def test_kill_and_resume_transitions_are_serialized(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    marker = tmp_path / "KILL"
    audit_path = tmp_path / "audit.jsonl"
    KillSwitch(marker).engage("initial")

    resume_entered = context.Event()
    release_resume = context.Event()
    kill_started = context.Event()
    kill_entered = context.Event()
    resume = context.Process(
        target=_resume_with_pause,
        args=(str(marker), str(audit_path), resume_entered, release_resume),
    )
    kill = context.Process(
        target=_engage_and_signal,
        args=(str(marker), str(audit_path), kill_started, kill_entered),
    )
    started: list[multiprocessing.Process] = []
    resume.start()
    started.append(resume)
    try:
        assert resume_entered.wait(15), "resume did not reach its audit boundary"
        kill.start()
        started.append(kill)
        assert kill_started.wait(15), "kill worker did not start"
        assert not kill_entered.wait(2), (
            "a concurrent kill entered its transition before resume completed"
        )
    finally:
        release_resume.set()
    _join(started)

    entries = AuditLog(audit_path).entries()
    assert [entry["event"] for entry in entries] == [
        "kill.cleared",
        "kill.engaged",
    ]
    assert KillSwitch(marker).is_engaged()


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="symlink lock rejection requires POSIX O_NOFOLLOW",
)
def test_audit_append_rejects_symlinked_lock_sidecar(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    target = tmp_path / "unrelated"
    target.write_text("", encoding="utf-8")
    path.with_name(path.name + ".lock").symlink_to(target)

    log = AuditLog(path)
    with pytest.raises(OSError, match="regular non-symlink"):
        log.append("must.not.append", {})

    assert log.entries() == []

@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="symlink audit-path rejection requires POSIX O_NOFOLLOW",
)
def test_audit_log_refuses_symlink_destination_without_touching_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unrelated"
    target.write_text("keep-me\n", encoding="utf-8")
    target.chmod(0o644)
    original_mode = stat.S_IMODE(target.stat().st_mode)
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)

    with pytest.raises(OSError, match="regular non-symlink"):
        AuditLog(link)

    assert target.read_text(encoding="utf-8") == "keep-me\n"
    assert stat.S_IMODE(target.stat().st_mode) == original_mode


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="symlink audit-path rejection requires POSIX O_NOFOLLOW",
)
def test_audit_append_refuses_path_replaced_by_symlink(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("before.swap", {"safe": True})
    target = tmp_path / "unrelated"
    target.write_text("untouched\n", encoding="utf-8")
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(OSError, match="regular non-symlink"):
        log.append("must.not.append", {})

    assert target.read_text(encoding="utf-8") == "untouched\n"
    assert log.verify() is False


def test_audit_log_refuses_non_regular_destination(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.mkdir()

    with pytest.raises(OSError):
        AuditLog(path)
