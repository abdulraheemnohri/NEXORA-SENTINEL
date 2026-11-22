from __future__ import annotations

import json
import multiprocessing
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora._oversight_impl import Witness
from nexora.oversight.witness import (
    IndependentWitness,
    WitnessVerificationError,
    verify_witness_chain,
)


def _write_private_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        path.chmod(0o600)
    return key


def _signed_worker(path: str, key_path: str, worker: int, count: int) -> None:
    witness = IndependentWitness(Path(path), Path(key_path))
    for item in range(count):
        digest = f"{worker:02x}{item:02x}" + "a" * 60
        witness.attest(digest, "concurrency.test")


def _legacy_worker(path: str, worker: int, count: int) -> None:
    witness = Witness(Path(path))
    for item in range(count):
        digest = f"{worker:02x}{item:02x}" + "b" * 60
        witness.attest(digest, "legacy.concurrency.test")


def _join(processes: list[multiprocessing.Process]) -> None:
    for process in processes:
        process.join(30)
        if process.is_alive():
            process.terminate()
            process.join()
    assert [process.exitcode for process in processes] == [0] * len(processes)


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")


def test_signed_witness_refuses_symlink_destination_without_touching_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unrelated.jsonl"
    target.write_text("preserve-this\n", encoding="utf-8")
    target.chmod(0o644)
    original_mode = stat.S_IMODE(target.stat().st_mode)
    link = tmp_path / "witness.jsonl"
    _symlink(link, target)

    with pytest.raises(OSError, match="regular non-symlink"):
        IndependentWitness(link, Ed25519PrivateKey.generate())

    assert target.read_text(encoding="utf-8") == "preserve-this\n"
    assert stat.S_IMODE(target.stat().st_mode) == original_mode


def test_signed_witness_append_refuses_path_replaced_by_symlink(tmp_path: Path) -> None:
    path = tmp_path / "witness.jsonl"
    witness = IndependentWitness(path, Ed25519PrivateKey.generate())
    target = tmp_path / "unrelated.jsonl"
    target.write_text("untouched\n", encoding="utf-8")
    path.unlink()
    _symlink(path, target)

    with pytest.raises(OSError, match="regular non-symlink"):
        witness.attest("a" * 64, "must.not.append")

    assert target.read_text(encoding="utf-8") == "untouched\n"


def test_signed_witness_verification_refuses_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "real.jsonl"
    key = Ed25519PrivateKey.generate()
    IndependentWitness(target, key).attest("c" * 64, "test")
    link = tmp_path / "alias.jsonl"
    _symlink(link, target)

    with pytest.raises(WitnessVerificationError, match="witness_log_unreadable"):
        verify_witness_chain(link, key.public_key())


def test_signed_witness_refuses_non_regular_destination(tmp_path: Path) -> None:
    path = tmp_path / "witness-dir"
    path.mkdir()
    with pytest.raises(OSError, match="regular non-symlink"):
        IndependentWitness(path, Ed25519PrivateKey.generate())


def test_signed_witness_serializes_concurrent_process_appends(tmp_path: Path) -> None:
    key_path = tmp_path / "keys" / "witness.pem"
    key = _write_private_key(key_path)
    path = tmp_path / "witness.jsonl"
    IndependentWitness(path, key_path)
    context = multiprocessing.get_context("spawn")
    workers, per_worker = 4, 10
    processes = [
        context.Process(
            target=_signed_worker,
            args=(str(path), str(key_path), worker, per_worker),
        )
        for worker in range(workers)
    ]
    for process in processes:
        process.start()
    _join(processes)

    report = verify_witness_chain(path, key.public_key())
    assert report["valid"] is True
    assert report["count"] == workers * per_worker
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [row["payload"]["sequence"] for row in rows] == list(
        range(1, workers * per_worker + 1)
    )
    assert len({row["payload"]["event_hash"] for row in rows}) == workers * per_worker


def test_legacy_witness_refuses_symlink_destination_without_touching_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "legacy-target.jsonl"
    target.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "legacy.jsonl"
    _symlink(link, target)

    with pytest.raises(OSError, match="regular non-symlink"):
        Witness(link)

    assert target.read_text(encoding="utf-8") == "keep\n"


def test_legacy_witness_serializes_concurrent_process_appends(tmp_path: Path) -> None:
    path = tmp_path / "legacy.jsonl"
    context = multiprocessing.get_context("spawn")
    workers, per_worker = 4, 10
    processes = [
        context.Process(
            target=_legacy_worker,
            args=(str(path), worker, per_worker),
        )
        for worker in range(workers)
    ]
    for process in processes:
        process.start()
    _join(processes)

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == workers * per_worker
    assert all(row["event_type"] == "legacy.concurrency.test" for row in rows)
    assert len({row["witness_hash"] for row in rows}) == workers * per_worker
