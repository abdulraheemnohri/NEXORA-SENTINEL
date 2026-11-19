import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.witness_independence import (
    WitnessIndependenceError,
    inspect_witness_independence,
)


def _write_private(path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    if os.name == "posix":
        path.chmod(0o600)
    return path


def test_witness_independence_confirms_distinct_local_keys_and_paths(tmp_path):
    backup = _write_private(tmp_path / "backup" / "backup.pem", Ed25519PrivateKey.generate())
    update = _write_private(tmp_path / "update" / "update.pem", Ed25519PrivateKey.generate())
    witness = _write_private(tmp_path / "witness" / "witness.pem", Ed25519PrivateKey.generate())

    report = inspect_witness_independence(backup, update, witness)

    assert report["status"] == "LOCAL_SEPARATION_CHECK_PASSED"
    assert report["checks"]["fingerprints_unique"] is True
    assert report["checks"]["file_paths_unique"] is True
    assert report["checks"]["parent_directories_unique"] is True
    assert report["independence"]["off_device_custody"] == "NOT_VERIFIED"
    assert report["independence"]["hardware_backing"] == "NOT_VERIFIED"
    assert report["controls"]["read_only"] is True
    assert report["controls"]["private_key_material_exposed"] is False


def test_witness_independence_detects_reused_key_fingerprint(tmp_path):
    shared = Ed25519PrivateKey.generate()
    backup = _write_private(tmp_path / "backup" / "backup.pem", shared)
    update = _write_private(tmp_path / "update" / "update.pem", Ed25519PrivateKey.generate())
    witness = _write_private(tmp_path / "witness" / "witness.pem", shared)

    report = inspect_witness_independence(backup, update, witness)

    assert report["checks"]["fingerprints_unique"] is False
    assert report["status"] == "LOCAL_SEPARATION_NOT_ESTABLISHED"


def test_witness_independence_requires_separate_parent_directories(tmp_path):
    backup = _write_private(tmp_path / "keys" / "backup.pem", Ed25519PrivateKey.generate())
    update = _write_private(tmp_path / "keys" / "update.pem", Ed25519PrivateKey.generate())
    witness = _write_private(tmp_path / "keys" / "witness.pem", Ed25519PrivateKey.generate())

    report = inspect_witness_independence(backup, update, witness)

    assert report["checks"]["fingerprints_unique"] is True
    assert report["checks"]["file_paths_unique"] is True
    assert report["checks"]["parent_directories_unique"] is False
    assert report["status"] == "LOCAL_SEPARATION_NOT_ESTABLISHED"


def test_witness_independence_refuses_symlinked_key_file(tmp_path):
    target = _write_private(tmp_path / "target.pem", Ed25519PrivateKey.generate())
    link = tmp_path / "witness" / "key.pem"
    link.parent.mkdir()
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    update = _write_private(tmp_path / "update" / "update.pem", Ed25519PrivateKey.generate())
    extra = _write_private(tmp_path / "extra" / "extra.pem", Ed25519PrivateKey.generate())
    with pytest.raises(WitnessIndependenceError, match="witness_key_symlink_refused"):
        inspect_witness_independence(extra, update, link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission mode assertion")
def test_witness_independence_reports_open_private_key_permissions(tmp_path):
    backup = _write_private(tmp_path / "backup" / "backup.pem", Ed25519PrivateKey.generate())
    update = _write_private(tmp_path / "update" / "update.pem", Ed25519PrivateKey.generate())
    witness = _write_private(tmp_path / "witness" / "witness.pem", Ed25519PrivateKey.generate())
    witness.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)

    report = inspect_witness_independence(backup, update, witness)

    assert report["keys"][2]["private_key_permissions"] == "TOO_OPEN"
    assert report["checks"]["posix_private_permissions_restricted"] is False
    assert report["status"] == "LOCAL_SEPARATION_NOT_ESTABLISHED"
