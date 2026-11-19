import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexora.cli import main


def _key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path


def test_witness_independence_cli_reports_local_only_separation(tmp_path, capsys):
    backup = _key(tmp_path / "backup" / "backup.pem")
    update = _key(tmp_path / "update" / "update.pem")
    witness = _key(tmp_path / "witness" / "witness.pem")

    result = main([
        "witness-independence",
        "--backup-private-key", str(backup),
        "--update-private-key", str(update),
        "--witness-private-key", str(witness),
    ])
    report = json.loads(capsys.readouterr().out)

    assert result == 0
    assert report["status"] == "LOCAL_SEPARATION_CHECK_PASSED"
    assert report["independence"]["off_device_custody"] == "NOT_VERIFIED"
    assert report["independence"]["hardware_backing"] == "NOT_VERIFIED"
    assert report["controls"]["key_files_modified"] is False
