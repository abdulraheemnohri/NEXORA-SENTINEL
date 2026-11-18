# Installation

## Debian / Ubuntu / Android Debian

Python 3.11 or newer is required. From the repository root:

```bash
bash scripts/install_linux.sh
.venv/bin/nexora status
bash scripts/verify.sh
```

For Android Debian, use the dedicated `scripts/install_android_debian.sh` installer. Device-specific behavior must be verified on the target phone; remote CI does not establish Pixel hardware compatibility.

## Configuration

The conservative profiles are in `config/*.yaml`. The application settings loader uses YAML safe loading and rejects unknown keys. Policy, permissions, maturity, model and budget files are declarative review inputs; they do not dynamically grant runtime privileges.

## Data

Runtime data is local under `data/` by default. Protect the directory and signing private keys. Keep a copy of the backup manifest separate if you need an independent integrity reference.
