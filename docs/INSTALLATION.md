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


## Optional LiteRT-LM local inference

The official Google CLI requires Python 3.10 or newer. From the activated NEXORA virtual environment:

```bash
nexora litertlm install --confirm
nexora litertlm doctor
```

The command installs the official `litert-lm` package into the active Python environment. On Android Debian ARM64, package/wheel availability is environment-dependent; if installation fails, retain the rest of NEXORA and review the error rather than substituting an unrelated runtime.

Local model files belong in `models/`. Set `runtime_enabled: true` in `config/litertlm.yaml` only after reviewing the model and resource requirements. Network model downloads remain disabled by default; enabling them requires both the settings switch and a per-command confirmation. Python presets remain disabled.

```bash
nexora litertlm models
nexora litertlm run --model your-model.litertlm --prompt "Hello" --confirm-inference
nexora litertlm chat --model your-model.litertlm --confirm-inference

# Optional Hugging Face import + inference (large network download)
# First set network_downloads_enabled: true in config/litertlm.yaml.
nexora litertlm run \
  --from-huggingface-repo=litert-community/Qwen3-4B-Thinking-2507 \
  --prompt "Hello" --confirm-download --confirm-inference
```

CPU is the default backend. Use `--backend gpu` only if the installed runtime and device support it. NEXORA's adapter does not invoke presets or model-provided tools. The Qwen3-4B-Thinking-2507 repository's main model bundle is approximately 2.5 GB; reserve sufficient disk and free RAM. On phones, stop if the OS reports memory pressure. Actual Pixel/Android Debian compatibility remains unverified. The local web dashboard exposes runtime status at `/api/runtime`; it is read-only and never starts inference.
