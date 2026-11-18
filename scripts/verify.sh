#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -x .venv/bin/ruff ]]; then .venv/bin/ruff check src tests; fi
if [[ -x .venv/bin/pytest ]]; then .venv/bin/pytest; else python3 -m pytest; fi
python3 -m compileall -q src
