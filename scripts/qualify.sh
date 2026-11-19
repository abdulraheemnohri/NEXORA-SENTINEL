#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'

if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON" -m venv .venv
fi
VENV_PYTHON=".venv/bin/python"

"$VENV_PYTHON" -m pip install --upgrade pip
"$VENV_PYTHON" -m pip install -e ".[dev]" build
"$VENV_PYTHON" -m pip check
"$VENV_PYTHON" -m ruff check src tests
"$VENV_PYTHON" -m pytest
"$VENV_PYTHON" -m compileall -q src
"$VENV_PYTHON" -m build --wheel
".venv/bin/nexora" --help
".venv/bin/nexora" settings diff --help

echo "NEXORA Sentinel qualification checks passed on this host."
