#!/usr/bin/env bash
set -euo pipefail
ruff check src tests
python -m compileall -q src
python -m pytest
python -m nexora.cli --help >/dev/null
