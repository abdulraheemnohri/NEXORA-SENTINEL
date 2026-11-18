#!/usr/bin/env bash
set -euo pipefail
python -m pip install -e . pytest ruff
ruff check src tests
pytest
python -m compileall -q src
