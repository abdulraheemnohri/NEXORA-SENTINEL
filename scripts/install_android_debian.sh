#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"'
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
mkdir -p data models && chmod 700 data models
echo "Installed. Run .venv/bin/nexora status"
