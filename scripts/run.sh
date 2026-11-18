#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .venv/bin/nexora ]]; then
  echo "Install first: bash scripts/install_linux.sh" >&2
  exit 2
fi
exec .venv/bin/nexora "$@"
