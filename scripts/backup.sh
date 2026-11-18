#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# -gt 0 ]]; then exec .venv/bin/nexora backup "$1"; fi
exec .venv/bin/nexora backup
