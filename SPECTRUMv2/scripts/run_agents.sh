#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# From SPECTRUMv2 root:
#   bash scripts/run_agents.sh
#
# Notes:
# - Requires pyyaml: pip install pyyaml
# - Uses local Ollama if enabled in agents/config.yaml

PYTHON_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN="python3"
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[!] Python not found in PATH. Activate your env or set PYTHON_BIN."
  exit 1
fi

export PYTHONPATH="$ROOT:$ROOT/src:${PYTHONPATH:-}"
"$PYTHON_BIN" -m agents.run agents/config.yaml
