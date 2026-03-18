#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
  PY_BIN="python3"
fi
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
  echo "[!] Python not found in PATH. Activate your env or set PYTHON_BIN."
  exit 1
fi

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}"
exec "$PY_BIN" -m src.runners.ingest_tiered_feeds
