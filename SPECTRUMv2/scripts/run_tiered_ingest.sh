#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_BIN="${PYTHON_BIN:-python3}"

cd "$ROOT_DIR"
exec "$PY_BIN" -m src.runners.ingest_tiered_feeds
