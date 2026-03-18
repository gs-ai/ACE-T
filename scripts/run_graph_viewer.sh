#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_BIN="${PYTHON_BIN:-python}"

cd "$ROOT_DIR"

# Stop any existing servers on port 8000
if command -v lsof >/dev/null 2>&1; then
  lsof -ti :8000 | xargs -r kill -9 || true
fi

# Stop any stray streaming builders
pkill -f "build_graph.py --streaming" >/dev/null 2>&1 || true

# Reset generated artifacts
rm -f GRAPH_COPY/graph_3d.json GRAPH_COPY/graph_3d_render.json GRAPH_COPY/data/sources.json || true

# One-shot build + viewer server (streaming disabled by default)
exec "$PY_BIN" GRAPH_COPY/launch_viewer.py
