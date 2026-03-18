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

# Force streaming off unless explicitly enabled by the caller
export ACE_T_ENABLE_STREAMING="${ACE_T_ENABLE_STREAMING:-0}"

# If artifacts exist and not forced, reuse cached data by default
if [[ "${ACE_T_FORCE_BUILD:-0}" != "1" ]]; then
  if [[ -f GRAPH_COPY/graph_3d_render.json || -f GRAPH_COPY/graph_3d.json ]]; then
    export ACE_T_SKIP_BUILD="1"
  fi
fi

# Reset generated artifacts unless explicitly told to reuse cached data
if [[ "${ACE_T_SKIP_BUILD:-0}" != "1" ]]; then
  rm -f GRAPH_COPY/graph_3d.json GRAPH_COPY/graph_3d_render.json GRAPH_COPY/data/sources.json || true
fi

# One-shot build + viewer server (streaming disabled by default)
exec "$PY_BIN" GRAPH_COPY/launch_viewer.py
