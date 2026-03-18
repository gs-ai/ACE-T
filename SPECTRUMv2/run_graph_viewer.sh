#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
  PY_BIN="python3"
fi

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR:$ROOT_DIR/src:${PYTHONPATH:-}"

# Keep live and historical viewers on the exact same script.
if [[ -f graph/ace_t_spectrum_3d.html ]]; then
  mkdir -p gui
  cp graph/ace_t_spectrum_3d.html gui/ace_t_spectrum_3d.html || true
fi

# Stop any existing servers on port 8000
if command -v lsof >/dev/null 2>&1; then
  lsof -ti :8000 | xargs -r kill -9 || true
fi

# Stop any stray streaming builders
pkill -f "build_graph.py --streaming" >/dev/null 2>&1 || true
pkill -f "graph/launch_viewer.py" >/dev/null 2>&1 || true

# Force streaming off unless explicitly enabled by the caller
export ACE_T_ENABLE_STREAMING="${ACE_T_ENABLE_STREAMING:-0}"

# Default to rebuild unless explicitly skipped by caller
if [[ -z "${ACE_T_SKIP_BUILD+x}" ]]; then
  export ACE_T_SKIP_BUILD="0"
fi

# Only skip build when explicitly requested
if [[ "${ACE_T_FORCE_BUILD:-0}" == "1" ]]; then
  export ACE_T_SKIP_BUILD="0"
fi

# Reset generated artifacts unless explicitly told to reuse cached data
if [[ "${ACE_T_SKIP_BUILD:-0}" != "1" ]]; then
  rm -f graph/graph_3d.json graph/graph_3d_render.json || true
fi

# One-shot build + viewer server (streaming disabled by default)
exec "$PY_BIN" graph/launch_viewer.py
