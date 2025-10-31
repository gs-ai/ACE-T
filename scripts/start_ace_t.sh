#!/usr/bin/env bash
# ACE-T startup (robust)
# - change to repo root
# - prefer `conda run -n ace-t-env` when available
# - skip failing alembic migrations but attempt them

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

# Build command prefixes for conda-run if available; otherwise fall back to system python
if command -v conda >/dev/null 2>&1 && conda run --help >/dev/null 2>&1; then
  CONDA_RUN=(conda run -n ace-t-env --no-capture-output)
  PYTHON_CMD=("${CONDA_RUN[@]}" python)
  ALEMBIC_CMD=("${CONDA_RUN[@]}" alembic)
else
  PYTHON_BIN="$(command -v python3 || command -v python || true)"
  if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] No python interpreter found in PATH. Install python3 or set up conda." >&2
    exit 1
  fi
  PYTHON_CMD=("$PYTHON_BIN")
  ALEMBIC_CMD=("$(command -v alembic || true)")
fi

echo "[+] Cleaning workspace..."
"${PYTHON_CMD[@]}" scripts/clean_ace_t.py || true

echo "[+] Running Alembic migrations (attempt)..."
if [ -n "${ALEMBIC_CMD[0]:-}" ]; then
  # don't let alembic failure stop the whole startup; log and continue
  if ! "${ALEMBIC_CMD[@]}" upgrade head; then
    echo "[!] alembic upgrade failed (continuing)"
  fi
else
  echo "[!] alembic not found in PATH; skipping migrations"
fi

echo "[+] Starting ACE-T orchestrator..."
"${PYTHON_CMD[@]}" scripts/ace_t_orchestrator.py

# End of script
