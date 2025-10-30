#!/usr/bin/env bash
# ACE-T Unified Startup Script (robust, portable)
# - changes working dir to repo root
# - prefers `conda run -n ace-t-env` when available
# - falls back to system python3/python

# Resolve script dir and change to repo root so relative paths work
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

# If user has a local anaconda install, try to source it (non-fatal)
if [ -f "$HOME/anaconda3/etc/profile.d/conda.sh" ]; then
  # shellcheck source=/dev/null
  source "$HOME/anaconda3/etc/profile.d/conda.sh" || true
fi

# Prefer using `conda run` if available (runs in ace-t-env without requiring activation)
if command -v conda >/dev/null 2>&1 && conda run --help >/dev/null 2>&1; then
  PYTHON_CMD=(conda run -n ace-t-env --no-capture-output python)
  ALEMBIC_CMD=(conda run -n ace-t-env --no-capture-output alembic)
else
  # Fallback to system python3 or python
  PYTHON_BIN="$(command -v python3 || command -v python || true)"
  if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] No python interpreter found in PATH. Install python3 or set up conda." >&2
    exit 1
  fi
  PYTHON_CMD=("$PYTHON_BIN")
  ALEMBIC_CMD=("$(command -v alembic || true)")
fi

# Also attempt a non-fatal conda activate for interactive shells
if command -v conda >/dev/null 2>&1; then
  conda activate ace-t-env || true
fi

echo "[+] Cleaning workspace..."
"${PYTHON_CMD[@]}" scripts/clean_ace_t.py

echo "[+] Running Alembic migrations..."
if [ -n "${ALEMBIC_CMD[0]}" ]; then
  "${ALEMBIC_CMD[@]}" upgrade head || echo "[!] alembic upgrade failed (continuing)"
else
  echo "[!] alembic not found in PATH; skipping migrations"
fi

echo "[+] Starting ACE-T orchestrator..."
"${PYTHON_CMD[@]}" scripts/ace_t_orchestrator.py

# End of script
