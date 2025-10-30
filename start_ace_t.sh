#!/usr/bin/env bash
# Compatibility shim: preserve the original repo-root entrypoint for callers.
# This simply execs the new script under `scripts/` and forwards all args.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/scripts/start_ace_t.sh" "$@"
#!/bin/bash
# ACE-T Unified Startup Script (Updated for 2025 modular structure)
# This script cleans, initializes, and launches all ACE-T components in one go.

# Activate conda environment
source ~/anaconda3/etc/profile.d/conda.sh
conda activate ace-t-env

# Clean workspace (logs, db, __pycache__)
echo "[+] Cleaning workspace..."
python clean_ace_t.py

# Run Alembic migrations to ensure DB is up to date
echo "[+] Running Alembic migrations..."
alembic upgrade head

# Start orchestrator (launches backend, OSINT monitor, log ingester, alert GUI)
echo "[+] Starting ACE-T orchestrator..."
python3 ace_t_orchestrator.py

# End of script
