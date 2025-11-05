#!/usr/bin/env bash
# Compatibility shim: preserve the original repo-root entrypoint for callers.
# This simply execs the new script under `scripts/` and forwards all args.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/scripts/start_ace_t.sh" "$@"
