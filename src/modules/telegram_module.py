from __future__ import annotations

import os


ENABLED = os.getenv("ACE_T_ENABLE_TELEGRAM", "0").strip().lower() in {"1", "true", "yes"}


def ingest_telegram() -> None:
    """Placeholder for Telegram ingestion (disabled by default)."""
    if not ENABLED:
        print("[telegram] disabled (set ACE_T_ENABLE_TELEGRAM=1 to enable)")
        return
    print("[telegram] enabled but not implemented in ACE-T SPECTRUM yet")
