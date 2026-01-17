from __future__ import annotations

import os


ENABLED = os.getenv("ACE_T_ENABLE_PASTEBIN", "0").strip().lower() in {"1", "true", "yes"}


def ingest_pastebin() -> None:
    """Placeholder for Pastebin ingestion (disabled by default)."""
    if not ENABLED:
        print("[pastebin] disabled (set ACE_T_ENABLE_PASTEBIN=1 to enable)")
        return
    print("[pastebin] enabled but not implemented in ACE-T SPECTRUM yet")
