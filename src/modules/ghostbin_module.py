from __future__ import annotations

import os


ENABLED = os.getenv("ACE_T_ENABLE_GHOSTBIN", "0").strip().lower() in {"1", "true", "yes"}


def ingest_ghostbin() -> None:
    """Placeholder for Ghostbin ingestion (disabled by default)."""
    if not ENABLED:
        print("[ghostbin] disabled (set ACE_T_ENABLE_GHOSTBIN=1 to enable)")
        return
    print("[ghostbin] enabled but not implemented in ACE-T SPECTRUM yet")
