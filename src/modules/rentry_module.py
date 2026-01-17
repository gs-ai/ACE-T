from __future__ import annotations

import os


ENABLED = os.getenv("ACE_T_ENABLE_RENTRY", "0").strip().lower() in {"1", "true", "yes"}


def ingest_rentry() -> None:
    """Placeholder for Rentry ingestion (disabled by default)."""
    if not ENABLED:
        print("[rentry] disabled (set ACE_T_ENABLE_RENTRY=1 to enable)")
        return
    print("[rentry] enabled but not implemented in ACE-T SPECTRUM yet")
