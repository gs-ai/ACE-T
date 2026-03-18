from __future__ import annotations

import logging
import sys

from src.modules.tiered_ingest import ingest_all


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    summary = ingest_all()
    print("[tiered_ingest] complete", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
