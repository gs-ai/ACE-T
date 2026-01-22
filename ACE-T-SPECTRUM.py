#!/usr/bin/env python3
from __future__ import annotations

import sys

from spectrum_export.build_graph_3d import build_graph_3d


def main() -> int:
    try:
        build_graph_3d()
    except Exception as exc:
        print(f"[ACE-T-SPECTRUM] build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
