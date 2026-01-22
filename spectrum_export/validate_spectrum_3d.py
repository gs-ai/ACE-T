#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def _hex_to_rgb(value: str):
    text = (value or "").strip().lstrip("#")
    if len(text) != 6:
        return None
    try:
        r = int(text[0:2], 16)
        g = int(text[2:4], 16)
        b = int(text[4:6], 16)
        return r, g, b
    except Exception:
        return None


def _rgb_to_hue(r: int, g: int, b: int) -> float:
    rf, gf, bf = r / 255.0, g / 255.0, b / 255.0
    mx = max(rf, gf, bf)
    mn = min(rf, gf, bf)
    delta = mx - mn
    if delta == 0:
        return 0.0
    if mx == rf:
        h = ((gf - bf) / delta) % 6
    elif mx == gf:
        h = ((bf - rf) / delta) + 2
    else:
        h = ((rf - gf) / delta) + 4
    return (h * 60.0) % 360.0


def _bucket_for_hue(hue: float) -> str:
    if hue >= 330 or hue < 20:
        return "red"
    if hue < 45:
        return "orange"
    if hue < 95:
        return "yellow_green"
    if hue < 190:
        return "cyan_blue"
    if hue < 250:
        return "indigo"
    return "violet"


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "data" / "graph_3d.json"
    if not path.exists():
        print("FAIL missing graph_3d.json")
        return 1
    try:
        payload = json.loads(path.read_text())
    except Exception as exc:
        print(f"FAIL invalid json: {exc}")
        return 1

    nodes = payload.get("nodes") or []
    if not nodes:
        print("FAIL no nodes")
        return 1

    spectrum_values = [n.get("spectrum_index") for n in nodes if isinstance(n.get("spectrum_index"), (int, float))]
    coverage = len(spectrum_values) / max(1, len(nodes))
    if coverage < 0.95:
        print(f"FAIL spectrum_index coverage {coverage:.2%}")
        return 1

    if min(spectrum_values) > 0.05 or max(spectrum_values) < 0.95:
        print(f"FAIL spectrum_index spread min={min(spectrum_values):.3f} max={max(spectrum_values):.3f}")
        return 1

    buckets = set()
    for node in nodes:
        color = node.get("spectrum_color") or node.get("spectral_color") or ""
        rgb = _hex_to_rgb(color)
        if not rgb:
            continue
        hue = _rgb_to_hue(*rgb)
        buckets.add(_bucket_for_hue(hue))

    if len(buckets) < 6:
        print(f"FAIL hue buckets {sorted(buckets)}")
        return 1

    print(f"PASS nodes={len(nodes)} spectrum_range=({min(spectrum_values):.3f}-{max(spectrum_values):.3f}) buckets={len(buckets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
