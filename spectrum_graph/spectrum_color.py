from __future__ import annotations

import colorsys
from typing import Any, Tuple

from spectrum_core.spectrum_math import clamp_normalize

SPECTRUM_STOPS = [
    (0.00, (179, 0, 0)),    # deep red
    (0.20, (255, 122, 0)),  # orange
    (0.40, (140, 212, 0)),  # yellow-green
    (0.60, (0, 179, 255)),  # cyan-blue
    (0.80, (75, 44, 255)),  # indigo
    (1.00, (127, 0, 255)),  # violet
]


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _base_rgb(spectrum_index: float) -> Tuple[float, float, float]:
    idx = clamp_normalize(spectrum_index, default=0.5, label="spectrum_index")
    for i in range(len(SPECTRUM_STOPS) - 1):
        a_pos, a_rgb = SPECTRUM_STOPS[i]
        b_pos, b_rgb = SPECTRUM_STOPS[i + 1]
        if idx <= b_pos:
            span = max(1e-6, b_pos - a_pos)
            t = (idx - a_pos) / span
            return (
                _lerp(a_rgb[0], b_rgb[0], t),
                _lerp(a_rgb[1], b_rgb[1], t),
                _lerp(a_rgb[2], b_rgb[2], t),
            )
    return float(SPECTRUM_STOPS[-1][1][0]), float(SPECTRUM_STOPS[-1][1][1]), float(SPECTRUM_STOPS[-1][1][2])


def spectrum_hsl(
    spectrum_index: Any,
    confidence: Any,
    recency: Any,
) -> Tuple[float, float, float]:
    base = _base_rgb(float(spectrum_index or 0.0))
    r, g, b = (base[0] / 255.0, base[1] / 255.0, base[2] / 255.0)
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    sat = clamp_normalize(0.35 + (0.65 * clamp_normalize(confidence, default=0.5, label="confidence")), default=0.5)
    val = clamp_normalize(0.25 + (0.75 * clamp_normalize(recency, default=0.5, label="recency")), default=0.5)
    r2, g2, b2 = colorsys.hsv_to_rgb(h, sat, val)
    h2, l2, s2 = colorsys.rgb_to_hls(r2, g2, b2)
    return (h2 * 360.0), s2, l2


def spectrum_rgb(
    spectrum_index: Any,
    confidence: Any,
    recency: Any,
) -> Tuple[int, int, int]:
    base = _base_rgb(float(spectrum_index or 0.0))
    r, g, b = (base[0] / 255.0, base[1] / 255.0, base[2] / 255.0)
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    sat = clamp_normalize(0.35 + (0.65 * clamp_normalize(confidence, default=0.5, label="confidence")), default=0.5)
    val = clamp_normalize(0.25 + (0.75 * clamp_normalize(recency, default=0.5, label="recency")), default=0.5)
    r2, g2, b2 = colorsys.hsv_to_rgb(h, sat, val)
    return int(r2 * 255), int(g2 * 255), int(b2 * 255)


def spectrum_color(
    spectrum_index: Any,
    confidence: Any,
    recency: Any,
) -> str:
    r, g, b = spectrum_rgb(spectrum_index, confidence, recency)
    return f"#{r:02x}{g:02x}{b:02x}"


def spectrum_color_payload(
    spectrum_index: Any,
    confidence: Any,
    recency: Any,
) -> dict:
    hue, sat, light = spectrum_hsl(spectrum_index, confidence, recency)
    rgb = spectrum_rgb(spectrum_index, confidence, recency)
    return {
        "spectrum_color": spectrum_color(spectrum_index, confidence, recency),
        "rgb": rgb,
        "hsl": (round(hue, 3), round(sat, 4), round(light, 4)),
    }
