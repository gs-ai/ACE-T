from __future__ import annotations

from typing import Dict, Iterable, List, Set

from modules.realtime_open_feeds import THREAT_FEEDS
from runners.subreddit_targets import SUBREDDIT_COLORS


def _hsl_to_rgb(h: float, s: float, l: float) -> tuple[int, int, int]:
    s /= 100.0
    l /= 100.0
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60.0) % 2 - 1))
    m = l - c / 2
    if 0 <= h < 60:
        r, g, b = c, x, 0
    elif 60 <= h < 120:
        r, g, b = x, c, 0
    elif 120 <= h < 180:
        r, g, b = 0, c, x
    elif 180 <= h < 240:
        r, g, b = 0, x, c
    elif 240 <= h < 300:
        r, g, b = x, 0, c
    else:
        r, g, b = c, 0, x
    return (
        int(round((r + m) * 255)),
        int(round((g + m) * 255)),
        int(round((b + m) * 255)),
    )


def _color_from_hsl(h: float, s: float, l: float) -> str:
    r, g, b = _hsl_to_rgb(h, s, l)
    return f"#{r:02x}{g:02x}{b:02x}"


def _generate_palette(names: Iterable[str], used: Set[str]) -> Dict[str, str]:
    items = [n for n in names if n]
    total = max(1, len(items))
    colors: Dict[str, str] = {}
    for idx, name in enumerate(sorted(items)):
        hue = (idx * (360.0 / total)) % 360
        color = _color_from_hsl(hue, 68, 56)
        # Nudge hue until we avoid collisions with existing colors.
        tries = 0
        while color in used and tries < 12:
            hue = (hue + 19) % 360
            color = _color_from_hsl(hue, 68, 56)
            tries += 1
        colors[name] = color
        used.add(color)
    return colors


SUBREDDIT_SOURCE_COLORS = SUBREDDIT_COLORS
_used_colors = set(SUBREDDIT_SOURCE_COLORS.values())

FEED_SOURCE_COLORS = _generate_palette(THREAT_FEEDS.keys(), _used_colors)

SOURCE_COLORS: Dict[str, str] = {}
SOURCE_COLORS.update(SUBREDDIT_SOURCE_COLORS)
SOURCE_COLORS.update(FEED_SOURCE_COLORS)
