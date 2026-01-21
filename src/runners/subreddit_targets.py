from __future__ import annotations

from typing import Iterable, List, Set, Tuple
from urllib.parse import urlparse

# ============================================================
# ACE-T — Subreddit Target Ingestion List
# Drop directly into VSC / config / pipeline
# ============================================================

SUBREDDITS = {
    "osint_threat_intel": [
        "https://www.reddit.com/r/InfoSecNews/new/",
        "pwnhub/new/",
        "OSINT/new/",
        "threatintel/new/",
        "Malware/new/",
        "ReverseEngineering/new/",
        "computerforensics/new/",
        "phishing/new/",
        "blueteamsec/new/",
        "netsec/new/",
        "redteamsec/new/",
        "sysadmin/new/",
        "cybersecurity/new/",
        "IncidentResponse/new/",
    ],
}


def _normalize_subreddit(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        hostname = (parsed.hostname or "").lower()
        if not hostname.endswith("reddit.com"):
            return ""
        value = parsed.path
    elif value.startswith("www.reddit.com"):
        parsed = urlparse(f"https://{value}")
        hostname = (parsed.hostname or "").lower()
        if not hostname.endswith("reddit.com"):
            return ""
        value = parsed.path
    marker = "/r/"
    if marker in value:
        value = value.split(marker, 1)[1]
    value = value.strip("/")
    lower_value = value.lower()
    if lower_value.endswith("/new"):
        value = value[: -len("/new")]
    elif lower_value == "new":
        return ""
    return value.strip("/").lower()


def _is_reddit_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    return hostname == "reddit.com" or hostname.endswith(".reddit.com")


def _hsl_to_rgb(h: float, s: float, l: float) -> Tuple[int, int, int]:
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


def _color_for_index(index: int, total: int) -> str:
    if total <= 0:
        return "#22d3ee"
    hue = (index * (360.0 / total)) % 360
    sat = 72
    light = 52
    r, g, b = _hsl_to_rgb(hue, sat, light)
    return f"#{r:02x}{g:02x}{b:02x}"


def _flatten(groups: Iterable[Iterable[str]]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for group in groups:
        for sub in group:
            normalized = _normalize_subreddit(sub)
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(normalized)
    return ordered


NORMALIZED_SUBREDDITS = {k: _flatten([v]) for k, v in SUBREDDITS.items()}

DEFAULT_SUBREDDITS = _flatten(SUBREDDITS.values())

SUBREDDIT_COLORS = {
    sub: _color_for_index(idx, len(DEFAULT_SUBREDDITS))
    for idx, sub in enumerate(DEFAULT_SUBREDDITS)
}
