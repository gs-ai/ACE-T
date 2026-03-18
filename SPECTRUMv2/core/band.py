from __future__ import annotations

from typing import Dict, Iterable

BAND_WEIGHTS: Dict[str, float] = {
    "GAMMA": 1.9,
    "XRAY": 1.6,
    "UV": 1.3,
    "IR": 1.3,
    "VISIBLE": 1.0,
    "RADAR": 1.2,
    "FM": 1.4,
    "TV": 0.9,
    "SHORTWAVE": 1.1,
    "AM": 0.6,
}

BAND_PRIORITY = {
    "GAMMA": 10,
    "XRAY": 9,
    "UV": 8,
    "IR": 7,
    "RADAR": 6,
    "FM": 5,
    "TV": 4,
    "SHORTWAVE": 3,
    "VISIBLE": 2,
    "AM": 1,
}

BAND_CONFIDENCE_CAP = {
    "GAMMA": 1.0,
    "XRAY": 1.0,
    "UV": 0.95,
    "IR": 0.95,
    "RADAR": 0.9,
    "FM": 0.9,
    "TV": 0.85,
    "SHORTWAVE": 0.85,
    "VISIBLE": 0.75,
    "AM": 0.6,
}


def band_weight(band: str | None) -> float:
    if not band:
        return 1.0
    return float(BAND_WEIGHTS.get(band.upper(), 1.0))


def confidence_cap(band: str | None) -> float:
    if not band:
        return 1.0
    return float(BAND_CONFIDENCE_CAP.get(band.upper(), 1.0))


def dominant_band(bands: Iterable[str]) -> str:
    best = ""
    score = -1
    for band in bands:
        key = str(band or "").upper()
        if key and BAND_PRIORITY.get(key, 0) > score:
            best = key
            score = BAND_PRIORITY.get(key, 0)
    return best
