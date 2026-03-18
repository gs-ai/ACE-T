from __future__ import annotations

import json
import logging
import math
import time
from typing import Any, Optional

LOG = logging.getLogger(__name__)


def _log(event: str, **fields: Any) -> None:
    if not LOG.isEnabledFor(logging.DEBUG):
        return
    payload = {"event": event, **fields}
    LOG.debug(json.dumps(payload, sort_keys=True))


def clamp_normalize(
    value: Any,
    *,
    lo: float = 0.0,
    hi: float = 1.0,
    default: float = 0.0,
    label: Optional[str] = None,
    context: Optional[str] = None,
) -> float:
    try:
        v = float(value)
    except Exception:
        _log("clamp_invalid", label=label, value=value, context=context, default=default)
        return default
    if math.isnan(v) or math.isinf(v):
        _log("clamp_invalid", label=label, value=v, context=context, default=default)
        return default
    if v < lo or v > hi:
        _log("clamp_range", label=label, value=v, context=context, lo=lo, hi=hi)
    return max(lo, min(hi, v))


def _norm_count(value: Any, scale: float) -> float:
    if scale <= 0:
        return 0.0
    try:
        v = max(0.0, float(value or 0.0))
    except Exception:
        return 0.0
    return 1.0 - math.exp(-v / scale)


def recency_factor(timestamp: Any, now: Optional[float] = None, half_life_h: float = 48.0) -> float:
    ts = 0.0
    try:
        ts = float(timestamp or 0.0)
    except Exception:
        ts = 0.0
    if ts <= 0.0:
        return 0.5
    if now is None:
        now = time.time()
    age_s = max(0.0, now - ts)
    half_life_s = max(1.0, half_life_h * 3600.0)
    return math.exp(-math.log(2) * (age_s / half_life_s))


def extract_confidence(value: Any, fallback: float = 0.5) -> float:
    try:
        v = float(value)
    except Exception:
        return fallback
    if math.isnan(v) or math.isinf(v):
        return fallback
    if v > 1.0:
        v = v / 100.0
    return clamp_normalize(v, default=fallback, label="confidence")


def _stable_hash(text: str) -> float:
    h = 0
    for ch in text:
        h = ((h << 5) - h) + ord(ch)
        h &= 0xFFFFFFFF
    return (h % 100000) / 100000.0


def percentile_normalize(values: list[float], keys: Optional[list[str]] = None) -> list[float]:
    if not values:
        return []
    if len(values) == 1:
        return [0.5]
    if keys and len(keys) == len(values):
        indexed = sorted(
            enumerate(values),
            key=lambda x: (x[1], _stable_hash(str(keys[x[0]]))),
        )
    else:
        indexed = sorted(enumerate(values), key=lambda x: x[1])
    n = len(values)
    ranks = [0.0] * n
    for rank, (idx, _val) in enumerate(indexed):
        ranks[idx] = rank
    denom = max(1.0, n - 1)
    return [r / denom for r in ranks]


def compute_convergence_score(
    cross_source_count: Any,
    evidence_count: Any,
    domain_reuse: Any,
    temporal_alignment: Any,
) -> float:
    cross_norm = _norm_count(cross_source_count, 3.0)
    evidence_norm = _norm_count(evidence_count, 5.0)
    domain_norm = clamp_normalize(domain_reuse, default=0.0, label="domain_reuse")
    temporal_norm = clamp_normalize(temporal_alignment, default=0.0, label="temporal_alignment")

    score = (
        0.34 * cross_norm
        + 0.22 * evidence_norm
        + 0.24 * domain_norm
        + 0.2 * temporal_norm
    )
    score = clamp_normalize(score, default=0.0, label="convergence_score")
    _log(
        "convergence_score",
        cross_norm=round(cross_norm, 4),
        evidence_norm=round(evidence_norm, 4),
        domain_norm=round(domain_norm, 4),
        temporal_norm=round(temporal_norm, 4),
        score=round(score, 4),
    )
    return score


def compute_spectrum_index(
    band_weight: Any,
    confidence: Any,
    evidence_count: Any,
    cross_source_count: Any,
    domain_reuse: Any,
    temporal_alignment: Any,
) -> float:
    band = clamp_normalize(band_weight, default=0.35, label="band_weight")
    conf = clamp_normalize(confidence, default=0.5, label="confidence")
    cross_norm = _norm_count(cross_source_count, 4.0)
    evidence_norm = _norm_count(evidence_count, 6.0)
    domain_norm = clamp_normalize(domain_reuse, default=0.0, label="domain_reuse")
    temporal_norm = clamp_normalize(temporal_alignment, default=0.0, label="temporal_alignment")
    convergence = compute_convergence_score(
        cross_source_count,
        evidence_count,
        domain_reuse,
        temporal_alignment,
    )

    evidence_gate = 0.4 + (0.6 * conf)
    corroboration_gate = 0.35 + (0.65 * convergence)
    evidence_term = evidence_norm * evidence_gate * corroboration_gate

    score = (
        0.22 * band
        + 0.28 * conf
        + 0.18 * cross_norm
        + 0.12 * evidence_term
        + 0.12 * domain_norm
        + 0.08 * temporal_norm
        + 0.1 * convergence
    )
    score = clamp_normalize(score, default=0.0, label="spectrum_index")
    _log(
        "spectrum_index",
        band=round(band, 4),
        conf=round(conf, 4),
        cross_norm=round(cross_norm, 4),
        evidence_norm=round(evidence_norm, 4),
        domain_norm=round(domain_norm, 4),
        temporal_norm=round(temporal_norm, 4),
        convergence=round(convergence, 4),
        score=round(score, 4),
    )
    return score
