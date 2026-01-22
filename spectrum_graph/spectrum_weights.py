from __future__ import annotations

import math
from typing import Any, Dict


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def volume_weight(node: Dict[str, Any], degree: int = 0) -> float:
    alert_count = _safe_float(node.get("alert_count") or node.get("alerts") or node.get("alertTotal"), 0.0)
    ioc_count = _safe_float(node.get("ioc_count") or node.get("iocs") or node.get("iocTotal"), 0.0)
    evidence_count = _safe_float(node.get("evidence_count") or node.get("volume") or node.get("volume_count"), 0.0)
    sightings = _safe_float(node.get("sightings") or node.get("sighting_count"), 0.0)
    total = alert_count + ioc_count + evidence_count + sightings
    if total <= 0.0:
        total = max(1.0, float(degree or 1))
    return max(1.0, total)


def energy_weight(node: Dict[str, Any]) -> float:
    return _clamp01(_safe_float(node.get("spectrum_index"), 0.0))


def node_repulsion(node: Dict[str, Any]) -> float:
    spec = energy_weight(node)
    vol = volume_weight(node, int(node.get("degree") or 0))
    volume_boost = 1.0 + (math.log1p(vol) * 0.15)
    return (1.0 - spec) * volume_boost


def node_stability(node: Dict[str, Any]) -> float:
    spec = energy_weight(node)
    convergence = _clamp01(_safe_float(node.get("convergence"), 0.0))
    return _clamp01(0.35 + (0.45 * spec) + (0.2 * convergence))


def edge_coherence(src: Dict[str, Any], tgt: Dict[str, Any]) -> float:
    a = energy_weight(src)
    b = energy_weight(tgt)
    similarity = 1.0 - abs(a - b)
    conv = min(
        _clamp01(_safe_float(src.get("convergence"), 0.0)),
        _clamp01(_safe_float(tgt.get("convergence"), 0.0)),
    )
    coherence = (0.7 * similarity) + (0.3 * conv)
    return _clamp01(coherence)
