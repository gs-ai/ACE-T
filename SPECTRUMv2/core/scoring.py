from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Tuple

from core.band import band_weight, confidence_cap, dominant_band


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _as_list(value: Any) -> List:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def score_objects(
    objects: Iterable[Dict[str, Any]],
    scoring_cfg: Dict[str, Any],
    band_lookup: Dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    band_lookup = band_lookup or {}
    band_weights = scoring_cfg.get("band_weights") or {}
    edge_weight_rules = {r.get("edge_type"): r.get("base") for r in scoring_cfg.get("edge_weight_rules", [])}
    confidence_rules = scoring_cfg.get("confidence_rules") or {}
    evidence_boost = float(confidence_rules.get("evidence_count_boost", 0.0))
    cross_band_boost = float(confidence_rules.get("cross_band_boost", 0.0))
    contradiction_penalty = float(confidence_rules.get("contradiction_penalty", 0.0))

    scored: List[Dict[str, Any]] = []
    for obj in objects:
        obj_type = obj.get("type")
        band = str(obj.get("band") or band_lookup.get(obj.get("id")) or "").upper() or None
        base_conf = obj.get("confidence")
        if base_conf is None:
            base_conf = 0.5
        base_conf = _clamp(float(base_conf))
        band_w = float(band_weights.get(band, band_weight(band)))

        evidence = _as_list(obj.get("evidence"))
        evidence_ids = [e.get("artifact_id") for e in evidence if isinstance(e, dict)]
        evidence_ids = [e for e in evidence_ids if e]
        evidence_count = len(set(evidence_ids))
        confidence = base_conf + (evidence_count * evidence_boost)

        if evidence_ids:
            evidence_bands = {band_lookup.get(eid) for eid in evidence_ids if band_lookup.get(eid)}
            if len(evidence_bands) > 1:
                confidence += cross_band_boost

        if obj_type == "claim" and obj.get("claim_type") == "DENIAL":
            confidence -= contradiction_penalty

        confidence *= band_w
        confidence = _clamp(confidence, 0.0, confidence_cap(band))
        obj["confidence"] = round(confidence, 4)
        if band:
            obj["band"] = band

        if obj_type == "edge":
            edge_type = obj.get("edge_type")
            base = float(edge_weight_rules.get(edge_type, obj.get("weight") or 10.0))
            obj["weight"] = round(base * (1.0 + math.log1p(band_w)), 3)
        scored.append(obj)

    return scored


def build_band_index(objects: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for obj in objects:
        obj_id = obj.get("id")
        band = obj.get("band")
        if obj_id and band:
            mapping[obj_id] = str(band).upper()
    return mapping


def dominant_band_for_objects(objects: Iterable[Dict[str, Any]]) -> str:
    bands = [str(o.get("band") or "").upper() for o in objects if o.get("band")]
    return dominant_band(bands)
