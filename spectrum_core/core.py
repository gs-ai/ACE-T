from __future__ import annotations

import colorsys
import math
from typing import Optional


def clamp01(
    value: float | int | None,
    default: float = 0.0,
    label: Optional[str] = None,
    context: Optional[str] = None,
) -> float:
    try:
        if value is None:
            if label:
                _log_invalid(label, value, context)
            return default
        v = float(value)
    except Exception:
        if label:
            _log_invalid(label, value, context)
        return default
    if math.isnan(v) or math.isinf(v):
        if label:
            _log_invalid(label, value, context)
        return default
    if v < 0.0 or v > 1.0:
        if label:
            _log_invalid(label, v, context)
    return max(0.0, min(1.0, v))


def _log_invalid(label: str, value: object, context: Optional[str]) -> None:
    ctx = f" context={context}" if context else ""
    print(f"[spectrum_core] clamp {label} value={value!r}{ctx}")


def band_weight_from_severity(severity: str | None, fallback: float = 0.35) -> float:
    sev = str(severity or "").strip().lower()
    mapping = {
        "low": 0.2,
        "medium": 0.45,
        "high": 0.7,
        "critical": 0.92,
    }
    return clamp01(mapping.get(sev, fallback), fallback)


def _norm_count(value: float | int | None, scale: float) -> float:
    if scale <= 0:
        return 0.0
    v = max(0.0, float(value or 0.0))
    return 1.0 - math.exp(-v / scale)


def compute_convergence_scalar(
    cross_source_count: float | int | None,
    evidence_count: float | int | None,
    domain_convergence: float | int | None,
    indicator_convergence: float | int | None,
    temporal_alignment: float | int | None,
) -> float:
    cross_norm = _norm_count(cross_source_count, 3.2)
    evidence_norm = _norm_count(evidence_count, 5.0)
    domain_norm = clamp01(domain_convergence, 0.0)
    indicator_norm = clamp01(indicator_convergence, 0.0)
    temporal_norm = clamp01(temporal_alignment, 0.0)

    score = (
        0.28 * cross_norm
        + 0.2 * evidence_norm
        + 0.22 * domain_norm
        + 0.18 * indicator_norm
        + 0.12 * temporal_norm
    )
    return clamp01(score, 0.0)


def compute_spectrum_index(
    band_weight: float | int | None,
    confidence: float | int | None,
    cross_source_count: float | int | None,
    evidence_count: float | int | None,
    domain_convergence: float | int | None,
    indicator_convergence: float | int | None,
    temporal_alignment: float | int | None,
) -> float:
    band = clamp01(band_weight, 0.35)
    conf = clamp01(confidence, 0.5)
    cross_norm = _norm_count(cross_source_count, 4.0)
    evidence_norm = _norm_count(evidence_count, 5.5)
    domain_norm = clamp01(domain_convergence, 0.0)
    indicator_norm = clamp01(indicator_convergence, 0.0)
    temporal_norm = clamp01(temporal_alignment, 0.0)
    convergence = compute_convergence_scalar(
        cross_source_count,
        evidence_count,
        domain_convergence,
        indicator_convergence,
        temporal_alignment,
    )
    evidence_gate = 0.3 + (0.7 * conf)
    corroboration_gate = 0.35 + (0.65 * convergence)
    evidence_term = evidence_norm * evidence_gate * corroboration_gate

    score = (
        0.22 * band
        + 0.32 * conf
        + 0.18 * cross_norm
        + 0.08 * evidence_term
        + 0.1 * domain_norm
        + 0.06 * indicator_norm
        + 0.12 * convergence
        + 0.06 * temporal_norm
    )
    return clamp01(score, 0.0)


def spectral_color(
    spectrum_index: float | int | None,
    confidence: float | int | None,
    recency: float | int | None,
    *,
    low_hue: float = 210.0,
    high_hue: float = 0.0,
) -> str:
    idx = clamp01(spectrum_index, 0.35)
    conf = clamp01(confidence, 0.5)
    rec = clamp01(recency, 0.5)

    hue = (1.0 - idx) * (low_hue - high_hue) + high_hue
    sat = 0.42 + (0.55 * conf)
    light = 0.34 + (0.52 * rec)

    r, g, b = colorsys.hls_to_rgb(hue / 360.0, light, sat)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"


def _hex_to_rgb(hex_color: str) -> Optional[tuple[float, float, float]]:
    if not hex_color:
        return None
    value = hex_color.strip()
    if value.startswith("#"):
        value = value[1:]
    if len(value) != 6:
        return None
    try:
        r = int(value[0:2], 16) / 255.0
        g = int(value[2:4], 16) / 255.0
        b = int(value[4:6], 16) / 255.0
        return r, g, b
    except Exception:
        return None


def spectral_color_from_source(
    spectrum_index: float | int | None,
    confidence: float | int | None,
    recency: float | int | None,
    source_color: Optional[str] = None,
    *,
    hue_span: float = 90.0,
    low_hue: float = 210.0,
    high_hue: float = 0.0,
) -> str:
    idx = clamp01(spectrum_index, 0.35)
    conf = clamp01(confidence, 0.5)
    rec = clamp01(recency, 0.5)

    base_hue = None
    if source_color:
        rgb = _hex_to_rgb(source_color)
        if rgb:
            h, _l, _s = colorsys.rgb_to_hls(*rgb)
            base_hue = (h * 360.0) % 360.0

    if base_hue is None:
        return spectral_color(idx, conf, rec, low_hue=low_hue, high_hue=high_hue)

    shift = (idx - 0.5) * hue_span
    hue = (base_hue + shift) % 360.0
    sat = 0.35 + (0.55 * conf)
    light = 0.28 + (0.52 * rec) + (0.12 * idx)
    light = max(0.18, min(0.82, light))
    r, g, b = colorsys.hls_to_rgb(hue / 360.0, light, sat)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"
