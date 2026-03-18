from __future__ import annotations

import hashlib
import json
import math
import time
import os
import ipaddress
import re
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, Iterable, Tuple

from schema import validate_elements
from core.band import BAND_WEIGHTS, band_weight, dominant_band

try:
    from spectrum_core.core import (
        band_weight_from_severity,
        clamp01,
        compute_convergence_scalar,
        compute_spectrum_index,
        spectral_color,
        spectral_color_from_source,
    )
except Exception:
    band_weight_from_severity = None
    clamp01 = None
    compute_convergence_scalar = None
    compute_spectrum_index = None
    spectral_color = None
    spectral_color_from_source = None

try:
    from sources.source_colors import SOURCE_COLORS
except Exception:
    SOURCE_COLORS = {}

OUT_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "graph_data.json"
POS_CACHE = OUT_PATH.with_name("graph_positions.json")

# Volume-only sizing
VOLUME_MIN_SIZE = 12
VOLUME_MAX_SIZE = 100
VOLUME_SCALE = 16.0
BAND_WEIGHT_MAX = max(BAND_WEIGHTS.values()) if BAND_WEIGHTS else 1.0

RELATION_BASE_WEIGHTS = {
    "source_cluster": 1.2,
    "mentions": 1.2,
    "indicator_overlap": 1.6,
    "domain_overlap": 1.4,
    "cross_match": 1.8,
}


def _hash_float(key: str, salt: str, lo: float, hi: float) -> float:
    """
    Deterministic pseudo-random number in [lo, hi] based on the node/edge id.
    Keeps placement stable between runs while still jittering new nodes.
    """
    digest = hashlib.sha1(f"{salt}:{key}".encode("utf-8")).digest()
    n = int.from_bytes(digest[:8], "big") / float(2**64)
    return lo + (hi - lo) * n


def _load_saved_positions() -> Dict[str, Dict[str, float]]:
    """
    Load any previously persisted positions from graph_data.json or graph_positions.json.
    Supports both element lists and simple {id: {x, y}} mappings.
    """
    positions: Dict[str, Dict[str, float]] = {}
    for path in (POS_CACHE, OUT_PATH):
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if isinstance(payload, dict) and all(isinstance(v, dict) for v in payload.values()):
            for nid, pos in payload.items():
                if isinstance(pos, dict) and "x" in pos and "y" in pos:
                    positions[nid] = {"x": float(pos["x"]), "y": float(pos["y"])}
            continue

        elements = payload.get("elements") if isinstance(payload, dict) else payload
        if not isinstance(elements, list):
            continue
        for el in elements:
            if not isinstance(el, dict):
                continue
            data = el.get("data") or {}
            nid = data.get("id")
            pos = el.get("position")
            if nid and isinstance(pos, dict) and "x" in pos and "y" in pos:
                positions[nid] = {"x": float(pos["x"]), "y": float(pos["y"])}
    return positions


def _seed_position(nid: str, neighbors: Iterable[str], saved: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    """
    Place a new node near any positioned neighbors; otherwise spread nodes on a deterministic spiral.
    """
    neighbor_positions = [saved[n] for n in neighbors if n in saved]
    if neighbor_positions:
        avg_x = sum(p["x"] for p in neighbor_positions) / len(neighbor_positions)
        avg_y = sum(p["y"] for p in neighbor_positions) / len(neighbor_positions)
        jitter = _hash_float(nid, "jitter", -90.0, 90.0)
        return {"x": avg_x + jitter, "y": avg_y + _hash_float(nid, "jitterY", -90.0, 90.0)}

    # No neighbors with positions; distribute on a stable spiral to avoid overlap
    angle = _hash_float(nid, "angle", 0.0, math.tau)
    radius = 280.0 + _hash_float(nid, "radius", 0.0, 140.0)
    return {"x": math.cos(angle) * radius, "y": math.sin(angle) * radius}


def _root_domain(host: str) -> str:
    host = host.strip().lower().strip(".")
    if not host:
        return ""
    try:
        ip = ipaddress.ip_address(host.split(":")[0])
        return ip.compressed
    except Exception:
        pass
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _extract_domain(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        return _root_domain(parsed.netloc or "")
    if text.startswith("www."):
        return _root_domain(text[4:])
    if "/" in text or "?" in text:
        parsed = urlparse(f"//{text}")
        return _root_domain(parsed.netloc or "")
    return _root_domain(text)


def _node_domain(node: Dict) -> str:
    indicator = str(node.get("indicator") or "").strip()
    if indicator:
        return _extract_domain(indicator)
    url = str(node.get("post_url") or node.get("url") or "").strip()
    if url:
        return _extract_domain(url)
    label = str(node.get("label") or "").strip()
    if "://" in label:
        return _extract_domain(label.split()[0])
    return ""


def _volume_count(node: Dict) -> int:
    alert_count = node.get("alert_count") or node.get("alerts") or node.get("alertTotal")
    ioc_count = node.get("ioc_count") or node.get("iocs") or node.get("iocTotal")
    evidence_count = node.get("evidence_count") or node.get("volume")
    total = 0
    for v in (alert_count, ioc_count, evidence_count):
        try:
            total += int(v or 0)
        except Exception:
            continue
    if total <= 0:
        kind = str(node.get("kind") or "").lower()
        total = 1 if kind in {"alert", "ioc"} else 1
    return max(1, total)


def _band_to_unit(band: str | None, severity: str | None) -> float:
    raw = band_weight(band)
    if BAND_WEIGHT_MAX > 0:
        norm = raw / BAND_WEIGHT_MAX
    else:
        norm = 1.0
    if band_weight_from_severity is not None:
        fallback = band_weight_from_severity(severity)
        return max(fallback, min(1.0, norm))
    return max(0.0, min(1.0, norm))


def _infer_band(node: Dict) -> str:
    band = str(node.get("band") or "").strip().upper()
    if band:
        return band
    source = str(node.get("source") or "").strip().lower()
    subsource = str(node.get("subsource") or "").strip().lower()
    kind = str(node.get("kind") or "").strip().lower()
    if source == "reddit" or subsource == "reddit":
        return "VISIBLE"
    if kind in {"ioc", "alert"}:
        return "FM"
    if source:
        return "FM"
    return ""


_DOMAIN_TOKEN_RE = re.compile(
    r"(https?://[^\s)]+|(?:[a-z0-9-]{1,63}\.)+[a-z]{2,})(?::\d+)?",
    re.I,
)


def _extract_domains_from_text(text: str) -> set[str]:
    if not text:
        return set()
    domains: set[str] = set()
    for match in _DOMAIN_TOKEN_RE.findall(text):
        token = match.strip().strip(").,;\"'")
        if not token:
            continue
        domain = _extract_domain(token)
        if domain and len(domain) >= 4:
            domains.add(domain)
        if len(domains) >= 6:
            break
    return domains


def emit_graph(nodes: Iterable[Dict], edges: Iterable[Dict]) -> None:
    def data_view(item: Dict) -> Dict:
        return item.get("data") if "data" in item else item

    node_map = {data_view(n)["id"]: data_view(n) for n in nodes}
    edge_map = {data_view(e)["id"]: data_view(e) for e in edges}
    saved_positions = _load_saved_positions()

    # Global retention: drop nodes/edges older than ACE_T_RETENTION_DAYS (default 30)
    now = time.time()
    indicator_hits: Dict[str, int] = {nid: 0 for nid in node_map}
    temporal_sum: Dict[str, float] = {nid: 0.0 for nid in node_map}
    temporal_count: Dict[str, int] = {nid: 0 for nid in node_map}
    try:
        retention_days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    except Exception:
        retention_days = 30
    cutoff = now - (retention_days * 86400)
    initial_node_count = len(node_map)
    initial_edge_count = len(edge_map)
    # Keep nodes whose timestamp is within the cutoff; default to 'now' if missing
    node_map = {nid: n for nid, n in node_map.items() if float(n.get("timestamp", now)) >= cutoff}
    # Remove edges where source/target have been pruned
    edge_map = {eid: e for eid, e in edge_map.items() if e.get("source") in node_map and e.get("target") in node_map}
    pruned_nodes = initial_node_count - len(node_map)
    pruned_edges = initial_edge_count - len(edge_map)
    if pruned_nodes or pruned_edges:
        print(f"[emit_graph] pruned {pruned_nodes} nodes and {pruned_edges} edges older than {retention_days} days")

    # Degree and time-decay sizing
    degree = {nid: 0 for nid in node_map}
    neighbors: Dict[str, set] = {nid: set() for nid in node_map}
    for e in edge_map.values():
        src = e.get("source")
        tgt = e.get("target")
        if src in degree:
            degree[src] += 1
            neighbors[src].add(tgt)
        if tgt in degree:
            degree[tgt] += 1
            neighbors[tgt].add(src)

    # Pre-compute node domains, source keys, timestamps for enrichment
    node_domain: Dict[str, str] = {}
    node_source_key: Dict[str, str] = {}
    node_ts: Dict[str, float] = {}
    node_band: Dict[str, str] = {}
    node_band_weight: Dict[str, float] = {}
    for nid, n in node_map.items():
        node_domain[nid] = _node_domain(n)
        node_source_key[nid] = str(n.get("subsource") or n.get("source") or "").strip().lower()
        node_ts[nid] = float(n.get("timestamp", now) or now)
        band = _infer_band(n)
        if band:
            node_band[nid] = band
            n["band"] = band
        band_w = band_weight(band)
        node_band_weight[nid] = band_w
        n.setdefault("object_type", n.get("type") or n.get("kind") or "node")

    # Signal density: non-duplicate signals per 24h window, grouped by source/subsource
    density_counts: Dict[str, int] = {}
    recent_cutoff = now - 86400.0
    per_source_signals: Dict[str, set] = {}
    for nid, n in node_map.items():
        if node_ts.get(nid, 0.0) < recent_cutoff:
            continue
        key = node_source_key.get(nid, "")
        if not key:
            continue
        indicator = str(n.get("indicator") or n.get("label") or n.get("id") or "").strip().lower()
        if not indicator:
            continue
        per_source_signals.setdefault(key, set()).add(indicator)
    for key, values in per_source_signals.items():
        density_counts[key] = len(values)

    # Cross-source vs same-source degrees and domain convergence stats
    cross_source_degree: Dict[str, int] = {nid: 0 for nid in node_map}
    same_source_degree: Dict[str, int] = {nid: 0 for nid in node_map}
    domain_neighbors: Dict[str, set] = {nid: set() for nid in node_map}
    domain_edge_counts: Dict[str, int] = {nid: 0 for nid in node_map}
    for e in edge_map.values():
        src = e.get("source")
        tgt = e.get("target")
        if not src or not tgt:
            continue
        src_key = node_source_key.get(src, "")
        tgt_key = node_source_key.get(tgt, "")
        if src in cross_source_degree and tgt in cross_source_degree:
            if src_key and tgt_key and src_key != tgt_key:
                cross_source_degree[src] += 1
                cross_source_degree[tgt] += 1
            else:
                same_source_degree[src] += 1
                same_source_degree[tgt] += 1
        tgt_domain = node_domain.get(tgt, "")
        if src in domain_edge_counts and tgt_domain:
            domain_edge_counts[src] += 1
            domain_neighbors[src].add(tgt_domain)
        src_domain = node_domain.get(src, "")
        if tgt in domain_edge_counts and src_domain:
            domain_edge_counts[tgt] += 1
            domain_neighbors[tgt].add(src_domain)

    now = time.time()

    def time_decay(ts: float, half_life_hours: float = 48.0) -> float:
        age_hours = max(0.0, (now - ts) / 3600.0)
        return math.exp(-age_hours / half_life_hours)

    for nid, n in node_map.items():
        ts = float(n.get("timestamp", now))
        decay = time_decay(ts)
        original_confidence = float(n.get("confidence", 0.5) or 0.5)
        domain_total = domain_edge_counts.get(nid, 0)
        unique_domains = len(domain_neighbors.get(nid, set()))
        domain_convergence_score = (unique_domains / domain_total) if domain_total > 0 else 0.0
        x_degree = cross_source_degree.get(nid, 0)
        s_degree = same_source_degree.get(nid, 0)
        signal_density = float(density_counts.get(node_source_key.get(nid, ""), 0))

        adjusted_confidence = (
            original_confidence
            + (domain_convergence_score * 0.8)
            + (math.log1p(x_degree) * 0.6)
        )
        if s_degree > 12 and domain_convergence_score < 0.25:
            adjusted_confidence *= 0.85
        adjusted_confidence = max(0.0, min(1.0, adjusted_confidence))
        n["adjusted_confidence"] = round(adjusted_confidence, 4)
        n["confidence"] = adjusted_confidence

        adjusted_recency = decay * (1.0 + (signal_density * 0.15))
        if clamp01 is not None:
            adjusted_recency = clamp01(adjusted_recency, 0.0)
        else:
            adjusted_recency = max(0.0, min(1.0, adjusted_recency))
        n["recency"] = round(adjusted_recency, 4)
        n["domain_convergence_score"] = round(domain_convergence_score, 4)
        n["cross_source_degree"] = int(x_degree)
        n["same_source_degree"] = int(s_degree)
        n["signal_density"] = round(signal_density, 4)

        band_w = node_band_weight.get(nid, 1.0)
        n["band_weight"] = round(band_w, 3)
        volume = _volume_count(n)
        n["volume_count"] = int(volume)
        size = VOLUME_MIN_SIZE + (math.log1p(volume) * VOLUME_SCALE)
        n["size"] = max(VOLUME_MIN_SIZE, min(VOLUME_MAX_SIZE, int(round(size))))
        # Preserve existing color/opacity if set
        n.setdefault("opacity", 1.0)

        if "position" not in n:
            n_pos = saved_positions.get(nid) or _seed_position(nid, neighbors[nid], saved_positions)
            n["position"] = n_pos

    # Cross-source connectors: link Reddit alerts to matching feed indicators
    try:
        reddit_nodes = [n for n in node_map.values() if str(n.get("source") or "").lower() == "reddit"]
        other_nodes = [n for n in node_map.values() if str(n.get("source") or "").lower() != "reddit"]
        indicator_map = {}
        domain_map: Dict[str, set] = {}
        for n in other_nodes:
            indicator = str(n.get("indicator") or n.get("label") or "").strip()
            node_id = n.get("id")
            dom = node_domain.get(node_id) if node_id else ""
            if not dom:
                dom = _extract_domain(indicator)
            if dom and len(dom) >= 4:
                domain_map.setdefault(dom, set()).add(n.get("id"))
            if len(indicator) < 6:
                continue
            key = indicator.lower()
            indicator_map.setdefault(key, set()).add(n.get("id"))
        indicators = list(indicator_map.items())[:2000]
        for r in reddit_nodes:
            label_text = str(r.get("label") or "")
            label = label_text.lower()
            if not label and not label_text:
                continue
            r_id = r.get("id")
            if not r_id:
                continue
            for indicator, node_ids in indicators:
                if indicator in label:
                    for nid in node_ids:
                        if not nid:
                            continue
                        eid = f"cross::{nid}→{r_id}"
                        if eid in edge_map:
                            continue
                        edge_map[eid] = {
                            "id": eid,
                            "source": nid,
                            "target": r_id,
                            "relation": "cross_match",
                            "weight": 1.8,
                        }
            domains = set()
            r_domain = node_domain.get(r_id, "")
            if r_domain:
                domains.add(r_domain)
            domains.update(_extract_domains_from_text(label_text))
            domain_links = 0
            for dom in domains:
                if dom not in domain_map:
                    continue
                for nid in domain_map.get(dom, set()):
                    if not nid:
                        continue
                    eid = f"cross::domain::{dom}::{nid}→{r_id}"
                    if eid in edge_map:
                        continue
                    edge_map[eid] = {
                        "id": eid,
                        "source": nid,
                        "target": r_id,
                        "relation": "cross_match",
                        "weight": 1.7,
                    }
                    domain_links += 1
                    if domain_links >= 20:
                        break
                if domain_links >= 20:
                    break
    except Exception:
        pass

    # Indicator overlap: connect alerts/IOCs that share the same indicator value across sources
    try:
        indicator_index: Dict[str, list] = {}
        for n in node_map.values():
            if n.get("kind") in {"source_hub", "relation_hub"}:
                continue
            if n.get("kind") not in {"ioc", "alert"}:
                continue
            indicator = str(n.get("indicator") or n.get("label") or "").strip()
            if len(indicator) < 6:
                continue
            key = indicator.lower()
            indicator_index.setdefault(key, []).append(n)

        max_edges_per_indicator = 30
        for key, nodes_for_indicator in indicator_index.items():
            if len(nodes_for_indicator) < 2:
                continue
            # Connect only across different sources/subsources to keep noise low
            for i in range(len(nodes_for_indicator)):
                a = nodes_for_indicator[i]
                a_id = a.get("id")
                if not a_id:
                    continue
                a_src = str(a.get("subsource") or a.get("source") or "").lower()
                for j in range(i + 1, len(nodes_for_indicator)):
                    if max_edges_per_indicator <= 0:
                        break
                    b = nodes_for_indicator[j]
                    b_id = b.get("id")
                    if not b_id:
                        continue
                    b_src = str(b.get("subsource") or b.get("source") or "").lower()
                    if not a_src or not b_src or a_src == b_src:
                        continue
                    eid = f"overlap::{key}::{a_id}→{b_id}"
                    if eid in edge_map:
                        continue
                    edge_map[eid] = {
                        "id": eid,
                        "source": a_id,
                        "target": b_id,
                        "relation": "indicator_overlap",
                        "weight": 1.6,
                    }
                    max_edges_per_indicator -= 1
    except Exception:
        pass

    # Domain overlap: connect alerts/IOCs that share the same root domain across sources
    try:
        domain_index: Dict[str, list] = {}
        for n in node_map.values():
            if n.get("kind") in {"source_hub", "relation_hub"}:
                continue
            if n.get("kind") not in {"ioc", "alert"}:
                continue
            nid = n.get("id")
            dom = node_domain.get(nid) if nid else ""
            if not dom or len(dom) < 4:
                continue
            domain_index.setdefault(dom, []).append(n)

        max_edges_per_domain = 20
        for dom, nodes_for_domain in domain_index.items():
            if len(nodes_for_domain) < 2:
                continue
            for i in range(len(nodes_for_domain)):
                if max_edges_per_domain <= 0:
                    break
                a = nodes_for_domain[i]
                a_id = a.get("id")
                if not a_id:
                    continue
                a_src = str(a.get("subsource") or a.get("source") or "").lower()
                for j in range(i + 1, len(nodes_for_domain)):
                    if max_edges_per_domain <= 0:
                        break
                    b = nodes_for_domain[j]
                    b_id = b.get("id")
                    if not b_id:
                        continue
                    b_src = str(b.get("subsource") or b.get("source") or "").lower()
                    if not a_src or not b_src or a_src == b_src:
                        continue
                    eid = f"domain::{dom}::{a_id}→{b_id}"
                    if eid in edge_map:
                        continue
                    edge_map[eid] = {
                        "id": eid,
                        "source": a_id,
                        "target": b_id,
                        "relation": "domain_overlap",
                        "weight": 1.4,
                    }
                    max_edges_per_domain -= 1
    except Exception:
        pass

    # Edge semantic metadata (preserved across avg-mass normalization)
    for e in edge_map.values():
        src = e.get("source")
        tgt = e.get("target")
        relation = str(e.get("relation") or "").strip().lower()
        base_relation_weight = float(RELATION_BASE_WEIGHTS.get(relation, e.get("weight", 1.0) or 1.0))
        ts_a = node_ts.get(src, 0.0)
        ts_b = node_ts.get(tgt, 0.0)
        if ts_a and ts_b:
            diff = abs(ts_a - ts_b)
            temporal_alignment = math.exp(-diff / (48.0 * 3600.0))
        else:
            temporal_alignment = 0.0
        if src in temporal_sum:
            temporal_sum[src] += temporal_alignment
            temporal_count[src] += 1
        if tgt in temporal_sum:
            temporal_sum[tgt] += temporal_alignment
            temporal_count[tgt] += 1
        a_domain = node_domain.get(src, "")
        b_domain = node_domain.get(tgt, "")
        cross_domain_flag = bool(a_domain and b_domain and a_domain != b_domain)
        evidence_count = 2 if relation == "indicator_overlap" else 1
        semantic_weight = base_relation_weight * (1.0 + temporal_alignment) * (1.6 if cross_domain_flag else 1.0)
        semantic_weight = max(0.0, min(3.0, semantic_weight))
        e["semantic_weight"] = round(semantic_weight, 4)
        e["cross_domain_flag"] = bool(cross_domain_flag)
        e["temporal_alignment"] = round(temporal_alignment, 4)
        e["evidence_count"] = int(evidence_count)
        if relation in {"indicator_overlap", "domain_overlap", "cross_match"}:
            if src in indicator_hits:
                indicator_hits[src] += 1
            if tgt in indicator_hits:
                indicator_hits[tgt] += 1
        src_band = node_band.get(src, "")
        tgt_band = node_band.get(tgt, "")
        edge_band = dominant_band([src_band, tgt_band])
        if edge_band:
            e["band"] = edge_band
        e.setdefault("object_type", "edge")

    # Spectrum index + convergence (continuous)
    for nid, n in node_map.items():
        if clamp01 is not None and n.get("spectrum_index") is not None:
            _ = clamp01(n.get("spectrum_index"), 0.0, "spectrum_index", f"node={nid}")
        band = node_band.get(nid, "")
        band_unit = _band_to_unit(band, n.get("severity"))
        temporal_align = temporal_sum.get(nid, 0.0) / max(1, temporal_count.get(nid, 0))
        domain_conv = float(n.get("domain_convergence_score", 0.0) or 0.0)
        indicator_conv = 0.0
        if degree.get(nid, 0) > 0:
            indicator_conv = indicator_hits.get(nid, 0) / max(1.0, float(degree.get(nid, 0)))
        cross_sources = cross_source_degree.get(nid, 0)
        evidence = n.get("volume_count", 1)

        if compute_spectrum_index is not None:
            spectrum_index = compute_spectrum_index(
                band_unit,
                n.get("confidence", 0.5),
                cross_sources,
                evidence,
                domain_conv,
                indicator_conv,
                temporal_align,
            )
        else:
            spectrum_index = max(0.0, min(1.0, band_unit))

        if compute_convergence_scalar is not None:
            convergence = compute_convergence_scalar(
                cross_sources,
                evidence,
                domain_conv,
                indicator_conv,
                temporal_align,
            )
        else:
            convergence = max(0.0, min(1.0, temporal_align))

        n["temporal_alignment"] = round(temporal_align, 4)
        n["indicator_convergence"] = round(indicator_conv, 4)
        n["spectrum_band_weight"] = round(band_unit, 4)
        n["spectrum_index"] = round(spectrum_index, 4)
        n["convergence"] = round(convergence, 4)
        energy_mass = 0.8 + (spectrum_index * 2.8) + (convergence * 1.6)
        n["mass"] = round(energy_mass, 3)

        src_key = node_source_key.get(nid, "")
        source_color = SOURCE_COLORS.get(src_key, "")
        if spectral_color_from_source is not None:
            spectral = spectral_color_from_source(
                spectrum_index,
                n.get("confidence", 0.5),
                n.get("recency", 0.5),
                source_color,
            )
        elif spectral_color is not None:
            spectral = spectral_color(spectrum_index, n.get("confidence", 0.5), n.get("recency", 0.5))
        else:
            spectral = n.get("color") or source_color or "#22d3ee"
        n["spectral_color"] = spectral
        if source_color:
            n["source_color"] = source_color
        n["color"] = spectral

    # Edge weights for bundling + tension
    for e in edge_map.values():
        src = e.get("source")
        tgt = e.get("target")
        src_spec = float(node_map.get(src, {}).get("spectrum_index", _band_to_unit("", None)))
        tgt_spec = float(node_map.get(tgt, {}).get("spectrum_index", _band_to_unit("", None)))
        spec_avg = (src_spec + tgt_spec) / 2.0
        min_spec = min(src_spec, tgt_spec)
        dispersion = abs(src_spec - tgt_spec)
        coherence = max(0.05, 1.0 - dispersion)
        conv_boost = max(
            float(node_map.get(src, {}).get("convergence", 0.0)),
            float(node_map.get(tgt, {}).get("convergence", 0.0)),
        )
        e["spectrum_low"] = round(min(src_spec, tgt_spec), 4)
        e["spectrum_high"] = round(max(src_spec, tgt_spec), 4)
        energy_weight = (0.8 + (spec_avg * 1.4) + (conv_boost * 1.0)) * (0.6 + (0.8 * coherence))
        e["weight"] = round(energy_weight, 3)
        e["dispersion"] = round(dispersion, 4)
        e["edge_strength"] = round(coherence, 4)
        edge_opacity = 0.08 + (0.72 * coherence) * (0.45 + (0.55 * min_spec))
        edge_opacity *= 0.5 + (0.5 * float(e.get("temporal_alignment", 0.0)))
        edge_opacity *= 0.7 + (conv_boost * 0.6)
        e["edge_opacity"] = round(max(0.05, min(0.95, edge_opacity)), 4)
        e["edge_thickness"] = round(0.35 + (2.2 * coherence) * (0.5 + (0.5 * min_spec)), 3)
        # Stable control-point offset keeps bundled edges separated without overdraw
        curve_base = _hash_float(str(e.get("id", f"{src}-{tgt}")), "curve", -120.0, 120.0)
        e["curve_offset"] = curve_base * (0.5 + (dispersion * 1.1) + ((1.0 - min_spec) * 0.6))

    elements = []

    positions_only: Dict[str, Dict[str, float]] = {}
    for nid, n in node_map.items():
        pos = n.pop("position", None)
        if isinstance(pos, dict) and "x" in pos and "y" in pos:
            positions_only[nid] = pos
        element = {"data": n}
        if pos:
            element["position"] = pos
        elements.append(element)

    for e in edge_map.values():
        elements.append({"data": e})

    validate_elements(elements)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(elements, indent=2), encoding="utf-8")
    if positions_only:
        POS_CACHE.write_text(json.dumps(positions_only, indent=2), encoding="utf-8")
