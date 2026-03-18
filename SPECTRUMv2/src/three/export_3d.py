#!/usr/bin/env python3
"""
Export a 3D-ready graph from graph_data.json + graph_positions.json.

- Uses cached 2D positions (x, y) if present.
- Computes z from: (mass/threat/recency) so "hot" clusters rise.
- Emits data/graph_3d.json: compact nodes + edges for WebGL.

No changes to ingestion. Safe read-only conversion.
"""
from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any, Dict, List

try:
    from sources.source_colors import SOURCE_COLORS as SOURCE_COLOR_MAP
except Exception:
    SOURCE_COLOR_MAP = {}

try:
    from spectrum_core.core import band_weight_from_severity, clamp01, spectral_color, spectral_color_from_source
except Exception:
    band_weight_from_severity = None
    clamp01 = None
    spectral_color = None
    spectral_color_from_source = None

ROOT = Path(__file__).resolve().parents[2]
GRAPH_PATH = ROOT / "data" / "graph_data.json"
POS_PATH = ROOT / "data" / "graph_positions.json"
OUT_PATH = ROOT / "data" / "graph_3d.json"
SURV_PATH = ROOT / "data" / "surveillance.json"  # watch state persisted by Dash UI

# ---- tuning (Apple Silicon friendly) ----
MAX_NODES = 6000          # clamp for sanity; increase later if needed
MAX_EDGES = 12000
Z_CLAMP = 2600.0
XY_SCALE = 1.7            # increased to spread out clusters more
Z_SCALE = 900.0           # "lift" multiplier (more depth)
RECENCY_HALFLIFE_H = 48.0 # matches 2D decay doctrine

# ---- deterministic force pass (export-time only) ----
FORCE_ITERATIONS = 120        # more passes for extra settling
EDGE_IDEAL = 100.0            # preferred edge length (pull if stretched, push if squashed)
EDGE_ATTRACT_K = 0.006        # spring strength for real edges
REPULSE_RADIUS = 220.0        # broader repulsion to keep clusters apart
REPULSE_K = 480.0             # stronger base repulsion
WELL_ATTRACT_K = 0.004        # convergence wells (spectrum gravity)
ANCHOR_K = 0.006              # keep high-energy truth anchors stable
CENTER_PULL_K = 0.0025        # pull high-energy nodes toward spectrum center
OUTWARD_DRIFT_K = 0.6         # push low-energy noise outward
STEP_SIZE = 0.025             # integration step
MAX_STEP_DELTA = 10.0         # clamp per-axis delta to avoid spikes
XY_CLAMP = 1600.0             # keep layout bounded horizontally



def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def _is_edge(el: Dict[str, Any]) -> bool:
    d = el.get("data", {})
    return "source" in d and "target" in d


def _safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _hash_unit(text: str, salt: str) -> float:
    seed = f"{salt}:{text}"
    h = 0
    for ch in seed:
        h = ((h << 5) - h) + ord(ch)
        h &= 0xFFFFFFFF
    return (h % 100000) / 100000.0


def _recency_weight(ts: float, now: float) -> float:
    if not ts:
        return 0.5
    age_s = max(0.0, now - ts)
    half_life_s = RECENCY_HALFLIFE_H * 3600.0
    return math.exp(-math.log(2) * (age_s / half_life_s))


def _z_from(node: Dict[str, Any], now: float) -> float:
    """
    z encodes momentum:
    - spectrum_index (signal energy), convergence, confidence, and recency lift z upward
    - older/low-signal sinks toward 0
    """
    d = node["data"]
    spec = _safe_float(d.get("spectrum_index", -1.0), -1.0)
    if spec < 0.0:
        if band_weight_from_severity is not None:
            spec = band_weight_from_severity(d.get("severity"))
        else:
            spec = 0.35
    spec = max(0.0, min(1.0, spec))
    conv = _safe_float(d.get("convergence", 0.0), 0.0)
    conf = _safe_float(d.get("confidence", 0.5), 0.5)
    ts = _safe_float(d.get("timestamp", 0.0), 0.0)
    rec = _safe_float(d.get("recency", _recency_weight(ts, now)), 0.5)
    rec = max(0.0, min(1.0, rec))
    rec = max(0.0, min(1.0, rec))

    energy = (spec * 1.1) + (conv * 0.55) + (conf * 0.2)
    lift = energy * (0.6 + (0.6 * rec))
    z = lift * Z_SCALE
    return max(-Z_CLAMP, min(Z_CLAMP, z))


def _edge_opacity(relation: str | None) -> float:
    rel = (relation or "").lower()
    if rel in {"source_cluster", "relation_cluster"}:
        return 0.08
    if rel in {"co_occurs_with", "same_as", "likely_same_as"}:
        return 0.32
    return 0.26


def _force_layout(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
    """
    Deterministic, bounded force refinement.
    Mutates node x/y/z in-place; no randomness; fixed iteration count.
    """
    if not nodes:
        return

    id_to_idx = {n["id"]: i for i, n in enumerate(nodes)}
    ncount = len(nodes)

    positions = [[_safe_float(n.get("x", 0.0)), _safe_float(n.get("y", 0.0)), _safe_float(n.get("z", 0.0))] for n in nodes]
    confidence = [_safe_float(n.get("confidence", 0.5), 0.5) for n in nodes]
    convergence = [_safe_float(n.get("convergence", 0.0), 0.0) for n in nodes]
    recency = [max(0.0, min(1.0, _safe_float(n.get("recency", 0.5), 0.5))) for n in nodes]

    def _spec_for(node: Dict[str, Any]) -> float:
        spec = _safe_float(node.get("spectrum_index", -1.0), -1.0)
        if spec < 0.0:
            if band_weight_from_severity is not None:
                spec = band_weight_from_severity(node.get("severity"))
            else:
                spec = 0.35
        return max(0.0, min(1.0, spec))

    spectrum = [_spec_for(n) for n in nodes]

    # degrees for mass weighting
    degree = [0] * ncount
    edge_data = []
    for e in edges:
        s, t = id_to_idx.get(e.get("source")), id_to_idx.get(e.get("target"))
        if s is None or t is None:
            continue
        w = _safe_float(e.get("weight", 1.0), 1.0)
        coherence = _safe_float(e.get("edge_strength", -1.0), -1.0)
        if coherence < 0.0:
            coherence = max(0.05, 1.0 - abs(spectrum[s] - spectrum[t]))
        edge_data.append((s, t, w, coherence))
        degree[s] += 1
        degree[t] += 1

    mass = [
        0.8
        + (spectrum[i] * 2.6)
        + (convergence[i] * 1.8)
        + (confidence[i] * 0.6)
        for i in range(ncount)
    ]

    energy_weights = [
        (spectrum[i] ** 1.6) + (convergence[i] * 0.9) + (confidence[i] * 0.3)
        for i in range(ncount)
    ]
    anchors = [pos[:] for pos in positions]
    seed_dirs = []
    for n in nodes:
        nid = str(n.get("id", ""))
        angle = _hash_unit(nid, "dir") * (2 * math.pi)
        z = (_hash_unit(nid, "dirz") - 0.5) * 0.6
        seed_dirs.append((math.cos(angle), math.sin(angle), z))
    energy_rank = sorted(range(ncount), key=lambda i: energy_weights[i], reverse=True)
    well_indices = energy_rank[: min(12, ncount)]

    def _build_cells():
        grid = {}
        cell_size = REPULSE_RADIUS
        for idx, (x, y, _z) in enumerate(positions):
            key = (int(x // cell_size), int(y // cell_size))
            grid.setdefault(key, []).append(idx)
        return grid

    def _clamp(v: float, lo: float, hi: float) -> float:
        return max(lo, min(hi, v))

    for _ in range(FORCE_ITERATIONS):
        forces = [[0.0, 0.0, 0.0] for _ in range(ncount)]
        cx = cy = cz = 0.0
        wsum = 0.0
        for idx, pos in enumerate(positions):
            w = energy_weights[idx]
            cx += pos[0] * w
            cy += pos[1] * w
            cz += pos[2] * w
            wsum += w
        if wsum > 0.0:
            cx /= wsum
            cy /= wsum
            cz /= wsum

        # Attraction along real edges
        for s, t, w, coherence in edge_data:
            ax, ay, az = positions[s]
            bx, by, bz = positions[t]
            dx, dy, dz = bx - ax, by - ay, bz - az
            dist_sq = dx * dx + dy * dy + dz * dz + 1e-6
            dist = math.sqrt(dist_sq)
            spec_delta = abs(spectrum[s] - spectrum[t])
            min_spec = min(spectrum[s], spectrum[t])
            coherence = max(0.05, min(1.0, coherence))
            ideal = EDGE_IDEAL * (0.45 + (1.2 * (1.0 - coherence))) * (0.8 + (0.6 * (1.0 - min_spec)))
            stretch = dist - ideal
            if stretch == 0.0:
                continue
            avg_conf = (confidence[s] + confidence[t]) * 0.5
            conv_boost = 0.8 + (0.6 * max(convergence[s], convergence[t]))
            coeff = EDGE_ATTRACT_K * stretch * w * (0.4 + avg_conf) * (0.55 + (0.9 * coherence)) * (0.65 + (0.6 * min_spec)) * conv_boost
            nx, ny, nz = dx / dist, dy / dist, dz / dist
            fx, fy, fz = nx * coeff, ny * coeff, nz * coeff
            forces[s][0] += fx
            forces[s][1] += fy
            forces[s][2] += fz
            forces[t][0] -= fx
            forces[t][1] -= fy
            forces[t][2] -= fz

        # Anchor high-energy nodes and create convergence wells
        for idx, pos in enumerate(positions):
            spec = spectrum[idx]
            conv = convergence[idx]
            ax, ay, az = anchors[idx]
            anchor_strength = ANCHOR_K * (0.25 + (spec ** 1.3) + (conv * 0.9))
            forces[idx][0] += (ax - pos[0]) * anchor_strength
            forces[idx][1] += (ay - pos[1]) * anchor_strength
            forces[idx][2] += (az - pos[2]) * anchor_strength

            dx = cx - pos[0]
            dy = cy - pos[1]
            dz = cz - pos[2]
            dist_sq = dx * dx + dy * dy + dz * dz
            if dist_sq < 1e-6:
                rx, ry, rz = seed_dirs[idx]
            else:
                dist = math.sqrt(dist_sq)
                rx, ry, rz = dx / dist, dy / dist, dz / dist

            if spec >= 0.35:
                pull = CENTER_PULL_K * ((spec ** 1.4) + (conv * 0.8))
                forces[idx][0] += rx * pull
                forces[idx][1] += ry * pull
                forces[idx][2] += rz * pull * 0.5
            else:
                drift = OUTWARD_DRIFT_K * (1.0 - spec) * (0.6 + (1.0 - recency[idx]) * 0.6)
                forces[idx][0] -= rx * drift
                forces[idx][1] -= ry * drift
                forces[idx][2] -= rz * drift * 0.4

            for widx in well_indices:
                if widx == idx:
                    continue
                wx, wy, wz = positions[widx]
                dxw = wx - pos[0]
                dyw = wy - pos[1]
                dzw = wz - pos[2]
                d2 = dxw * dxw + dyw * dyw + dzw * dzw
                if d2 > 520.0 * 520.0 or d2 < 1e-6:
                    continue
                d = math.sqrt(d2)
                coherence = max(0.1, 1.0 - abs(spec - spectrum[widx]))
                well_strength = (0.35 + (spectrum[widx] * 0.9) + (convergence[widx] * 0.8))
                pull = WELL_ATTRACT_K * well_strength * (0.25 + spec) * coherence * (1.0 - (d / 520.0))
                fx = (dxw / d) * pull
                fy = (dyw / d) * pull
                fz = (dzw / d) * pull
                forces[idx][0] += fx
                forces[idx][1] += fy
                forces[idx][2] += fz

        # Repulsion via coarse spatial grid (local neighborhoods only)
        grid = _build_cells()
        neighbor_offsets = [(-1, -1), (-1, 0), (-1, 1), (0, -1), (0, 0), (0, 1), (1, -1), (1, 0), (1, 1)]
        r2 = REPULSE_RADIUS * REPULSE_RADIUS

        for cell, idxs in grid.items():
            for dx_cell, dy_cell in neighbor_offsets:
                neighbor = (cell[0] + dx_cell, cell[1] + dy_cell)
                if neighbor not in grid:
                    continue
                # avoid double-processing pairs: only process neighbor >= cell in tuple ordering
                if neighbor < cell:
                    continue
                n_idxs = grid[neighbor]
                for i in idxs:
                    for j in n_idxs:
                        if neighbor == cell and j <= i:
                            continue
                        ax, ay, az = positions[i]
                        bx, by, bz = positions[j]
                        dx, dy, dz = ax - bx, ay - by, az - bz
                        dist_sq = dx * dx + dy * dy + dz * dz
                        if dist_sq < 1e-6 or dist_sq > r2:
                            continue
                        dist = math.sqrt(dist_sq)
                        spec_avg = (spectrum[i] + spectrum[j]) * 0.5
                        spec_delta = abs(spectrum[i] - spectrum[j])
                        conv_avg = (convergence[i] + convergence[j]) * 0.5
                        rec_avg = (recency[i] + recency[j]) * 0.5
                        repulse_scale = max(0.25, 1.25 - (spec_avg * 0.75))
                        repulse_scale *= max(0.4, 1.0 - (conv_avg * 0.55))
                        repulse_scale *= 0.85 + ((1.0 - rec_avg) * 0.35)
                        repulse_scale *= 0.65 + (0.7 * spec_delta)
                        coeff = REPULSE_K * repulse_scale * (mass[i] + mass[j]) / (dist_sq + 1.0)
                        nx, ny, nz = dx / dist, dy / dist, dz / dist
                        fx, fy, fz = nx * coeff, ny * coeff, nz * coeff
                        forces[i][0] += fx
                        forces[i][1] += fy
                        forces[i][2] += fz
                        forces[j][0] -= fx
                        forces[j][1] -= fy
                        forces[j][2] -= fz

        # Integrate with clamped step and bounds
        for idx, (fx, fy, fz) in enumerate(forces):
            drift = 0.25 + ((1.0 - spectrum[idx]) * 1.1) + ((1.0 - recency[idx]) * 0.5)
            drift = max(0.2, min(2.0, drift))
            dx = _clamp(fx * STEP_SIZE * drift, -MAX_STEP_DELTA, MAX_STEP_DELTA)
            dy = _clamp(fy * STEP_SIZE * drift, -MAX_STEP_DELTA, MAX_STEP_DELTA)
            dz = _clamp(fz * STEP_SIZE * drift, -MAX_STEP_DELTA, MAX_STEP_DELTA)
            px, py, pz = positions[idx]
            px = _clamp(px + dx, -XY_CLAMP, XY_CLAMP)
            py = _clamp(py + dy, -XY_CLAMP, XY_CLAMP)
            pz = _clamp(pz + dz, -Z_CLAMP, Z_CLAMP)
            positions[idx] = [px, py, pz]

    for idx, pos in enumerate(positions):
        nodes[idx]["x"], nodes[idx]["y"], nodes[idx]["z"] = pos


def main() -> None:
    els = _load_json(GRAPH_PATH, [])
    pos = _load_json(POS_PATH, {})  # { node_id: {"x":..,"y":..} }
    now = time.time()

    # Accept a few common JSON shapes: list of elements, or dict with 'elements'/'nodes'+'edges'
    if isinstance(els, dict):
        if "elements" in els and isinstance(els["elements"], list):
            els = els["elements"]
        elif ("nodes" in els or "edges" in els) and isinstance(els.get("nodes", []), list) and isinstance(els.get("edges", []), list):
            els = list(els.get("nodes", [])) + list(els.get("edges", []))
        elif "data" in els and isinstance(els.get("data"), dict):
            els = [els]
        else:
            els = []

    nodes_raw = [e for e in els if not _is_edge(e)]
    edges_raw = [e for e in els if _is_edge(e)]

    nodes_raw = nodes_raw[:MAX_NODES]
    edges_raw = edges_raw[:MAX_EDGES]

    nodes_out: List[Dict[str, Any]] = []
    id_set = set()

    # load persisted surveillance state (if present) so we can export it into 3D payload
    try:
        surv_store = json.loads(SURV_PATH.read_text()) if SURV_PATH.exists() else {}
    except Exception:
        surv_store = {}

    for n in nodes_raw:
        d = n.get("data", {})
        nid = d.get("id")
        if not nid or nid in id_set:
            continue
        id_set.add(nid)
        s = surv_store.get(nid, {})

        p = pos.get(nid) or n.get("position") or {}
        has_pos = isinstance(p, dict) and ("x" in p and "y" in p)
        x = _safe_float(p.get("x", 0.0)) * XY_SCALE
        y = _safe_float(p.get("y", 0.0)) * XY_SCALE
        z = _z_from(n, now)
        if not has_pos:
            spec_seed = _safe_float(d.get("spectrum_index", -1.0), -1.0)
            if spec_seed < 0.0:
                if band_weight_from_severity is not None:
                    spec_seed = band_weight_from_severity(d.get("severity"))
                else:
                    spec_seed = 0.35
            spec_seed = max(0.0, min(1.0, spec_seed))
            angle = _hash_unit(nid, "angle") * (2 * math.pi)
            radius = 120.0 + ((1.0 - spec_seed) * 520.0) + (_hash_unit(nid, "radius") * 120.0)
            x = math.cos(angle) * radius
            y = math.sin(angle) * radius
            z += (_hash_unit(nid, "zj") - 0.5) * 120.0

        src_key = str(d.get("subsource") or d.get("source") or "").strip().lower()
        source_color = d.get("source_color") or (SOURCE_COLOR_MAP.get(src_key) if src_key else "")
        spectral = d.get("spectral_color") or ""
        if not spectral and spectral_color_from_source is not None:
            spectral = spectral_color_from_source(
                spec_val,
                d.get("confidence", 0.5),
                max(0.0, min(1.0, _safe_float(d.get("recency", 0.5), 0.5))),
                source_color,
            )
        elif not spectral and spectral_color is not None:
            spec_val = _safe_float(d.get("spectrum_index", -1.0), -1.0)
            if spec_val < 0.0:
                if band_weight_from_severity is not None:
                    spec_val = band_weight_from_severity(d.get("severity"))
                else:
                    spec_val = 0.35
            spectral = spectral_color(spec_val, d.get("confidence", 0.5), max(0.0, min(1.0, _safe_float(d.get("recency", 0.5), 0.5))))
        if not spectral:
            spectral = d.get("color") or ""
        color = spectral or source_color or "#22d3ee"

        nodes_out.append(
            {
                "id": nid,
                "label": d.get("label", "")[:180],
                "kind": d.get("kind", ""),
                "object_type": d.get("object_type") or d.get("kind") or "",
                "severity": d.get("severity", ""),
                "source": d.get("source", ""),
                "subsource": d.get("subsource", d.get("subSource", "")),
                "color": color,
                "spectral_color": spectral or color,
                "source_color": source_color,
                "spectrum_index": _safe_float(d.get("spectrum_index", 0.0), 0.0),
                "convergence": _safe_float(d.get("convergence", 0.0), 0.0),
                "recency": max(0.0, min(1.0, _safe_float(d.get("recency", 0.0), 0.0))),
                "volume_count": _safe_float(d.get("volume_count", 1.0), 1.0),
                "size": _safe_float(d.get("size", 10.0), 10.0),
                "confidence": _safe_float(d.get("confidence", 0.5), 0.5),
                "band": d.get("band", ""),
                "timestamp": _safe_float(d.get("timestamp", 0.0), 0.0),
                "post_url": d.get("post_url") or d.get("reddit_url") or "",
                "author_url": d.get("author_url") or "",
                "x": x,
                "y": y,
                "z": z,
                "surveillance": bool(s.get("enabled", d.get("surveillance"))),
                "last_activity": int(s.get("last_activity", d.get("last_activity") or 0) or 0),
                "activity_count": int(s.get("activity_count", d.get("activity_count", 0)) or 0),
                "activity_level": s.get("activity_level", d.get("activity_level") or "low"),
            }
        )

    edges_out: List[Dict[str, Any]] = []
    for e in edges_raw:
        d = e.get("data", {})
        s, t = d.get("source"), d.get("target")
        if not s or not t:
            continue
        if s not in id_set or t not in id_set:
            continue
        opacity = _safe_float(d.get("edge_opacity", _edge_opacity(d.get("relation"))), 0.2)
        edges_out.append(
            {
                "id": d.get("id", f"{s}→{t}"),
                "source": s,
                "target": t,
                "relation": d.get("relation", ""),
                "weight": _safe_float(d.get("weight", 1.0), 1.0),
                "opacity": opacity,
                "dispersion": _safe_float(d.get("dispersion", 0.0), 0.0),
                "edge_strength": _safe_float(d.get("edge_strength", 0.5), 0.5),
                "edge_thickness": _safe_float(d.get("edge_thickness", 1.0), 1.0),
                "curve_offset": _safe_float(d.get("curve_offset", 0.0), 0.0),
                "band": d.get("band", ""),
                "object_type": d.get("object_type", "edge"),
            }
        )

    # ---- compute degree and mark top-N preserved nodes to keep them live in 3D ----
    from collections import Counter
    deg = Counter()
    for e in edges_out:
        s, t = e.get("source"), e.get("target")
        if s:
            deg[s] += 1
        if t:
            deg[t] += 1

    # annotate nodes with degree and identify top nodes
    for n in nodes_out:
        n_id = n.get("id")
        n["degree"] = int(deg.get(n_id, 0))
    MAX_PRESERVE = 300
    top_n = min(90, max(1, len(nodes_out)))
    top_ids = [nid for nid, _ in deg.most_common(top_n)]

    # include neighbors of top nodes so connected items stay, but cap total preserved nodes
    neighbor_map = {n.get("id"): set() for n in nodes_out}
    for e in edges_out:
        s, t = e.get("source"), e.get("target")
        if s and t and s in neighbor_map and t in neighbor_map:
            neighbor_map[s].add(t)
            neighbor_map[t].add(s)

    preserved = list(top_ids)
    # greedily add neighbors until cap
    for tid in list(top_ids):
        for nb in sorted(neighbor_map.get(tid, set()), key=lambda x: -deg.get(x, 0)):
            if nb not in preserved:
                preserved.append(nb)
            if len(preserved) >= MAX_PRESERVE:
                break
        if len(preserved) >= MAX_PRESERVE:
            break
    preserved = set(preserved)

    # also preserve nodes marked surveillance in stored data (if present) - ensure they are included
    surv_nodes = {n.get("id") for n in nodes_out if n.get("surveillance")}
    for nid in surv_nodes:
        preserved.add(nid)
    # final cap: trim non-surveillance items if too many preserved, but never drop surv_nodes
    if len(preserved) > MAX_PRESERVE:
        non_surv = [x for x in preserved if x not in surv_nodes]
        keep = set(sorted(non_surv, key=lambda x: -deg.get(x, 0))[: max(0, MAX_PRESERVE - len(surv_nodes))])
        preserved = keep.union(surv_nodes)

    for n in nodes_out:
        nid = n.get("id")
        if nid in preserved:
            n["live_preserve"] = True
            # reason label: top, neighbor, or surveillance (priority order)
            if nid in top_ids:
                n["preserved_reason"] = "top"
            elif n.get("surveillance"):
                n["preserved_reason"] = "surveillance"
            else:
                n["preserved_reason"] = "neighbor"
        else:
            n["live_preserve"] = False
            n["preserved_reason"] = ""

    _force_layout(nodes_out, edges_out)

    source_defs = {}
    for n in nodes_out:
        raw = str(n.get("subsource") or n.get("source") or "").strip()
        if not raw:
            continue
        key = raw.lower()
        entry = source_defs.get(key)
        if not entry:
            entry = {"name": key, "color": None, "count": 0}
            source_defs[key] = entry
        entry["count"] += 1
        if not entry.get("color"):
            color = n.get("source_color") or n.get("sourceColor") or n.get("color")
            if color:
                entry["color"] = color
    sources_list = sorted(source_defs.values(), key=lambda x: (-x["count"], x["name"]))

    payload = {
        "nodes": nodes_out,
        "edges": edges_out,
        "meta": {
            "built_at": int(now),
            "nodes": len(nodes_out),
            "edges": len(edges_out),
            "sources": sources_list
        }
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))
    sources_path = ROOT / "data" / "sources.json"
    sources_path.write_text(json.dumps({"sources": sources_list}, indent=2))
    print(f"[export_3d] wrote {OUT_PATH} nodes={len(nodes_out)} edges={len(edges_out)} built_at={int(now)}")


if __name__ == "__main__":
    main()
