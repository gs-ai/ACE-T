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
from core.band import band_weight

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
GROUP_ATTRACT_K = 0.0025      # pull harder to keep clusters tight
REPULSE_RADIUS = 220.0        # broader repulsion to keep clusters apart
REPULSE_K = 480.0             # stronger base repulsion
"""
Repulsion tuning:
- CROSS_SOURCE_REPULSE keeps different source clusters apart unless connected.
- SAME_SOURCE_REPULSE maintains cohesion within a cluster.
"""
CROSS_SOURCE_REPULSE = 2.4    # stronger repulsion between different sources
SAME_SOURCE_REPULSE = 0.55    # soften repulsion within same source cluster
STEP_SIZE = 0.025             # integration step
MAX_STEP_DELTA = 10.0         # clamp per-axis delta to avoid spikes
XY_CLAMP = 1600.0             # keep layout bounded horizontally

# Palette for synthetic source hubs (rotate if more than provided)
HUB_COLOR_PALETTE = [
    0x00d0ff,
    0x00ffb3,
    0xffae00,
    0xff5f5f,
    0x8a6bff,
    0x00ffa3,
    0xff6fd8,
    0x6de5ff,
    0xffe066,
    0xff9cf5,
]

# relation hub tuning
REL_HUB_REPULSE_FACTOR = 4.2  # increase repulsion between relation hubs so groups remain separated



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


def _recency_weight(ts: float, now: float) -> float:
    if not ts:
        return 0.5
    age_s = max(0.0, now - ts)
    half_life_s = RECENCY_HALFLIFE_H * 3600.0
    return math.exp(-math.log(2) * (age_s / half_life_s))


def _z_from(node: Dict[str, Any], now: float) -> float:
    """
    z encodes momentum:
    - mass (degree proxy), threat_score, confidence, and recency lift z upward
    - older/low-signal sinks toward 0
    """
    d = node["data"]
    mass = _safe_float(d.get("mass", d.get("degree", 1.0)), 1.0)
    threat = _safe_float(d.get("threat", 0.0), 0.0)
    conf = _safe_float(d.get("confidence", 0.5), 0.5)
    conf *= band_weight(d.get("band"))
    ts = _safe_float(d.get("timestamp", 0.0), 0.0)

    r = _recency_weight(ts, now)
    lift = (math.log1p(mass) * 0.65) + (threat * 0.85) + (conf * 0.35)
    z = (lift * r) * Z_SCALE
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
    source = [n.get("source") or "" for n in nodes]
    subsource = [n.get("subsource") or "" for n in nodes]
    group_key = [subsource[i] or source[i] for i in range(ncount)]

    # degrees for mass weighting
    degree = [0] * ncount
    edge_data = []
    for e in edges:
        s, t = id_to_idx.get(e.get("source")), id_to_idx.get(e.get("target"))
        if s is None or t is None:
            continue
        w = _safe_float(e.get("weight", 1.0), 1.0)
        edge_data.append((s, t, w))
        degree[s] += 1
        degree[t] += 1

    mass = [1.0 + math.log1p(d or 1) + (confidence[i] * 0.6) for i, d in enumerate(degree)]

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

        # Attraction along real edges
        for s, t, w in edge_data:
            ax, ay, az = positions[s]
            bx, by, bz = positions[t]
            dx, dy, dz = bx - ax, by - ay, bz - az
            dist_sq = dx * dx + dy * dy + dz * dz + 1e-6
            dist = math.sqrt(dist_sq)
            stretch = dist - EDGE_IDEAL
            if stretch == 0.0:
                continue
            avg_conf = (confidence[s] + confidence[t]) * 0.5
            cross_source = 1.3 if source[s] and source[t] and source[s] != source[t] else 1.0
            coeff = EDGE_ATTRACT_K * stretch * w * (0.5 + avg_conf) * cross_source
            nx, ny, nz = dx / dist, dy / dist, dz / dist
            fx, fy, fz = nx * coeff, ny * coeff, nz * coeff
            forces[s][0] += fx
            forces[s][1] += fy
            forces[s][2] += fz
            forces[t][0] -= fx
            forces[t][1] -= fy
            forces[t][2] -= fz

        # Soft attraction toward source/subsource centroids
        def _centroids(keys: List[str]):
            acc = {}
            for idx, key in enumerate(keys):
                if not key:
                    continue
                px, py, pz = positions[idx]
                sx, sy, sz, cnt = acc.get(key, (0.0, 0.0, 0.0, 0))
                acc[key] = (sx + px, sy + py, sz + pz, cnt + 1)
            return {k: (sx / c, sy / c, sz / c) for k, (sx, sy, sz, c) in acc.items() if c}

        src_centroid = _centroids(source)
        sub_centroid = _centroids(subsource)

        for idx, pos in enumerate(positions):
            for key, centroids in ((source[idx], src_centroid), (subsource[idx], sub_centroid)):
                if not key or key not in centroids:
                    continue
                cx, cy, cz = centroids[key]
                dx, dy, dz = cx - pos[0], cy - pos[1], cz - pos[2]
                forces[idx][0] += dx * GROUP_ATTRACT_K * (0.6 + confidence[idx])
                forces[idx][1] += dy * GROUP_ATTRACT_K * (0.6 + confidence[idx])
                forces[idx][2] += dz * GROUP_ATTRACT_K * 0.35  # z stays mild

        # Repulsion via coarse spatial grid (local neighborhoods only)
        grid = _build_cells()
        neighbor_offsets = [(-1, -1), (-1, 0), (-1, 1), (0, -1), (0, 0), (0, 1), (1, -1), (1, 0), (1, 1)]
        r2 = REPULSE_RADIUS * REPULSE_RADIUS

        # detect relation hubs for extra repulsion
        is_rel_hub = [True if nodes[idx].get("kind") == "relation_hub" else False for idx in range(ncount)]

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
                        coeff = REPULSE_K * (mass[i] + mass[j]) / (dist_sq + 1.0)
                        # Encourage separation between different source clusters
                        if group_key[i] and group_key[j]:
                            coeff *= CROSS_SOURCE_REPULSE if group_key[i] != group_key[j] else SAME_SOURCE_REPULSE
                        # if both are relation hubs, increase repulsion so groups remain separated
                        if is_rel_hub[i] and is_rel_hub[j]:
                            coeff *= REL_HUB_REPULSE_FACTOR
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
            dx = _clamp(fx * STEP_SIZE, -MAX_STEP_DELTA, MAX_STEP_DELTA)
            dy = _clamp(fy * STEP_SIZE, -MAX_STEP_DELTA, MAX_STEP_DELTA)
            dz = _clamp(fz * STEP_SIZE, -MAX_STEP_DELTA, MAX_STEP_DELTA)
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
        x = _safe_float(p.get("x", 0.0)) * XY_SCALE
        y = _safe_float(p.get("y", 0.0)) * XY_SCALE
        z = _z_from(n, now)

        src_key = str(d.get("subsource") or d.get("source") or "").strip().lower()
        color = d.get("color", "")
        if src_key and src_key in SOURCE_COLOR_MAP:
            color = SOURCE_COLOR_MAP[src_key]

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
        edges_out.append(
            {
                "id": d.get("id", f"{s}→{t}"),
                "source": s,
                "target": t,
                "relation": d.get("relation", ""),
                "weight": _safe_float(d.get("weight", 1.0), 1.0),
                "opacity": _edge_opacity(d.get("relation")),
                "band": d.get("band", ""),
                "object_type": d.get("object_type", "edge"),
            }
        )

    # ---- add synthetic hubs per source/subsource to cluster content and connect ----
    by_source: Dict[str, Dict[str, Any]] = {}
    for n in nodes_out:
        src = n.get("subsource") or n.get("source")
        if not src:
            continue
        entry = by_source.setdefault(
            src,
            {"sum": [0.0, 0.0, 0.0], "count": 0, "ids": []},
        )
        entry["sum"][0] += n.get("x", 0.0)
        entry["sum"][1] += n.get("y", 0.0)
        entry["sum"][2] += n.get("z", 0.0)
        entry["count"] += 1
        entry["ids"].append(n["id"])

    existing_node_ids = {n.get("id") for n in nodes_out}
    existing_edge_ids = {e.get("id") for e in edges_out}
    hub_nodes: List[Dict[str, Any]] = []
    hub_edges: List[Dict[str, Any]] = []
    for idx, (src, data) in enumerate(by_source.items()):
        if data["count"] == 0:
            continue
        hub_id = f"hub::{src}"
        if hub_id in existing_node_ids:
            continue  # hub already present from upstream data

        cx = data["sum"][0] / data["count"]
        cy = data["sum"][1] / data["count"]
        cz = data["sum"][2] / data["count"]
        color = HUB_COLOR_PALETTE[idx % len(HUB_COLOR_PALETTE)]
        if src:
            color = int(SOURCE_COLOR_MAP.get(str(src).lower(), f"#{int(color):06x}").lstrip("#"), 16)
        hub_nodes.append(
            {
                "id": hub_id,
                "label": src,
                "kind": "source_hub",
                "severity": "",
                "source": src,
                "subsource": src,
                "color": f"#{int(color):06x}",
                "size": 26.0,
                "confidence": 1.0,
                "timestamp": 0.0,
                "x": cx,
                "y": cy,
                "z": cz,
            }
        )
        for nid in data["ids"]:
            eid = f"{hub_id}→{nid}"
            if eid in existing_edge_ids:
                continue
            hub_edges.append(
                {
                    "id": eid,
                    "source": hub_id,
                    "target": nid,
                    "relation": "source_cluster",
                    "weight": 1.5,
                    "opacity": _edge_opacity("source_cluster"),
                    "synthetic": True,
                }
            )

    # ---- add synthetic hubs per relation type to keep relation clusters separate ----
    by_relation: Dict[str, Dict[str, Any]] = {}
    for e in edges_raw:
        d = e.get("data", {})
        rel = d.get("relation") or ""
        if not rel:
            continue
        s, t = d.get("source"), d.get("target")
        entry = by_relation.setdefault(rel, {"sum": [0.0, 0.0, 0.0], "count": 0, "ids": set()})
        # only include nodes that exist in nodes_out by id
        if s in id_set:
            entry["ids"].add(s)
            # sum positions
            n = next((x for x in nodes_out if x["id"] == s), None)
            if n:
                entry["sum"][0] += n.get("x", 0.0)
                entry["sum"][1] += n.get("y", 0.0)
                entry["sum"][2] += n.get("z", 0.0)
                entry["count"] += 1
        if t in id_set:
            entry["ids"].add(t)
            n = next((x for x in nodes_out if x["id"] == t), None)
            if n:
                entry["sum"][0] += n.get("x", 0.0)
                entry["sum"][1] += n.get("y", 0.0)
                entry["sum"][2] += n.get("z", 0.0)
                entry["count"] += 1

    for rel, data in by_relation.items():
        if data["count"] == 0:
            continue
        cx = data["sum"][0] / data["count"]
        cy = data["sum"][1] / data["count"]
        cz = data["sum"][2] / data["count"]
        hub_id = f"relhub::{rel}"
        # color selection: reuse source color rotation but offset
        color = HUB_COLOR_PALETTE[hash(rel) % len(HUB_COLOR_PALETTE)]
        hub_nodes.append(
            {
                "id": hub_id,
                "label": rel,
                "kind": "relation_hub",
                "severity": "",
                "source": "relation",
                "subsource": rel,
                "color": f"#{int(color):06x}",
                "size": 26.0,
                "confidence": 1.0,
                "timestamp": 0.0,
                "x": cx,
                "y": cy,
                "z": cz,
            }
        )
        for nid in data["ids"]:
            hub_edges.append(
                {
                    "id": f"{hub_id}→{nid}",
                    "source": hub_id,
                    "target": nid,
                    "relation": "relation_cluster",
                    "weight": 1.5,
                    "opacity": _edge_opacity("relation_cluster"),
                    "synthetic": True,
                }
            )
    nodes_out.extend(hub_nodes)
    edges_out.extend(hub_edges)

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

    payload = {
        "nodes": nodes_out,
        "edges": edges_out,
        "meta": {"built_at": int(now), "nodes": len(nodes_out), "edges": len(edges_out)}
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))
    print(f"[export_3d] wrote {OUT_PATH} nodes={len(nodes_out)} edges={len(edges_out)} built_at={int(now)}")


if __name__ == "__main__":
    main()
