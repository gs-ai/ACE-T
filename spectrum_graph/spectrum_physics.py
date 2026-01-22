from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

from spectrum_graph.spectrum_weights import edge_coherence, node_repulsion, node_stability

BASE_REPULSE = 220.0
BASE_ATTRACT = 0.006
EDGE_IDEAL = 110.0
REPULSE_RADIUS = 240.0
OUTWARD_DRIFT = 0.55
CENTER_PULL = 0.0035
ANCHOR_STRENGTH = 0.006
STEP_SIZE = 0.022
MAX_STEP = 9.0
XY_CLAMP = 1800.0
Z_SCALE = 900.0


def similarity(a: float, b: float) -> float:
    return max(0.0, 1.0 - abs(a - b))


def compute_z_lift(spectrum_index: float, convergence_score: float) -> float:
    return spectrum_index * convergence_score * Z_SCALE


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _build_cells(positions: List[Tuple[float, float]]) -> Dict[Tuple[int, int], List[int]]:
    cells: Dict[Tuple[int, int], List[int]] = {}
    cell_size = REPULSE_RADIUS
    for idx, (x, y) in enumerate(positions):
        key = (int(x // cell_size), int(y // cell_size))
        cells.setdefault(key, []).append(idx)
    return cells


def apply_spectrum_physics(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], iterations: int = 120) -> None:
    if not nodes:
        return

    id_to_idx = {n["id"]: i for i, n in enumerate(nodes) if n.get("id") is not None}
    positions = [(float(n.get("x", 0.0)), float(n.get("y", 0.0))) for n in nodes]
    initial_positions = list(positions)

    spectrum = [_safe_float(n.get("spectrum_index"), 0.0) for n in nodes]
    convergence = [_safe_float(n.get("convergence"), 0.0) for n in nodes]

    edge_pairs = []
    for e in edges:
        s = id_to_idx.get(e.get("source"))
        t = id_to_idx.get(e.get("target"))
        if s is None or t is None or s == t:
            continue
        edge_pairs.append((s, t))

    for _ in range(iterations):
        deltas = [[0.0, 0.0] for _ in nodes]
        cells = _build_cells(positions)

        for (cell_x, cell_y), idxs in cells.items():
            neighbors = []
            for ox in (-1, 0, 1):
                for oy in (-1, 0, 1):
                    neighbors.extend(cells.get((cell_x + ox, cell_y + oy), []))
            for i in idxs:
                xi, yi = positions[i]
                rep_i = BASE_REPULSE * node_repulsion(nodes[i])
                for j in neighbors:
                    if j <= i:
                        continue
                    xj, yj = positions[j]
                    dx = xi - xj
                    dy = yi - yj
                    dist_sq = (dx * dx) + (dy * dy) + 1.0
                    if dist_sq > (REPULSE_RADIUS * REPULSE_RADIUS):
                        continue
                    dist = math.sqrt(dist_sq)
                    rep_j = BASE_REPULSE * node_repulsion(nodes[j])
                    force = (rep_i + rep_j) * 0.5 / dist_sq
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force
                    deltas[i][0] += fx
                    deltas[i][1] += fy
                    deltas[j][0] -= fx
                    deltas[j][1] -= fy

        for s, t in edge_pairs:
            xi, yi = positions[s]
            xj, yj = positions[t]
            dx = xj - xi
            dy = yj - yi
            dist = math.sqrt((dx * dx) + (dy * dy)) + 1e-6
            coherence = edge_coherence(nodes[s], nodes[t])
            ideal = EDGE_IDEAL * (1.15 - (coherence * 0.6))
            attract = BASE_ATTRACT * (0.4 + (0.8 * coherence))
            delta = (dist - ideal) * attract
            fx = (dx / dist) * delta
            fy = (dy / dist) * delta
            deltas[s][0] += fx
            deltas[s][1] += fy
            deltas[t][0] -= fx
            deltas[t][1] -= fy

        for i, (x, y) in enumerate(positions):
            spec = spectrum[i]
            conv = convergence[i]
            center_pull = CENTER_PULL * (spec ** 1.3) * (0.6 + (conv * 0.8))
            deltas[i][0] += (-x) * center_pull
            deltas[i][1] += (-y) * center_pull

            r = math.sqrt((x * x) + (y * y)) + 1e-6
            outward = OUTWARD_DRIFT * ((1.0 - spec) ** 1.2)
            deltas[i][0] += (x / r) * outward
            deltas[i][1] += (y / r) * outward

            anchor = ANCHOR_STRENGTH * node_stability(nodes[i])
            ix, iy = initial_positions[i]
            deltas[i][0] += (ix - x) * anchor
            deltas[i][1] += (iy - y) * anchor

        next_positions = []
        for i, (x, y) in enumerate(positions):
            spec = spectrum[i]
            step_scale = 0.35 + ((1.0 - spec) * 0.7)
            dx = _clamp(deltas[i][0] * STEP_SIZE * step_scale, -MAX_STEP, MAX_STEP)
            dy = _clamp(deltas[i][1] * STEP_SIZE * step_scale, -MAX_STEP, MAX_STEP)
            nx = _clamp(x + dx, -XY_CLAMP, XY_CLAMP)
            ny = _clamp(y + dy, -XY_CLAMP, XY_CLAMP)
            next_positions.append((nx, ny))
        positions = next_positions

    for i, (x, y) in enumerate(positions):
        nodes[i]["x"] = float(x)
        nodes[i]["y"] = float(y)
