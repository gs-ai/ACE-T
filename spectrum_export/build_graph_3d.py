#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from spectrum_core.spectrum_math import (
    clamp_normalize,
    extract_confidence,
    percentile_normalize,
    recency_factor,
)
from spectrum_graph.spectrum_color import spectrum_color

try:
    from sources.source_colors import SOURCE_COLORS as SOURCE_COLOR_MAP
except Exception:
    SOURCE_COLOR_MAP = {}

ROOT = Path(__file__).resolve().parents[1]
PRIMARY_DATA_ROOT = ROOT / "data"

MAX_NODES = 9000
MAX_EDGES = 18000
Z_CLAMP = 2600.0
X_SPAN = 3000.0
Y_SPAN = 900.0
Z_SPAN = 1800.0
Z_BONUS = 600.0
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\\.)+[a-z]{2,}$", re.IGNORECASE)
IP_RE = re.compile(r"^(?:\\d{1,3}\\.){3}\\d{1,3}$")
HASH_RE = re.compile(r"^[a-f0-9]{32,64}$", re.IGNORECASE)
REDDIT_POST_RE = re.compile(r"reddit\\.com/r/[^/]+/comments/([a-z0-9]+)/", re.IGNORECASE)
REDDIT_SHORT_RE = re.compile(r"redd\\.it/([a-z0-9]+)", re.IGNORECASE)


def _is_reddit_domain(url: str) -> bool:
    """Check if URL is from a legitimate Reddit domain using proper parsing."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        # Check for exact reddit.com domain or www.reddit.com
        return domain in ('reddit.com', 'www.reddit.com')
    except Exception:
        return False


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _hash_unit(text: str, salt: str) -> float:
    seed = f"{salt}:{text}"
    h = 0
    for ch in seed:
        h = ((h << 5) - h) + ord(ch)
        h &= 0xFFFFFFFF
    return (h % 100000) / 100000.0


def _parse_timestamp(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return 0.0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def _normalize_confidence(value: Any) -> float:
    return extract_confidence(value, fallback=0.5)


def _extract_elements(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        elements = payload.get("elements")
        if isinstance(elements, list):
            return elements
        if "nodes" in payload and "edges" in payload:
            nodes = payload.get("nodes") or []
            edges = payload.get("edges") or []
            if isinstance(nodes, list) and isinstance(edges, list):
                return nodes + edges
    if isinstance(payload, list):
        return payload
    return []


def _load_positions(path: Path) -> Dict[str, Dict[str, float]]:
    positions: Dict[str, Dict[str, float]] = {}
    if not path.exists():
        return positions
    payload = _load_json(path, {})
    if isinstance(payload, dict) and all(isinstance(v, dict) for v in payload.values()):
        for nid, pos in payload.items():
            if isinstance(pos, dict) and "x" in pos and "y" in pos:
                positions[nid] = {"x": float(pos["x"]), "y": float(pos["y"])}
        return positions
    elements = payload.get("elements") if isinstance(payload, dict) else payload
    if not isinstance(elements, list):
        return positions
    for el in elements:
        if not isinstance(el, dict):
            continue
        data = el.get("data") or {}
        nid = data.get("id")
        pos = el.get("position")
        if nid and isinstance(pos, dict) and "x" in pos and "y" in pos:
            positions[nid] = {"x": float(pos["x"]), "y": float(pos["y"])}
    return positions


def _seed_position(nid: str) -> Tuple[float, float]:
    angle = _hash_unit(nid, "angle") * math.tau
    radius = 260.0 + (_hash_unit(nid, "radius") * 140.0)
    return math.cos(angle) * radius, math.sin(angle) * radius


def _resolve_data_root() -> Tuple[Path, List[Path], Path]:
    graph_path = PRIMARY_DATA_ROOT / "graph_data.json"
    return PRIMARY_DATA_ROOT, [PRIMARY_DATA_ROOT], graph_path


def _load_feed_urls() -> Dict[str, str]:
    feed_urls: Dict[str, str] = {}
    feeds_path = ROOT / "src" / "modules" / "realtime_open_feeds.py"
    if not feeds_path.exists():
        return feed_urls
    try:
        tree = ast.parse(feeds_path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "THREAT_FEEDS":
                        value = ast.literal_eval(node.value)
                        if isinstance(value, dict):
                            for key, meta in value.items():
                                if isinstance(meta, dict):
                                    url = str(meta.get("url") or "").strip()
                                    if url:
                                        feed_urls[str(key).strip().lower()] = url
                        return feed_urls
    except Exception:
        return feed_urls
    return feed_urls


FEED_URLS = _load_feed_urls()


def _first_url(node: Dict[str, Any]) -> str:
    fields = [
        "post_url",
        "comment_url",
        "permalink",
        "url",
        "source_url",
        "reference",
    ]
    for key in fields:
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    payload = node.get("payload")
    if isinstance(payload, dict):
        for key in fields:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    meta = node.get("metadata") or node.get("meta")
    if isinstance(meta, dict):
        for key in fields:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _is_reddit_source(node: Dict[str, Any]) -> bool:
    source = str(node.get("source") or "").strip().lower()
    sub = str(node.get("subsource") or "").strip().lower()
    return source == "reddit" or (sub and source in ("", "reddit", "osint"))


def _extract_post_id(node: Dict[str, Any]) -> str:
    for key in ("post_id", "link_id", "reddit_id", "thread_id", "id"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            val = value.strip()
            if ":" in val:
                val = val.split(":", 1)[0]
            if val.isalnum() and len(val) >= 5 and len(val) <= 12:
                return val
    payload = node.get("payload") or {}
    if isinstance(payload, dict):
        for key in ("post_id", "link_id", "reddit_id", "thread_id", "id"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                val = value.strip()
                if ":" in val:
                    val = val.split(":", 1)[0]
                if val.isalnum() and len(val) >= 5 and len(val) <= 12:
                    return val
    return ""


def _build_reddit_post_url(node: Dict[str, Any], post_id: str) -> str:
    sub = str(node.get("subsource") or node.get("subreddit") or "").strip().lower()
    if sub:
        return f"https://www.reddit.com/r/{sub}/comments/{post_id}/"
    return f"https://www.reddit.com/comments/{post_id}/"


def _is_reddit_post_url(url: str) -> bool:
    return bool(REDDIT_POST_RE.search(url) or REDDIT_SHORT_RE.search(url))


def _derive_source_url(node: Dict[str, Any]) -> str:
    direct = _first_url(node)
    if direct:
        if _is_reddit_source(node) and _is_reddit_domain(direct) and not _is_reddit_post_url(direct):
            direct = ""
        if direct:
            return direct

    post_id = _extract_post_id(node)
    if post_id:
        return _build_reddit_post_url(node, post_id)

    indicator = str(node.get("indicator") or "").strip()
    if indicator:
        if URL_RE.match(indicator):
            return indicator
        if DOMAIN_RE.match(indicator):
            return f"https://{indicator}"
        if IP_RE.match(indicator):
            return f"https://www.virustotal.com/gui/ip-address/{indicator}"
        if HASH_RE.match(indicator):
            return f"https://www.virustotal.com/gui/search/{indicator}"

    return ""


def build_graph_3d(
    graph_path: Path | None = None,
    positions_path: Path | None = None,
    output_path: Path | None = None,
) -> Dict[str, Any]:
    data_root, output_roots, default_graph = _resolve_data_root()
    graph_path = graph_path or default_graph
    positions_path = positions_path or (data_root / "graph_positions.json")
    output_path = output_path or (data_root / "graph_3d.json")

    if not graph_path.exists():
        raise FileNotFoundError(f"graph_data.json not found: {graph_path}")

    payload = _load_json(graph_path, [])
    elements = _extract_elements(payload)
    if not elements:
        raise ValueError("graph_data.json has no elements to export")

    nodes_raw: List[Dict[str, Any]] = []
    edges_raw: List[Dict[str, Any]] = []
    for el in elements:
        if not isinstance(el, dict):
            continue
        data = el.get("data") if "data" in el else el
        if not isinstance(data, dict):
            continue
        if "source" in data and "target" in data:
            edges_raw.append({"data": data})
        else:
            nodes_raw.append({"data": data, "position": el.get("position")})

    positions = _load_positions(positions_path)
    node_map = {n["data"].get("id"): n["data"] for n in nodes_raw if n["data"].get("id")}

    degree: Dict[str, int] = {nid: 0 for nid in node_map}
    cross_source: Dict[str, int] = {nid: 0 for nid in node_map}
    for e in edges_raw:
        d = e.get("data", {})
        src = d.get("source")
        tgt = d.get("target")
        if src in degree:
            degree[src] += 1
        if tgt in degree:
            degree[tgt] += 1
        if src in node_map and tgt in node_map:
            src_key = str(node_map[src].get("subsource") or node_map[src].get("source") or "").strip().lower()
            tgt_key = str(node_map[tgt].get("subsource") or node_map[tgt].get("source") or "").strip().lower()
            if src_key and tgt_key and src_key != tgt_key:
                cross_source[src] += 1
                cross_source[tgt] += 1

    node_items: List[Dict[str, Any]] = []
    raw_energy: List[float] = []
    now = time.time()

    for item in nodes_raw[:MAX_NODES]:
        d = dict(item.get("data", {}))
        nid = d.get("id")
        if not nid:
            continue
        deg = degree.get(nid, 0)
        evidence = _safe_float(d.get("evidence_count") or d.get("volume") or d.get("volume_count") or deg or 1, 1.0)
        cross = _safe_float(d.get("cross_source_degree") or d.get("cross_source_count") or cross_source.get(nid, 0), 0.0)
        conf = _normalize_confidence(d.get("confidence") or d.get("adjusted_confidence"))
        rec = d.get("recency")
        if rec is None:
            rec = recency_factor(_parse_timestamp(d.get("timestamp")), now=now)
        rec = clamp_normalize(rec, default=0.5, label="recency")

        energy = (
            0.45 * conf
            + 0.20 * math.log1p(evidence)
            + 0.20 * math.log1p(cross)
            + 0.15 * rec
        )
        raw_energy.append(energy)

        pos = item.get("position") or positions.get(nid)
        if isinstance(pos, dict) and "y" in pos:
            y = _safe_float(pos.get("y"), 0.0)
        elif isinstance(d.get("y"), (int, float)):
            y = _safe_float(d.get("y"), 0.0)
        else:
            y = (_hash_unit(str(nid), "y") - 0.5) * Y_SPAN

        node_items.append(
            {
                "id": nid,
                "data": d,
                "degree": deg,
                "evidence": evidence,
                "cross": cross,
                "confidence": conf,
                "recency": rec,
                "y": y,
            }
        )

    spectrum_values = percentile_normalize(raw_energy, keys=[item["id"] for item in node_items])
    nodes_out: List[Dict[str, Any]] = []
    for idx, item in enumerate(node_items):
        d = dict(item["data"])
        spec = clamp_normalize(spectrum_values[idx] if spectrum_values else 0.5, default=0.5, label="spectrum_index")
        conf = item["confidence"]
        rec = item["recency"]
        deg = item["degree"]
        cross = item["cross"]

        cross_norm = 1.0 - math.exp(-cross / 3.0) if cross > 0 else 0.0
        degree_norm = 1.0 - math.exp(-deg / 4.0) if deg > 0 else 0.0
        convergence = clamp_normalize((0.65 * cross_norm) + (0.35 * degree_norm), default=0.0, label="convergence")

        spectrum_hex = spectrum_color(spec, conf, rec)
        source_key = str(d.get("subsource") or d.get("source") or "").strip().lower()
        source_color = d.get("source_color") or (SOURCE_COLOR_MAP.get(source_key) if source_key else "")
        volume_weight = max(1.0, item["evidence"])
        volume_count = max(1, _safe_int(d.get("volume_count") or volume_weight, 1))
        size = 8.0 + (math.log1p(volume_count) * 6.0)
        size = max(6.0, min(90.0, size))

        x = (spec - 0.5) * X_SPAN
        y = item["y"]
        z = (spec ** 1.35) * Z_SPAN + (convergence * Z_BONUS)
        z = max(-Z_CLAMP, min(Z_CLAMP, z))

        source_url = _derive_source_url(d)
        if not source_url:
            label_url = d.get("label")
            if isinstance(label_url, str) and URL_RE.match(label_url.strip()):
                source_url = label_url.strip()
        if source_url and not d.get("post_url") and _is_reddit_post_url(source_url):
            d["post_url"] = source_url

        d.update(
            {
                "spectrum_index": round(spec, 4),
                "spectrum_color": spectrum_hex,
                "spectral_color": spectrum_hex,
                "color": spectrum_hex,
                "energy_weight": round(spec, 4),
                "volume_weight": float(volume_weight),
                "volume_count": volume_count,
                "confidence": round(conf, 4),
                "recency": round(rec, 4),
                "convergence": round(convergence, 4),
                "source_color": source_color or d.get("source_color") or "",
                "size": float(size),
                "source_url": source_url,
                "pos": {"x": float(x), "y": float(y), "z": float(z)},
                "x": float(x),
                "y": float(y),
                "z": float(z),
            }
        )
        nodes_out.append(d)

    nodes_by_id = {n["id"]: n for n in nodes_out}
    edges_out: List[Dict[str, Any]] = []
    for e in edges_raw[:MAX_EDGES]:
        d = dict(e.get("data", {}))
        src = d.get("source")
        tgt = d.get("target")
        if not src or not tgt:
            continue
        src_node = nodes_by_id.get(src)
        tgt_node = nodes_by_id.get(tgt)
        if not src_node or not tgt_node:
            continue

        dispersion = abs(_safe_float(src_node.get("spectrum_index"), 0.0) - _safe_float(tgt_node.get("spectrum_index"), 0.0))
        conf = min(_safe_float(src_node.get("confidence"), 0.5), _safe_float(tgt_node.get("confidence"), 0.5))
        coherence = clamp_normalize((1.0 - dispersion) * conf, default=0.0, label="coherence")
        avg_spec = (src_node["spectrum_index"] + tgt_node["spectrum_index"]) * 0.5
        avg_conf = (src_node["confidence"] + tgt_node["confidence"]) * 0.5
        avg_rec = (src_node["recency"] + tgt_node["recency"]) * 0.5
        edge_color = spectrum_color(avg_spec, avg_conf, avg_rec)

        opacity = (0.05 + (0.55 * coherence)) * (1.0 - (dispersion * 0.6))
        opacity = max(0.02, min(0.75, opacity))
        thickness = 0.25 + (1.25 * coherence)

        d.update(
            {
                "coherence": round(coherence, 4),
                "dispersion": round(dispersion, 4),
                "opacity": round(opacity, 4),
                "edge_thickness": round(thickness, 4),
                "color": edge_color,
                "spectrum_color": edge_color,
                "spectral_color": edge_color,
            }
        )

        edges_out.append(d)

    url_cache: Dict[str, str] = {}
    for node in nodes_out:
        nid = node.get("id")
        if not nid:
            continue
        candidate = _derive_source_url(node)
        if candidate and _is_reddit_source(node) and _is_reddit_domain(candidate) and not _is_reddit_post_url(candidate):
            candidate = ""
        url_cache[nid] = candidate

    adjacency: Dict[str, List[str]] = {}
    for edge in edges_out:
        src = edge.get("source")
        tgt = edge.get("target")
        if not src or not tgt:
            continue
        adjacency.setdefault(src, []).append(tgt)
        adjacency.setdefault(tgt, []).append(src)

    for node in nodes_out:
        if node.get("source_url"):
            continue
        nid = node.get("id")
        if not nid:
            continue
        neighbors = adjacency.get(nid, [])
        best = ""
        for nb in neighbors:
            candidate = url_cache.get(nb, "")
            if not candidate:
                continue
            best = candidate
            break
        if best:
            node["source_url"] = best
            if not node.get("post_url") and _is_reddit_post_url(best):
                node["post_url"] = best

    payload_out = {
        "nodes": nodes_out,
        "edges": edges_out,
        "meta": {
            "built_at": int(time.time()),
            "nodes": len(nodes_out),
            "edges": len(edges_out),
        },
    }

    output_targets: List[Path] = []
    if output_path is not None:
        output_targets.append(output_path)
    for root in output_roots:
        output_targets.append(root / "graph_3d.json")
    seen: set = set()
    for path in output_targets:
        if path in seen:
            continue
        seen.add(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload_out, indent=2))

    return payload_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ACE-T 3D spectrum graph.")
    parser.add_argument("--graph", type=Path, default=None)
    parser.add_argument("--positions", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    build_graph_3d(args.graph, args.positions, args.out)


if __name__ == "__main__":
    main()
