from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Set, Tuple, cast

from sqlalchemy import create_engine, case, desc
from sqlalchemy.orm import sessionmaker
# from ..legacyV1.ace_t_osint.models import Event, Incident
import dash_cytoscape as cyto
from dash import Dash, Input, Output, State, ALL, callback_context, ClientsideFunction, dcc, html, no_update
from flask import Response, jsonify, request, send_file, send_from_directory

from gui.state import GraphState

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_DIR = BASE_DIR / "db"
GUI_DIR = BASE_DIR / "gui"
THREE_DIR = GUI_DIR / "three"

GRAPH_PATH = DATA_DIR / "graph_data.json"
GRAPH_POS_PATH = DATA_DIR / "graph_positions.json"
GRAPH3D_PATH = DATA_DIR / "graph_3d.json"
DEFAULT_JSON = GRAPH_PATH
_DB_CANDIDATES = [DB_DIR / "project.db", DB_DIR / "osint.db"]
DEFAULT_DB = next((p for p in _DB_CANDIDATES if p.exists()), _DB_CANDIDATES[0])

THREE_HTML_PATH = GUI_DIR / "three_view_3d.html"
THREE_VENDOR_DIR = THREE_DIR / "vendor"
SURVEILLANCE_FILE = DATA_DIR / "surveillance.json"
GROUP_FILE = DATA_DIR / "group_state.json"
INGEST_STATUS_PATH = DATA_DIR / "ingest_status.json"

LAST_3D_BUILD = 0.0
BUILD_3D_LOCK = Lock()
START_EMPTY = False

TIMEZONE = "UTC"
SUBREDDITS: List[str] = []
ENABLE_GROUP_CONNECTORS = True
EXCLUDED_NODE_KINDS: Set[str] = set()
DISPLAY_NODE_KINDS: Set[str] = set()

CYAN = "#22d3ee"
CYAN_DIM = "#0891b2"
BG_VANTA = "#000000"
BG_PANEL_ALT = "#04111a"
TEXT_MAIN = "#e6f1ff"
TEXT_MUTED = "#6fb8d6"

SEVERITY_COLORS: Dict[str, str] = {
    "low": "#22d3ee",
    "medium": "#fbbf24",
    "high": "#fb7185",
    "critical": "#f472b6",
}

try:
    from sources.source_colors import SOURCE_COLORS
except Exception:
    SOURCE_COLORS: Dict[str, str] = {}
_DYNAMIC_SOURCE_COLORS: Dict[str, str] = {}

FOCUS_CONFIG = {
    "depth": 1,
    "fade_opacity": 0.08,
    "neighbor_opacity": 0.65,
}

# Dash Cytoscape 1.x bundles an older Cytoscape.js build that rejects shadow-* styles.
ENABLE_CYTO_SHADOWS = os.getenv("ACE_T_CYTO_SHADOWS", "").strip().lower() in {"1", "true", "yes"}
SIMPLE_STYLE = os.getenv("ACE_T_SIMPLE_STYLE", "1").strip().lower() in {"1", "true", "yes"}
SHADOW_STYLE_PROPS = ("shadow-blur", "shadow-color", "shadow-offset-x", "shadow-offset-y")
CYTO_GLOW_FALLBACKS: Dict[str, Dict[str, Any]] = {
    ".focus": {"background-blacken": -0.35, "border-opacity": 1},
    ".activated": {"background-blacken": -0.45},
    ".neighbor": {"background-blacken": -0.15},
    ".surveillance": {"border-opacity": 1, "background-blacken": -0.1},
    ".surv-moderate": {"border-opacity": 1, "background-blacken": -0.12},
    ".surv-high": {"border-opacity": 1, "background-blacken": -0.18},
    ".surveillance-active": {"border-opacity": 1, "background-blacken": -0.22},
}

DETAILS_WIDTH = 320
NODE_PANEL_STYLE = {
    "position": "fixed",
    "top": "72px",
    "right": f"-{DETAILS_WIDTH}px",
    "width": f"{DETAILS_WIDTH}px",
    "height": "calc(100vh - 120px)",
    "background": "rgba(2, 12, 23, 0.96)",
    "borderLeft": f"1px solid {CYAN_DIM}",
    "boxShadow": "0 0 22px rgba(0,0,0,0.65)",
    "padding": "16px",
    "color": TEXT_MAIN,
    "overflowY": "auto",
    "transition": "right 180ms ease",
    "backdropFilter": "blur(8px)",
    "zIndex": 900,
}

CONTROL_HEIGHT = "34px"
CONTROL_RADIUS = "12px"
CONTROL_BORDER = f"1px solid {CYAN_DIM}"
CONTROL_LABEL_STYLE = {
    "fontSize": "11px",
    "color": TEXT_MUTED,
    "letterSpacing": "0.15em",
    "textTransform": "uppercase",
}
CONTROL_BASE_STYLE = {
    "backgroundColor": BG_PANEL_ALT,
    "border": CONTROL_BORDER,
    "borderRadius": CONTROL_RADIUS,
    "color": TEXT_MAIN,
    "height": CONTROL_HEIGHT,
}

TIME_WINDOW_SECONDS = {"all": None, "30d": 30 * 86400, "7d": 7 * 86400, "1d": 86400}
TIME_WINDOW_OPTIONS = [
    {"label": "All Data", "value": "all"},
    {"label": "Last 30 Days", "value": "30d"},
    {"label": "Last 7 Days", "value": "7d"},
    {"label": "Last 24 Hours", "value": "1d"},
]
DEFAULT_TIME_WINDOW = "all"

# -------------------------
# GUI IDS
# -------------------------
ID_CY = "cytoscape"
ID_SEV = "severity"
ID_WIN = "time-window"
ID_SEARCH = "search"
ID_FIT_BTN = "fit-view-btn"
ID_PANEL = "node-panel"
ID_PANEL_BODY = "node-panel-content"
ID_STORE_SELECTED = "selected-node"
ID_STORE_FULL = "full-graph"
ID_STORE_FILTERED = "filtered-graph"

GRAPH_PATH = DATA_DIR / "graph_data.json"
STATE = GraphState(GRAPH_PATH)


def _load_surveillance() -> Dict[str, Any]:
    try:
        return json.loads(SURVEILLANCE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_surveillance(data: Dict[str, Any]) -> None:
    try:
        SURVEILLANCE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def _coerce_timestamp(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        try:
            iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
            dt = datetime.fromisoformat(iso_text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None


def _extract_node_timestamp(data: Dict[str, Any]) -> float | None:
    candidates = [
        data.get("timestamp"),
        data.get("detected_at"),
        data.get("created_at"),
        data.get("updated_at"),
    ]
    payload = data.get("payload")
    if isinstance(payload, dict):
        candidates.extend(
            [
                payload.get("timestamp"),
                payload.get("detected_at"),
                payload.get("created_at"),
            ]
        )
    for candidate in candidates:
        ts = _coerce_timestamp(candidate)
        if ts is not None:
            return ts
    return None


def _time_window_cutoff(value: str | None) -> float | None:
    duration = TIME_WINDOW_SECONDS.get(value or DEFAULT_TIME_WINDOW)
    if not duration:
        return None
    return time.time() - duration


# --- Group state persistence (relation groups collapsed/expanded) ---



def _load_group_state() -> Dict[str, Any]:
    try:
        return json.loads(GROUP_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_group_state(data: Dict[str, Any]) -> None:
    try:
        GROUP_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert to float, returning default on failure."""
    try:
        return float(val)
    except Exception:
        return default


def _node_signature(d: Dict[str, Any], degree: int) -> str:
    # Compact signature to detect meaningful changes (timestamp, confidence, size, label, degree)
    l = str(d.get("label") or "")
    ts = str(int(_safe_float(d.get("timestamp", 0.0))))
    conf = f"{_safe_float(d.get('confidence', 0.5)):.3f}"
    sz = str(int(d.get("size", 0) or 0))
    return "|".join([l, ts, conf, sz, str(degree)])


def _should_display_node(data: Dict[str, Any]) -> bool:
    kind = str(data.get("kind") or "").lower()
    if kind in EXCLUDED_NODE_KINDS:
        return False
    if DISPLAY_NODE_KINDS:
        if not kind:
            return False
        return kind in DISPLAY_NODE_KINDS
    return True


def _compute_activity_level(entry: Dict[str, Any], now: float) -> str:
    # Returns 'low' | 'moderate' | 'high'
    last = entry.get("last_activity") or 0
    count = int(entry.get("activity_count") or 0)
    age_h = max(0.0, (now - float(last)) / 3600.0) if last else 9999.0
    score = count / max(1.0, age_h)
    if score >= 10.0 or (age_h < 0.5 and count >= 3):
        return "high"
    if score >= 1.0 or age_h < 24.0:
        return "moderate"
    return "low"


def _normalize_elements(payload: Any) -> Tuple[List[dict], Dict[str, Any]]:
    """
    Accept a variety of shapes and normalize into Cytoscape 'elements' list.
    Returns: (elements, meta)
    """
    meta: Dict[str, Any] = {}

    if payload is None:
        return [], {"note": "no_payload"}

    # Common shapes:
    # 1) {"elements": [...], "meta": {...}}
    if isinstance(payload, dict):
        if "elements" in payload and isinstance(payload["elements"], list):
            meta = payload.get("meta") or {}
            return payload["elements"], meta

        # 2) {"nodes": [...], "edges": [...]}
        if "nodes" in payload or "edges" in payload:
            nodes = payload.get("nodes") or []
            edges = payload.get("edges") or []
            if isinstance(nodes, list) and isinstance(edges, list):
                return (nodes + edges), payload.get("meta") or {}

        # 3) {"data": {...}} single node? wrap
        if "data" in payload:
            return [payload], {}

    # 4) (nodes, edges) tuple/list
    if isinstance(payload, (tuple, list)) and len(payload) == 2:
        a, b = payload
        if isinstance(a, list) and isinstance(b, list):
            return (a + b), {}

    # 5) Already a list of elements
    if isinstance(payload, list) and all(isinstance(x, dict) for x in payload):
        return payload, {}

    return [], {"note": f"unrecognized_payload_type:{type(payload).__name__}"}


def _load_elements_from_json(path: Path) -> Tuple[List[dict], Dict[str, Any]]:
    if not path.exists():
        return [], {"note": f"json_not_found:{path}"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        elements, meta = _normalize_elements(payload)
        # Extract nodes from edges if not present
        node_ids = set()
        for el in elements:
            data = el.get('data', {})
            if 'source' in data and 'target' in data:
                node_ids.add(data['source'])
                node_ids.add(data['target'])
        existing_node_ids = {el['data']['id'] for el in elements if 'id' in el.get('data', {}) and 'source' not in el['data']}
        for nid in node_ids - existing_node_ids:
            elements.append({'data': {'id': nid, 'label': str(nid)}})
        meta.setdefault("source", str(path))
        return elements, meta
    except Exception as e:
        return [], {"note": f"json_load_error:{e}", "source": str(path)}


# def _try_build_from_db(db_path: Path) -> Tuple[List[dict], Dict[str, Any]]:
#     """
#     Load the last 200 events from DB, sorted by max_risk_score DESC, then timestamp DESC.
#     """
#     try:
#         engine = create_engine(f"sqlite:///{db_path}")
#         Session = sessionmaker(bind=engine)
#         session = Session()
        
#         events = session.query(Event).order_by(
#             desc(Event.max_risk_score),
#             desc(Event.last_seen)
#         ).limit(200).all()
        
#         elements = []
#         for event in events:
#             # Node data
#             node_data = {
#                 "id": event.event_key,
#                 "label": event.primary_indicator or event.event_key,
#                 "severity": "medium",
#                 "source": list(event.source_set) if event.source_set else [],
#                 "first_seen": event.first_seen,
#                 "last_seen": event.last_seen,
#                 "alert_count": event.observation_count,
#                 "status": "active",
#             }
#             elements.append({"data": node_data, "classes": "event"})
            
#             # For edges, create connections based on shared sources
#             for other in events:
#                 if other.event_key != event.event_key:
#                     shared_sources = set(event.source_set or []) & set(other.source_set or [])
#                     if shared_sources:
#                         edge_data = {
#                             "source": event.event_key,
#                             "target": other.event_key,
#                             "shared_sources": list(shared_sources),
#                         }
#                         elements.append({"data": edge_data})
        
#         session.close()
#         meta = {"source": str(db_path), "builder": "event_db_loader", "count": len([e for e in elements if "source" not in e["data"]])}
#         return elements, meta
#     except Exception as e:
#         return [], {"note": f"db_load_failed:{e}", "source": str(db_path)}


# def load_new_incidents(db_path: Path, since: str) -> List[dict]:
#     try:
#         engine = create_engine(f"sqlite:///{db_path}")
#         Session = sessionmaker(bind=engine)
#         session = Session()
        
#         severity_case = case(
#             (Incident.severity == "critical", 4),
#             (Incident.severity == "high", 3),
#             (Incident.severity == "medium", 2),
#             (Incident.severity == "low", 1),
#             else_=0
#         )
        
#         events = session.query(Event).filter(Event.last_seen > since).order_by(
#             desc(Event.max_risk_score),
#             desc(Event.last_seen)
#         ).limit(10).all()  # Limit to 10 new at a time
        
#         elements = []
#         for event in events:
#             node_data = {
#                 "id": event.event_key,
#                 "label": event.primary_indicator or event.event_key,
#                 "severity": "medium",
#                 "source": list(event.source_set) if event.source_set else [],
#                 "first_seen": event.first_seen,
#                 "last_seen": event.last_seen,
#                 "alert_count": event.observation_count,
#                 "status": "active",
#             }
#             elements.append({"data": node_data, "classes": "event"})
#             # For simplicity, no edges for new incidents
#         session.close()
#         return elements
#     except Exception:
#         return []
#     """
#     Load the last 200 incidents from DB, sorted by severity DESC, then timestamp DESC.
#     """
#     try:
#         engine = create_engine(f"sqlite:///{db_path}")
#         Session = sessionmaker(bind=engine)
#         session = Session()
        
#         # Severity order: critical=4, high=3, medium=2, low=1
#         severity_case = case(
#             (Event.severity == "critical", 4),
#             (Event.severity == "high", 3),
#             (Event.severity == "medium", 2),
#             (Event.severity == "low", 1),
#             else_=0
#         )
        
#         events = session.query(Event).order_by(
#             severity_case.desc(),
#             desc(Event.last_seen)
#         ).limit(200).all()
        
#         elements = []
#         for incident in incidents:
#             # Node data
#             node_data = {
#                 "id": incident.incident_key,
#                 "label": incident.primary_indicator or incident.incident_key,
#                 "severity": incident.severity,
#                 "source": list(incident.source_set) if incident.source_set else [],
#                 "first_seen": incident.first_seen,
#                 "last_seen": incident.last_seen,
#                 "alert_count": incident.alert_count,
#                 "status": incident.status,
#             }
#             elements.append({"data": node_data, "classes": "incident"})
            
#             # For edges, create connections based on shared sources or event_keys
#             # Simple: connect incidents that share at least one source
#             for other in incidents:
#                 if other.incident_key != incident.incident_key:
#                     shared_sources = set(incident.source_set or []) & set(other.source_set or [])
#                     if shared_sources:
#                         edge_data = {
#                             "source": incident.incident_key,
#                             "target": other.incident_key,
#                             "shared_sources": list(shared_sources),
#                         }
#                         elements.append({"data": edge_data})
        
#         session.close()
#         meta = {"source": str(db_path), "builder": "incident_db_loader", "count": len([e for e in elements if "source" not in e["data"]])}
#         return elements, meta
#     except Exception as e:
#         return [], {"note": f"db_load_failed:{e}", "source": str(db_path)}


def _sample_graph() -> Tuple[List[dict], Dict[str, Any]]:
    # Always-boot demo graph so the UI is never blank.
    elements = [
        {"data": {"id": "A", "label": "Ingest", "kind": "node", "severity": "low"}},
        {"data": {"id": "B", "label": "Enrich", "kind": "node", "severity": "medium"}},
        {"data": {"id": "C", "label": "Correlate", "kind": "node", "severity": "high"}},
        {"data": {"id": "D", "label": "Score", "kind": "node", "severity": "medium"}},
        {"data": {"id": "E", "label": "Alert", "kind": "node", "severity": "high"}},
        {"data": {"id": "AB", "source": "A", "target": "B", "label": "flow"}},
        {"data": {"id": "BC", "source": "B", "target": "C", "label": "flow"}},
        {"data": {"id": "CD", "source": "C", "target": "D", "label": "flow"}},
        {"data": {"id": "DE", "source": "D", "target": "E", "label": "flow"}},
    ]
    meta = {"source": "sample_graph", "note": "no graph data found; showing sample"}
    return elements, meta


def _inject_group_parents(elements: List[dict]) -> None:
    """
    Add Cytoscape compound group nodes and set `data.parent` on member nodes
    using `subsource` if present, otherwise `source`.
    Mutates the `elements` list in-place. Skips if groups already exist.
    """
    existing_group_ids = {
        el.get("data", {}).get("id")
        for el in elements
        if el.get("data", {}).get("kind") == "group"
    }

    group_map: Dict[str, str] = {}

    # create group nodes
    for el in elements:
        d = el.get("data") or {}
        # skip edges
        if "source" in d and "target" in d:
            continue
        grp_key = (d.get("subsource") or d.get("source") or "").strip()
        if not grp_key:
            continue
        gid = group_map.get(grp_key) or f"group::{grp_key}"
        group_map.setdefault(grp_key, gid)
        if gid in existing_group_ids:
            continue
        group_node = {"data": {"id": gid, "label": grp_key, "kind": "group"}}
        elements.append(group_node)
        existing_group_ids.add(gid)

    # assign parent on member nodes
    for el in elements:
        d = el.get("data") or {}
        if d.get("kind") == "group":
            continue
        if d.get("parent"):
            continue
        if "source" in d and "target" in d:
            continue
        grp_key = (d.get("subsource") or d.get("source") or "").strip()
        if not grp_key:
            continue
        gid = group_map.get(grp_key)
        if gid:
            d["parent"] = gid


def _inject_relation_hubs(elements: List[dict]) -> None:
    """
    For each unique edge `relation` value, create a synthetic 'relation_hub' node and
    connect it to the member nodes with edges of relation 'relation_cluster'.
    Mutates elements in-place and avoids duplicating hubs.
    """
    rel_map = {}  # relation -> {ids:set, hub_id:str}

    # collect node ids involved per relation
    for el in elements:
        d = el.get("data") or {}
        if "source" in d and "target" in d:
            rel = str(d.get("relation") or "").strip()
            if not rel:
                continue
            s = str(d.get("source"))
            t = str(d.get("target"))
            entry = rel_map.setdefault(rel, {"ids": set(), "hub": f"relhub::{rel}"})
            entry["ids"].add(s)
            entry["ids"].add(t)

    # add hub nodes and hub edges
    existing_ids = {el.get("data", {}).get("id") for el in elements}
    for rel, entry in rel_map.items():
        hub_id = entry["hub"]
        if hub_id not in existing_ids:
            elements.append({"data": {"id": hub_id, "label": rel, "kind": "relation_hub", "group": True}})
            existing_ids.add(hub_id)
        # create hub edges
        for member in sorted(entry["ids"]):
            # avoid duplicating edges if present
            eid = f"{hub_id}→{member}"
            elements.append({"data": {"id": eid, "source": hub_id, "target": member, "relation": "relation_cluster", "weight": 1.2}})


def _derive_group_id(data: Dict[str, Any]) -> str:
    parent = str(data.get("parent") or "").strip()
    if parent:
        return parent
    key = str(data.get("subsource") or data.get("source") or "").strip()
    return f"group::{key}" if key else ""


def _map_node_groups(nodes: List[dict]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for node in nodes:
        data = node.get("data") or {}
        nid = str(data.get("id") or "")
        if not nid:
            continue
        kind = str(data.get("kind") or "")
        if kind == "group":
            mapping[nid] = nid
            continue
        gid = _derive_group_id(data)
        if gid:
            mapping[nid] = gid
    return mapping


def _build_group_connectors(edges: List[dict], node_groups: Dict[str, str], available_group_ids: Set[str]) -> List[dict]:
    connectors: List[dict] = []
    seen: Set[Tuple[str, str]] = set()
    for edge in edges:
        data = edge.get("data") or {}
        if data.get("relation") == "group_connector":
            continue
        source = str(data.get("source") or "")
        target = str(data.get("target") or "")
        g1 = node_groups.get(source)
        g2 = node_groups.get(target)
        if not g1 or not g2 or g1 == g2:
            continue
        pair: Tuple[str, str] = (g1, g2) if g1 <= g2 else (g2, g1)
        if pair in seen:
            continue
        if pair[0] not in available_group_ids or pair[1] not in available_group_ids:
            continue
        seen.add(pair)
        connectors.append(
            {
                "data": {
                    "id": f"group-connector::{pair[0]}::{pair[1]}",
                    "source": pair[0],
                    "target": pair[1],
                    "relation": "group_connector",
                    "weight": 0.1,
                    # Keep cytoscape from warning about missing control-point distances
                    "curve_offset": 0,
                },
                "classes": "group-connector",
            }
        )
    return connectors


def _graph_source_candidates(json_path: Path | None, db_path: Path | None) -> List[Path]:
    candidates: List[Path] = []
    if json_path:
        candidates.append(json_path)
    if db_path:
        candidates.append(db_path)
    candidates.append(DEFAULT_JSON)
    candidates.append(DEFAULT_DB)
    return candidates


def _graph_source_mtime(json_path: Path | None, db_path: Path | None) -> float:
    for candidate in _graph_source_candidates(json_path, db_path):
        try:
            if candidate and candidate.exists():
                return candidate.stat().st_mtime
        except Exception:
            continue
    return 0.0


def _graph_backup_candidates(base: Path | None = None) -> List[Path]:
    target = base or DEFAULT_JSON
    directory = target.parent
    pattern = f"{target.stem}.backup*.json"
    entries: List[Tuple[float, Path]] = []
    try:
        for path in directory.glob(pattern):
            try:
                if not path.is_file():
                    continue
                entries.append((path.stat().st_mtime, path))
            except Exception:
                continue
    except Exception:
        return []
    entries.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in entries]


def _persist_positions_from_elements(elements: List[dict], dest: Path = GRAPH_POS_PATH) -> None:
    positions: Dict[str, Dict[str, float]] = {}
    for el in elements:
        if not isinstance(el, dict):
            continue
        data = el.get("data") or {}
        nid = data.get("id")
        pos = el.get("position")
        if not (nid and isinstance(pos, dict)):
            continue
        if "x" not in pos or "y" not in pos:
            continue
        try:
            positions[str(nid)] = {"x": float(pos["x"]), "y": float(pos["y"])}
        except Exception:
            continue
    if not positions:
        return
    try:
        dest.write_text(json.dumps(positions, indent=2), encoding="utf-8")
    except Exception:
        pass


def _seed_graph_from_backup(target: Path | None = None) -> bool:
    dest = target or DEFAULT_JSON
    try:
        if dest.exists() and dest.stat().st_size > 0:
            return False
    except Exception:
        pass
    for backup in _graph_backup_candidates(dest):
        try:
            payload = json.loads(backup.read_text(encoding="utf-8", errors="replace"))
            elements, _ = _normalize_elements(payload)
            if not elements:
                continue
            dest.write_text(json.dumps(elements, indent=2), encoding="utf-8")
            _persist_positions_from_elements(elements)
            print(f"[graph] restored {dest.name} from backup {backup.name}")
            return True
        except Exception:
            continue
    return False


def _ensure_seed_graph(json_path: Path | None) -> None:
    target = json_path or DEFAULT_JSON
    _seed_graph_from_backup(target)


def _wait_for_initial_graph(json_path: Path | None, db_path: Path | None, timeout: float = 300.0) -> None:
    """Block startup briefly so the GUI boots with real data instead of the sample graph.

    Increased default timeout to allow the ingestion scheduler to fetch sources
    before the web server starts. If you prefer not to block for long, set a
    smaller timeout when calling the function or start the server with a
    non-zero --reload so the UI will pick up the graph when it appears.
    """
    targets = [p for p in (json_path, db_path) if p]
    if not targets:
        targets = [DEFAULT_JSON]

    deadline = time.time() + max(1.0, timeout)
    print(f"waiting for initial graph data up to {timeout} seconds")
    while time.time() < deadline:
        for target in targets:
            try:
                if not target.exists() or target.stat().st_size <= 0:
                    continue
                payload = json.loads(target.read_text())
                elements, _ = _normalize_elements(payload)
                if elements:
                    print(f"initial graph found: {target} (elements={len(elements)})")
                    return
            except Exception:
                continue
        time.sleep(1.2)
    print(f"initial graph not found within timeout ({timeout} s); starting without graph")


def _load_backup_graph() -> Tuple[List[dict], Dict[str, Any]]:
    for backup in _graph_backup_candidates():
        elems, meta = _load_elements_from_json(backup)
        if elems:
            note = meta.get("note")
            meta["note"] = f"{note};restored_from_backup" if note else "restored_from_backup"
            meta.setdefault("source", str(backup))
            return elems, meta
    return [], {}


def load_graph(json_path: Path | None, db_path: Path | None) -> Tuple[List[dict], Dict[str, Any]]:
    # Preference: explicit DB > explicit JSON > default DB > default JSON > sample
    # if db_path:
    #     elems, meta = _try_build_from_db(db_path)
    #     if elems:
    #         try:
    #             _inject_group_parents(elems)
    #         except Exception:
    #             pass
    #         return elems, meta
    if json_path:
        elems, meta = _load_elements_from_json(json_path)
        if elems:
            # inject 2D grouping metadata for Cytoscape
            try:
                _inject_group_parents(elems)
            except Exception:
                pass
            try:
                _inject_relation_hubs(elems)
            except Exception:
                pass
            return elems, meta

    # if DEFAULT_DB.exists():
    #     elems, meta = _try_build_from_db(DEFAULT_DB)
    #     if elems:
    #         try:
    #             _inject_group_parents(elems)
    #         except Exception:
    #             pass
    #         return elems, meta

    if DEFAULT_JSON.exists():
        elems, meta = _load_elements_from_json(DEFAULT_JSON)
        if elems:
            try:
                _inject_group_parents(elems)
            except Exception:
                pass
            try:
                _inject_relation_hubs(elems)
            except Exception:
                pass
            return elems, meta

    backup_elems, backup_meta = _load_backup_graph()
    if backup_elems:
        try:
            _inject_group_parents(backup_elems)
        except Exception:
            pass
        try:
            _inject_relation_hubs(backup_elems)
        except Exception:
            pass
        return backup_elems, backup_meta

    return _sample_graph()


def _ensure_graph3d_fresh() -> None:
    """Rebuild graph_3d.json when missing or older than graph_data/positions."""
    global LAST_3D_BUILD
    try:
        now = time.time()
        out_exists = GRAPH3D_PATH.exists()
        out_m = GRAPH3D_PATH.stat().st_mtime if out_exists else 0
        data_m = GRAPH_PATH.stat().st_mtime if GRAPH_PATH.exists() else 0
        pos_m = GRAPH_POS_PATH.stat().st_mtime if GRAPH_POS_PATH.exists() else 0

        stale = (not out_exists) or (out_m < data_m) or (out_m < pos_m)
        if not stale and out_exists:
            try:
                payload = json.loads(GRAPH3D_PATH.read_text())
                stale = len(payload.get("nodes") or []) == 0
            except Exception:
                stale = True

        if not stale:
            return
        if now - LAST_3D_BUILD < 5:
            return
        if not BUILD_3D_LOCK.acquire(blocking=False):
            return
        try:
            from src.three.export_3d import main as build_3d  # type: ignore
            build_3d()
            LAST_3D_BUILD = time.time()
        finally:
            BUILD_3D_LOCK.release()
    except Exception:
        # Silent on failure; the route falls back to existing file or empty payload
        pass


def _position_coverage(elements: List[dict]) -> float:
    def is_edge(el: dict) -> bool:
        d = el.get("data") or {}
        return "source" in d and "target" in d

    nodes = [el for el in elements if not is_edge(el)]
    if not nodes:
        return 0.0
    with_pos = 0
    for n in nodes:
        pos = n.get("position")
        if isinstance(pos, dict) and {"x", "y"} <= set(pos):
            with_pos += 1
    return with_pos / max(1, len(nodes))


def _derive_lod_stage(zoom: float | None) -> str:
    if zoom is None:
        return "mid"
    if zoom < 0.6:
        return "far"
    if zoom < 1.4:
        return "mid"
    return "near"


def strip_positions(elements: List[dict]) -> List[dict]:
    for el in elements:
        if isinstance(el, dict) and "position" in el:
            el.pop("position", None)
    return elements


def _prime_visual_defaults(elements: List[dict]) -> None:
    """Ensure nodes/edges have baseline visual fields before the first callback runs."""
    for el in elements:
        if not isinstance(el, dict):
            continue
        data = el.get("data")
        if not isinstance(data, dict):
            continue
        if "source" in data and "target" in data:
            data.setdefault("weight", 1.0)
            data.setdefault("curve_offset", 40)
            continue
        sev = (data.get("severity") or "medium").lower()
        src = (data.get("subsource") or data.get("source") or "").strip().lower()
        if src:
            data["color"] = _source_color(src)
        else:
            data.setdefault("color", severity_to_color(sev))
        data.setdefault("opacity", 1.0)
        try:
            sz = max(1, min(100, int(data.get("size", 18))))
        except Exception:
            sz = 18
        data["size"] = sz
        mass = data.get("mass")
        try:
            data["mass"] = max(1.0, float(mass)) if mass is not None else max(1.0, float(sz))
        except Exception:
            data["mass"] = max(1.0, float(sz))


def _event_shifted(tap_event: Any) -> bool:
    try:
        original = tap_event.get("originalEvent") or tap_event.get("original_event") or {}
        return bool(original.get("shiftKey") or original.get("shift_key"))
    except Exception:
        return False


def get_n_hop_nodes(focus_id: str, edges: List[dict], depth: int) -> set[str]:
    if not focus_id or depth <= 0:
        return {focus_id} if focus_id else set()

    adjacency: Dict[str, set] = {}
    for e in edges:
        d = e.get("data") or {}
        s = str(d.get("source") or "")
        t = str(d.get("target") or "")
        if not s or not t:
            continue
        adjacency.setdefault(s, set()).add(t)
        adjacency.setdefault(t, set()).add(s)

    visited = {focus_id}
    frontier = {focus_id}
    for _ in range(depth):
        next_frontier = set()
        for nid in frontier:
            for neigh in adjacency.get(nid, set()):
                if neigh not in visited:
                    visited.add(neigh)
                    next_frontier.add(neigh)
        frontier = next_frontier

    return visited


def _apply_filters_to_elements(elements, severities, time_window, search, selected_id, focus_depth, sources=None):
    """Apply severity/time/search/focus AND source filtering.

    sources: list of source names to include (if provided and non-empty)
    """
    nodes = [e for e in elements if 'id' in e.get('data', {})]
    edges = [e for e in elements if 'source' in e.get('data', {})]
    sev_set = set((s or "").lower() for s in (severities or []))
    q = (search or "").strip().lower()
    src_set = set((s or "").lower() for s in (sources or []))

    kept_nodes = []
    kept_ids = set()

    for n in nodes:
        d = n.get("data") or {}
        sev = (d.get("severity") or "medium").lower()
        label = str(d.get("label") or d.get("id") or "").lower()
        nid = str(d.get("id") or "")
        src = str(d.get("subsource") or d.get("source") or "").lower()

        # severity filter
        if sev_set and sev not in sev_set:
            continue
        # source filter
        if src_set and src not in src_set:
            continue
        # time window
        if time_window and time_window != "all":
            ts = d.get("timestamp", 0)
            cutoff = time.time() - _parse_time_window(time_window)
            if ts < cutoff:
                continue
        # search
        if q and not (q in label or q in str(nid).lower() or q in src):
            continue

        kept_nodes.append(n)
        kept_ids.add(nid)

    kept_edges = [e for e in edges if str(e.get("data", {}).get("source", "")) in kept_ids and str(e.get("data", {}).get("target", "")) in kept_ids]

    # focus
    focus_id = str(selected_id or "")
    depth = max(1, int(focus_depth or 1))
    if focus_id:
        focus_nodes = get_n_hop_nodes(focus_id, kept_edges, depth)
        neighbor_nodes = focus_nodes - {focus_id}
        for n in kept_nodes:
            d = n.get("data") or {}
            nid = str(d.get("id") or "")
            classes = set(filter(None, (n.get("classes") or "").split()))
            if nid == focus_id:
                classes.add("focus")
                classes.add("activated")
            elif nid in neighbor_nodes:
                classes.add("neighbor")
            else:
                classes.add("faded")
            n["classes"] = " ".join(sorted(classes))

    return kept_nodes + kept_edges


def _parse_time_window(w):
    if w == "1d":
        return 24 * 3600
    if w == "7d":
        return 7 * 24 * 3600
    if w == "30d":
        return 30 * 24 * 3600
    return 0


def _apply_shadow_compat(stylesheet: List[dict]) -> None:
    if ENABLE_CYTO_SHADOWS:
        return
    for rule in stylesheet:
        style = rule.get("style")
        if not isinstance(style, dict):
            continue
        for prop in SHADOW_STYLE_PROPS:
            style.pop(prop, None)
        selector = str(rule.get("selector") or "")
        fallback = CYTO_GLOW_FALLBACKS.get(selector)
        if fallback:
            for key, value in fallback.items():
                style.setdefault(key, value)


def build_stylesheet(lod_stage: str = "mid", layout_mode: str | None = None) -> List[dict]:
    if SIMPLE_STYLE:
        return [
            {
                "selector": "core",
                "style": {
                    "background-color": BG_VANTA,
                    "selection-box-color": "transparent",
                    "selection-box-border-color": "transparent",
                    "selection-box-opacity": 0,
                    "selection-box-border-width": 0,
                    "active-bg-color": "transparent",
                    "active-bg-opacity": 0,
                },
            },
            {
                "selector": "node",
                "style": {
                    "label": "",
                    "background-color": "data(color)",
                    "border-color": "rgba(255,255,255,0.22)",
                    "border-width": 0.8,
                    "width": 18,
                    "height": 18,
                    "opacity": 1,
                    "background-opacity": 0.96,
                    "shadow-blur": 8,
                    "shadow-color": "rgba(255,255,255,0.06)",
                    "shadow-offset-x": 0,
                    "shadow-offset-y": 0,
                    "z-index": 1,
                },
            },
            {
                "selector": "edge",
                "style": {
                    "line-color": "#00e6d0",
                    "target-arrow-color": "#00e6d0",
                    "target-arrow-shape": "triangle",
                    "curve-style": "bezier",
                    "opacity": 0.4,
                    "width": 1,
                    "arrow-scale": 0.35,
                },
            },
            {
                "selector": "node:parent",
                "style": {
                    "display": "none",
                    "background-opacity": 0,
                    "border-width": 0,
                    "padding": 0,
                },
            },
        ]

    layout_mode = (layout_mode or "").lower()
    base = [
        {
            "selector": "core",
            "style": {
                "background-color": BG_VANTA,
                "selection-box-color": "transparent",
                "selection-box-border-color": "transparent",
                "selection-box-opacity": 0,
                "selection-box-border-width": 0,
                "active-bg-color": "transparent",
                "active-bg-opacity": 0,
                "outside-texture-bg-color": "transparent",
                "outside-texture-bg-opacity": 0,
            },
        },
        {
            "selector": "node",
            "style": {
                "label": "",
                "text-opacity": 0,
                "background-color": "data(color)",
                "border-color": "rgba(255,255,255,0.22)",
                "width": "mapData(size, 1, 100, 14, 30)",
                "height": "mapData(size, 1, 100, 14, 30)",
                "border-width": 0.8,
                "opacity": "data(opacity)",
                "background-opacity": 0.96,
                "shadow-blur": 8,
                "shadow-color": "rgba(255,255,255,0.06)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
                "z-index": 1,
                "transition-property": "opacity, border-width",
                "transition-duration": "150ms",
            },
        },
        {
            "selector": "edge",
            "style": {
                "label": "",
                "text-opacity": 0,
                "curve-style": "bezier",
                "line-color": "#00e6d0",
                "target-arrow-color": "#00e6d0",
                "target-arrow-shape": "triangle",
                "line-cap": "round",
                "opacity": 0.15,
                "width": "mapData(weight, 1, 200, 0.4, 1.2)",
                "control-point-distance": "data(curve_offset)",
                "control-point-step-size": 60,
                "arrow-scale": 0.35,
            },
        },
        {
            "selector": "node:parent",
            "style": {
                "display": "none",
                "background-opacity": 0,
                "border-width": 0,
            },
        },
        {"selector": ".faded", "style": {"opacity": FOCUS_CONFIG["fade_opacity"]}},
        {"selector": ".edge-faded", "style": {"opacity": 0.12}},
        {
            "selector": ".focus",
            "style": {
                "opacity": 1,
                "border-width": 3,
                "border-color": "#00ffff",
                "shadow-blur": 12,
                "shadow-color": "rgba(0,255,255,0.6)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
                "z-index": 999,
            },
        },
        {
            "selector": ".activated",
            "style": {
                "background-color": "#4ef0ff",
                "border-width": 2.5,
                "border-color": "#ffffff",
                "width": "mapData(size, 1, 100, 18, 38)",
                "height": "mapData(size, 1, 100, 18, 38)",
                "opacity": 1,
                "shadow-blur": 20,
                "shadow-color": "rgba(255,255,255,0.55)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
            },
        },
        {
            "selector": ".neighbor",
            "style": {
                "opacity": FOCUS_CONFIG["neighbor_opacity"],
                "border-width": 1.2,
                "border-color": "#00ffff",
                "shadow-blur": 8,
                "shadow-color": "rgba(0,255,255,0.45)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
            },
        },
        {
            "selector": ".edge-focus",
            "style": {
                "opacity": 0.9,
                "line-color": "#00ff9c",
                "target-arrow-color": "#00ff9c",
                "width": "mapData(weight, 1, 200, 1.2, 3.5)",
            },
        },
        {
            "selector": ".edge-neighbor",
            "style": {
                "opacity": 0.7,
                "line-color": "#00e6d0",
                "target-arrow-color": "#00e6d0",
                "width": "mapData(weight, 1, 200, 1.5, 4.5)",
            },
        },
        # Structural hubs/groups stay hidden in the live graph
        {
            "selector": "node[kind = \"group\"], node[kind = \"relation_hub\"], node[kind = \"source_hub\"]",
            "style": {
                "display": "none",
                "label": "",
                "text-opacity": 0,
            },
        },
        # Allow hiding nodes by class
        {
            "selector": "node.hidden",
            "style": {
                "display": "none",
            },
        },
        # Nodes with a parent get a subtle border when visible
        {
            "selector": "node[parent]",
            "style": {
                "border-style": "none",
                "border-width": 0,
                "border-color": "transparent",
            },
        },
        # Surveillance visual: ring + subtle pulse
        {
            "selector": ".surveillance",
            "style": {
                "border-color": "#ffb347",  # amber
                "border-width": 2,
                "shadow-blur": 8,
                "shadow-color": "rgba(255,179,71,0.35)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
                "z-index": 998,
            },
        },
        {
            "selector": ".surv-moderate",
            "style": {
                "border-color": "#00d0ff",
                "shadow-blur": 10,
                "shadow-color": "rgba(0,208,255,0.35)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
            },
        },
        {
            "selector": ".surv-high",
            "style": {
                "border-color": "#ff3b7a",
                "shadow-blur": 12,
                "shadow-color": "rgba(255,59,122,0.45)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
            },
        },
        {
            "selector": ".surveillance-active",
            "style": {
                "border-width": 4,
                "shadow-blur": 22,
                "shadow-color": "rgba(255,179,71,0.7)",
                "shadow-offset-x": 0,
                "shadow-offset-y": 0,
            },
        },
        {
            "selector": ".group-connector",
            "style": {
                "line-style": "dashed",
                "line-color": "#18c0ff",
                "target-arrow-color": "#18c0ff",
                "target-arrow-shape": "vee",
                "width": 1.6,
                "opacity": 0.45,
                "curve-style": "straight",
            },
        },
    ]

    if lod_stage == "far":
        base.extend(
            [
                {
                    "selector": "node",
                    "style": {
                        "width": "mapData(size, 1, 100, 6, 18)",
                        "height": "mapData(size, 1, 100, 6, 18)",
                        "border-width": 0.5,
                        "shadow-blur": 0,
                    },
                },
                {"selector": "edge", "style": {"opacity": 0.18, "width": "mapData(weight, 1, 200, 0.4, 1.6)"}},
            ]
        )
    elif lod_stage == "near":
        base.extend(
            [
                {"selector": "node", "style": {"border-width": 2}},
                {
                    "selector": ".focus",
                    "style": {
                        "shadow-blur": 22,
                        "shadow-color": "rgba(0,255,255,0.9)",
                        "shadow-offset-x": 0,
                        "shadow-offset-y": 0,
                        "border-width": 3,
                    },
                },
                {"selector": ".edge-focus", "style": {"opacity": 0.95, "width": "mapData(weight, 1, 200, 2.5, 7)"}},
                {"selector": ".edge-neighbor", "style": {"opacity": 0.85}},
            ]
        )

    if layout_mode == "grid":
        base.extend(
            [
                {
                    "selector": "node",
                    "style": {"shape": "square", "border-width": 1.4, "shadow-blur": 0},
                },
                {"selector": "edge", "style": {"curve-style": "straight", "opacity": 0.25}},
            ]
        )
    elif layout_mode == "grouped":
        base.extend(
            [
                {
                    "selector": "node",
                    "style": {
                        "shadow-blur": 10,
                        "shadow-color": "rgba(0,255,255,0.25)",
                        "shadow-offset-x": 0,
                        "shadow-offset-y": 0,
                    },
                },
                {"selector": "node[kind = \"group\"]", "style": {"background-opacity": 0.18, "border-width": 3}},
                {"selector": ".group-connector", "style": {"opacity": 0.7, "width": 2.4}},
            ]
        )
    elif layout_mode in {"circle", "concentric"}:
        base.extend(
            [
                {"selector": "node", "style": {"border-width": 1, "background-opacity": 0.9}},
                {"selector": "edge", "style": {"opacity": 0.3, "curve-style": "bezier"}},
            ]
        )

    _apply_shadow_compat(base)
    return base


def severity_to_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev.lower(), CYAN_DIM)


def _hex_to_rgb(h: str) -> Tuple[int, int, int]:
    """Convert #rrggbb to (r,g,b) ints 0-255."""
    h = (h or "").lstrip("#")
    if len(h) == 3:
        h = ''.join(ch*2 for ch in h)
    try:
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except Exception:
        return 0, 0, 0


def _rgb_to_hex(rgb: Tuple[float, float, float]) -> str:
    r, g, b = [int(max(0, min(255, round(x)))) for x in rgb]
    return f"#{r:02x}{g:02x}{b:02x}"


def _mix_hex(h1: str, h2: str, t: float) -> str:
    """Linear mix between two hex colors by t (0..1)."""
    r1, g1, b1 = _hex_to_rgb(h1)
    r2, g2, b2 = _hex_to_rgb(h2)
    return _rgb_to_hex((r1 + (r2 - r1) * t, g1 + (g2 - g1) * t, b1 + (b2 - b1) * t))


def _source_color(source: str) -> str:
    key = (source or "").strip().lower()
    if not key:
        return "#4b5563"
    if key in SOURCE_COLORS:
        return SOURCE_COLORS[key]
    if key in _DYNAMIC_SOURCE_COLORS:
        return _DYNAMIC_SOURCE_COLORS[key]
    digest = hashlib.sha1(key.encode("utf-8")).digest()
    r = 80 + (digest[0] % 160)
    g = 80 + (digest[1] % 160)
    b = 80 + (digest[2] % 160)
    color = f"#{r:02x}{g:02x}{b:02x}"
    _DYNAMIC_SOURCE_COLORS[key] = color
    return color


def format_ts(ts: float) -> str:
    try:
        tz = ZoneInfo(TIMEZONE)
        return datetime.fromtimestamp(ts, tz=tz).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _pretty_json(payload: Any) -> str:
    try:
        return json.dumps(payload, indent=2, sort_keys=True, default=str)
    except Exception:
        return json.dumps({"unserializable": str(payload)}, indent=2)


def get_graph_status() -> tuple[int, int, str]:
    if not GRAPH_PATH.exists():
        return 0, 0, "—"

    try:
        elements = json.loads(GRAPH_PATH.read_text())
        nodes = [e for e in elements if not {"source", "target"} <= set(e.get("data", {}).keys())]
        edges = [e for e in elements if {"source", "target"} <= set(e.get("data", {}).keys())]
        mtime = datetime.fromtimestamp(GRAPH_PATH.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return len(nodes), len(edges), mtime
    except Exception:
        return 0, 0, "—"


def _layout_config(name: str, tick: int | None = None, fit_viewport: bool = True) -> Dict[str, Any]:
    """Centralized Cytoscape layout config with force-like defaults for grouping."""
    n = (name or "grouped").lower()
    cfg: Dict[str, Any] = {"name": n, "fit": fit_viewport, "padding": 30, "animate": False}

    if n == "grouped":
        # Weightless floating nodes with elastic push/pull physics
        cfg.update(
            {
                "name": "cose",
                "animate": True,
                "randomize": True,
                "nodeRepulsion": 250000,  # Very strong push for weightless floating
                "idealEdgeLength": 100,  # Closer connections for elastic springs
                "edgeElasticity": 0.85,  # High elasticity - nodes bounce/float like magnets
                "nestingFactor": 1.2,
                "gravity": 0.3,  # Minimal gravity - nodes float freely
                "numIter": 500,  # More iterations for stable floating positions
                "coolingFactor": 0.95,  # Slower cooling allows more movement
                "componentSpacing": 400,  # Large gaps between clusters
                "nodeDimensionsIncludeLabels": False,
                "nodeOverlap": 25,  # Strong overlap prevention
                "initialTemp": 1500,  # High initial energy for dynamic separation
                "minTemp": 0.5,  # Lower minimum keeps some residual motion
            }
        )
    elif n == "cose" or n == "force":
        # Physics-based force layout - nodes cluster by connections
        cfg.update(
            {
                "name": "cose",
                "animate": False,
                "randomize": True,
                "nodeRepulsion": 100000,
                "idealEdgeLength": 140,
                "edgeElasticity": 0.35,
                "nestingFactor": 1.1,
                "gravity": 0.85,
                "numIter": 550,
                "coolingFactor": 0.98,
                "componentSpacing": 280,
                "nodeDimensionsIncludeLabels": False,
            }
        )
    elif n == "concentric":
        cfg.update(
            {
                "name": "concentric",
                "levelWidth": 120,
                "minNodeSpacing": 40,
                "startAngle": 1.57,
                "sweep": 5.8,
                "animate": False,
                "avoidOverlap": True,
            }
        )
    elif n == "grid":
        cfg.update(
            {
                "name": "grid",
                "rows": None,
                "cols": None,
                "condense": True,
                "avoidOverlap": True,
                "animate": False,
            }
        )
    elif n == "cola":
        cfg.update(
            {
                "name": "cola",
                "animate": True,
                "refresh": 1,
                "maxSimulationTime": 4000,
                "ungrabifyWhileSimulating": False,
                "fit": False,
                "padding": 30,
                "randomize": False,
                "avoidOverlap": True,
                "handleDisconnected": True,
                "convergenceThreshold": 0.01,
                "nodeSpacing": 10,
                "edgeLength": 100,
                "edgeSymDiffLength": 0,
                "edgeJaccardLength": 0,
                "unconstrIter": 10,
                "userConstIter": 15,
                "allConstIter": 20,
            }
        )
    elif n == "circle":
        cfg.update(
            {
                "name": "circle",
                "avoidOverlap": True,
                "nodeDimensionsIncludeLabels": False,
                "padding": 50,
                "spacingFactor": 1.5,
                "startAngle": 0.0,
            }
        )
    elif n == "preset":
        cfg.update({"name": "preset", "fit": True, "animate": False})

    # Bump refresh token so Cytoscape reruns layout when inputs change
    if tick is not None:
        cfg["refresh"] = tick
    return cfg


def main() -> None:
    ap = argparse.ArgumentParser(description="ACE-T Cytoscape GUI (no engine).")
    ap.add_argument("--json", type=str, default="", help="Path to Cytoscape elements JSON (preferred).")
    ap.add_argument("--db", type=str, default="", help="Path to SQLite DB to build graph from (optional).")
    ap.add_argument("--host", type=str, default="127.0.0.1", help="Host bind.")
    ap.add_argument("--port", type=int, default=8050, help="Port.")
    ap.add_argument("--reload", type=int, default=0, help="Auto-reload graph every N seconds (0=off).")
    ap.add_argument("--start-empty", action="store_true", help="Start with an empty graph (do not seed sample or backups).")
    args = ap.parse_args()

    # Ensure we're running inside the expected conda environment (default: ace-t-env)
    expected_env = os.getenv("ACE_T_EXPECT_ENV", "ace-t-env")
    current_env = os.environ.get("CONDA_DEFAULT_ENV") or os.environ.get("VIRTUAL_ENV")
    if current_env != expected_env and not os.getenv("ACE_T_ALLOW_NO_CONDA", "").strip():
        msg = (
            f"ERROR: This GUI must be run inside the conda environment '{expected_env}'.\n"
            f"Current environment: {current_env!r}.\n"
            "Start the GUI using the provided launcher: './ACE-T SPECTRUM/run_graph.sh'\n"
            "Or run: conda run -n ace-t-env python3 cyto_gui.py [--options]"
        )
        print(msg)
        raise SystemExit(2)

    # Propagate start-empty flag to server scope
    global START_EMPTY
    START_EMPTY = bool(args.start_empty)

    json_path = Path(args.json).expanduser() if args.json else None
    db_path = Path(args.db).expanduser() if args.db else None

    # Give the ingestion pipeline a short head start so we render live data on first paint
    if not args.start_empty:
        if json_path is None:
            _ensure_seed_graph(None)
        _wait_for_initial_graph(json_path, db_path)
    else:
        print("[cyto_gui] starting with empty graph (--start-empty)")

    if args.start_empty:
        elements, meta = [], {"note": "start-empty"}
    else:
        elements, meta = _load_elements_from_json(DEFAULT_JSON)
    # Ensure unique IDs
    seen_ids = set()
    for el in elements:
        data = el.get('data', {})
        id_ = data.get('id')
        if id_:
            if id_ in seen_ids:
                counter = 1
                while f"{id_}_{counter}" in seen_ids:
                    counter += 1
                data['id'] = f"{id_}_{counter}"
            seen_ids.add(data['id'])
    nodes = [e for e in elements if 'id' in e.get('data', {}) and 'source' not in e['data']]
    edges = [e for e in elements if 'source' in e.get('data', {})]
    print(f"Loaded {len(elements)} elements: {len(nodes)} nodes, {len(edges)} edges")
    print(f"Unique node IDs: {len(seen_ids)}")
    if len(nodes) < 2 and not args.start_empty:
        print("ERROR: Less than 2 nodes loaded, aborting")
        return
    _prime_visual_defaults(elements)
    meta["graph_mtime"] = str(_graph_source_mtime(json_path, db_path))
    # Hardcode to cola layout only - continuous force-directed
    layout_name = "cola"
    if layout_name not in ("preset", "grouped_preset"):
        elements = strip_positions(list(elements))

    position_coverage = _position_coverage(elements)
    meta["position_coverage"] = str(round(position_coverage, 3))
    meta["has_positions"] = str(position_coverage > 0)
    if "subreddits" not in meta:
        meta["subreddits"] = json.dumps(SUBREDDITS)
    base_stylesheet = build_stylesheet(layout_mode=layout_name)

    app = Dash(
        __name__,
        suppress_callback_exceptions=True,
        title="ACE-T Graph View",
        external_stylesheets=[],
    )
    server = app.server

    # Ensure we are referencing the expected GUI directory and warn/fail fast if it's missing
    server.logger.info(f"GUI_DIR resolved to: {GUI_DIR}")
    server.logger.info(f"THREE_HTML_PATH resolved to: {THREE_HTML_PATH}")
    server.logger.info(f"Styles file: {GUI_DIR / 'styles.css'}")
    if not GUI_DIR.exists():
        server.logger.error(f"Required GUI_DIR not found: {GUI_DIR}")
        raise SystemExit(f"Required GUI_DIR not found: {GUI_DIR}")
    if not (GUI_DIR / 'styles.css').exists():
        server.logger.warning(f"Styles file missing in GUI_DIR: {GUI_DIR / 'styles.css'}")

    # Log whether legacyV2 is on the module search path for diagnostic purposes
    try:
        import sys
        legacy_matches = [p for p in sys.path if (p and 'legacyV2' in p)]
        expected_legacy = str((Path(__file__).resolve().parent.parent / 'legacyV2').resolve())
        server.logger.info("legacyV2 in sys.path: %s; matches=%s; expected_path=%s", bool(legacy_matches), legacy_matches, expected_legacy)
    except Exception:
        server.logger.exception("Unable to inspect sys.path for legacyV2")

    @server.route('/debug/paths')
    def _debug_paths():
        """Return diagnostic information about sys.path and legacyV2 presence."""
        import sys
        try:
            matches = [p for p in sys.path if p and 'legacyV2' in p]
            return jsonify({"legacy_in_sys_path": bool(matches), "matching_paths": matches, "sys_path_preview": sys.path[:50]})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route('/debug/graph')
    def _debug_graph():
        """Return current GraphState counts so clients can verify server-side data."""
        try:
            snap = STATE.load_full()
            return jsonify({
                "nodes": len(snap.nodes),
                "edges": len(snap.edges),
                "orphan_edges": snap.orphan_edges,
                "kept_edges": snap.kept_edges,
                "mtime": getattr(STATE, "_last_mtime", 0)
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route('/status')
    def _ingest_status():
        """Return ingestion status from the scheduler."""
        if not INGEST_STATUS_PATH.exists():
            return jsonify({"ok": False, "error": "ingest status not available"}), 404
        try:
            payload = json.loads(INGEST_STATUS_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        tasks = payload.get("tasks", {}) if isinstance(payload, dict) else {}
        unhealthy = any(isinstance(v, dict) and v.get("status") == "error" for v in tasks.values())
        if isinstance(payload, dict):
            payload["ok"] = not unhealthy
        return jsonify(payload)

    @server.route('/health')
    def _health():
        """Basic health check for ingestion tasks."""
        if not INGEST_STATUS_PATH.exists():
            return jsonify({"ok": False, "error": "ingest status not available"}), 503
        try:
            payload = json.loads(INGEST_STATUS_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        tasks = payload.get("tasks", {}) if isinstance(payload, dict) else {}
        unhealthy = any(isinstance(v, dict) and v.get("status") == "error" for v in tasks.values())
        return jsonify({"ok": not unhealthy}), (200 if not unhealthy else 503)

    # Optional background watcher that triggers a 3D rebuild when graph_data.json changes
    if os.getenv("ACE_T_AUTO_REBUILD_3D", "1").strip() not in {"0", "false", "no"}:
        def _start_graph_watcher(poll_seconds: int = 5):
            from threading import Thread
            def _watch():
                last_mtime = GRAPH_PATH.stat().st_mtime if GRAPH_PATH.exists() else 0.0
                server.logger.info("graph-watcher: starting (poll_seconds=%s)", poll_seconds)
                while True:
                    try:
                        if GRAPH_PATH.exists():
                            m = GRAPH_PATH.stat().st_mtime
                            if m != last_mtime:
                                last_mtime = m
                                server.logger.info("graph-watcher: detected graph_data.json mtime change; triggering 3D rebuild")
                                # Respect the BUILD_3D_LOCK to avoid double builds
                                if not BUILD_3D_LOCK.acquire(blocking=False):
                                    server.logger.info("graph-watcher: build already in progress, skipping")
                                else:
                                    try:
                                        try:
                                            from src.three.export_3d import main as build_3d  # type: ignore
                                            build_3d()
                                            server.logger.info("graph-watcher: build completed")
                                        except Exception:
                                            server.logger.exception("graph-watcher: failed to build 3D export")
                                    finally:
                                        BUILD_3D_LOCK.release()
                        time.sleep(poll_seconds)
                    except Exception:
                        server.logger.exception("graph-watcher: unexpected error in watcher loop")
                        time.sleep(poll_seconds)
            t = Thread(target=_watch, name="graph-watcher", daemon=True)
            t.start()
        # Start the watcher in background
        try:
            _start_graph_watcher()
        except Exception:
            server.logger.exception("Unable to start graph watcher")


    # add cache-busting query param based on file mtime to force client reload on changes
    styles_mtime = int((GUI_DIR / "styles.css").stat().st_mtime) if (GUI_DIR / "styles.css").exists() else int(time.time())

    app.index_string = """
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <link rel="stylesheet" href="/gui/styles.css?v={styles_mtime}">
        <style>
            html, body {
                margin: 0 !important;
                padding: 0 !important;
                background-color: #010409 !important;
                color: #e6f1ff !important;
                font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
            }

            * {
                outline: none !important;
                box-sizing: border-box;
            }

            input,
            button,
            .Select-control,
            .Select-option,
            .Select-value,
            .Select-placeholder,
            .Select-menu-outer {
                font-family: inherit !important;
            }

            .command-bar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
                padding: 8px 16px;
                border-bottom: 1px solid rgba(6, 182, 212, 0.2);
                background: linear-gradient(90deg, rgba(1,4,9,0.96), rgba(4,13,26,0.92));
                box-shadow: 0 6px 18px rgba(0,0,0,0.55);
                position: relative;
                z-index: 20;
            }

            .cluster-left,
            .cluster-right {
                display: flex;
                gap: 10px;
                align-items: center;
            }

            .control-field {
                display: flex;
                flex-direction: column;
                gap: 4px;
                min-width: 150px;
            }

            .control-title {
                font-size: 10px;
                text-transform: uppercase;
                letter-spacing: 0.32em;
                color: rgba(111, 184, 214, 0.9);
            }

            .control-select {
                border-radius: 10px;
                box-shadow: 0 0 0 1px rgba(8, 145, 178, 0.45);
                transition: box-shadow 160ms ease;
            }

            .control-select:hover,
            .control-select:focus-within {
                box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.85);
            }

            .control-select .Select-control {
                background-color: #06111f !important;
                border: none !important;
                box-shadow: none !important;
                height: 34px;
                color: #e6f1ff !important;
            }

            .Select-menu-outer,
            .Select-menu,
            .Select-option,
            .Select-placeholder,
            .Select-value-label,
            .Select-input,
            .Select-value {
                background-color: #030a14 !important;
                color: #e6f1ff !important;
                border: none !important;
            }

            .Select-menu-outer {
                border: 1px solid rgba(8,145,178,0.4) !important;
                border-radius: 10px !important;
            }

            .Select-option {
                cursor: pointer;
            }

            .Select-option.is-focused {
                background-color: #071423 !important;
            }

            .Select-option.is-selected {
                background-color: rgba(8,145,178,0.4) !important;
                color: #010409 !important;
                font-weight: 600;
            }

            .ace-pill {
                border-radius: 999px;
                border: 1px solid rgba(34, 211, 238, 0.7);
                padding: 8px 48px;
                letter-spacing: 0.8em;
                font-size: 12px;
                text-transform: uppercase;
                background: radial-gradient(circle, rgba(2, 18, 32, 0.95), rgba(1, 4, 9, 0.94));
                color: #b9fbff;
                box-shadow: 0 0 20px rgba(8, 145, 178, 0.25);
                font-weight: 700;
            }

            .search-shell {
                position: relative;
                width: 240px;
            }

            .search-shell input {
                width: 100%;
                height: 36px;
                border-radius: 10px;
                border: 1px solid rgba(8,145,178,0.4);
                background: #030a14;
                color: #e6f1ff;
                font-size: 13px;
                padding: 0 12px;
                box-shadow: inset 0 0 14px rgba(2,12,23,0.6);
            }

            .search-shell input::placeholder {
                color: rgba(180, 231, 255, 0.45);
                letter-spacing: 0.08em;
            }

            .status-bar {
                height: 38px;
                font-size: 12px;
                letter-spacing: 0.12em;
                background: rgba(1,3,7,0.92);
                border-top: 1px solid rgba(34,211,238,0.3);
                box-shadow: 0 -8px 20px rgba(0,0,0,0.4);
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
"""

    # cache-bust styles link so clients always fetch the latest CSS on reload
    app.index_string = app.index_string.replace('href="/gui/styles.css">', f'href="/gui/styles.css?v={styles_mtime}">')
    # replace placeholder in index string with actual mtime value (due to prior literal insertion)
    app.index_string = app.index_string.replace('{styles_mtime}', str(styles_mtime))

    @server.route("/3d")
    def three_home():
        # Serve the standalone 3D viewer (Three.js + instanced layout)
        # Inject cache-busted CSS link and set no-cache headers so clients always fetch current CSS
        try:
            html = THREE_HTML_PATH.read_text()
            styles_mtime = int((GUI_DIR / "styles.css").stat().st_mtime) if (GUI_DIR / "styles.css").exists() else int(time.time())
            html = html.replace('/gui/styles.css', f'/gui/styles.css?v={styles_mtime}')
            resp = Response(html, mimetype='text/html')
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
            return resp
        except Exception:
            server.logger.exception("Failed to serve 3D page with cache-bust; falling back to direct file")
            return send_file(str(THREE_HTML_PATH))

    @server.route("/three/<path:filename>")
    def three_vendor(filename: str):
        # Serve Three.js vendor assets for the 3D page
        resp = send_from_directory(str(THREE_VENDOR_DIR), filename)
        # Prevent caching of vendor assets during development so updates are always fetched
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @server.route("/gui/styles.css")
    def gui_styles():
        # Serve styles with headers to prevent caching so clients always fetch the latest CSS
        resp = send_file(str(GUI_DIR / "styles.css"), mimetype="text/css")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @server.post("/graph_3d/rebuild")
    def graph_3d_rebuild():
        """Trigger an on-demand rebuild of graph_3d.json. Useful when starting empty."""
        try:
            if not BUILD_3D_LOCK.acquire(blocking=False):
                return jsonify({"ok": False, "error": "build_in_progress"}), 409
            try:
                from src.three.export_3d import main as build_3d  # type: ignore
                build_3d()
                server.logger.info("/graph_3d/rebuild: build triggered")
                return jsonify({"ok": True, "built_at": int(time.time())})
            finally:
                BUILD_3D_LOCK.release()
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @server.get('/sources')
    def _sources_list():
        """Return the canonical list of sources and their theme colors for clients."""
        try:
            merged = dict(SOURCE_COLORS)
            merged.update(_DYNAMIC_SOURCE_COLORS)
            sources = [{"name": k, "color": v} for k, v in merged.items()]
            return jsonify({"sources": sources})
        except Exception:
            return jsonify({"sources": []})

    @server.post('/debug/inject_source')
    def _debug_inject_source():
        """Debug helper: inject N synthetic nodes for a `source` into `graph_data.json` and trigger a 3D rebuild.
        Usage: POST /debug/inject_source with JSON body {"source": "pastebin", "count": 8}
        This is intentionally a debug-only endpoint to help bring new sources into the graph for validation.
        """
        try:
            payload = request.get_json(force=False, silent=True) or {}
            source = (request.args.get('source') or payload.get('source') or '').strip().lower()
            count = int(request.args.get('count') or payload.get('count') or 8)
            if not source or source not in SOURCE_COLORS:
                return jsonify({"ok": False, "error": "unknown_source"}), 400

            # load existing graph_data.json (supports dict {"elements": [...]} or list-of-elements shape)
            try:
                existing = json.loads(GRAPH_PATH.read_text()) if GRAPH_PATH.exists() else {"elements": []}
            except Exception:
                existing = {"elements": []}

            if isinstance(existing, list):
                elements = existing
                as_dict = False
            else:
                elements = existing.get("elements", [])
                as_dict = True

            import hashlib, threading
            now = int(time.time())
            injected = []
            for i in range(count):
                nid = hashlib.sha256(f"{source}-{now}-{i}".encode()).hexdigest()
                node_data = {
                    "id": nid,
                    "label": f"{source}-sample-{i}",
                    "source": source,
                    "confidence": round(0.5 + ((i % 10) * 0.03), 2),
                    "timestamp": now - (i * 3600),
                    # provide a color so downstream exporters and clients can pick it up immediately
                    "color": SOURCE_COLORS.get(source),
                    "kind": "alert",
                }
                # Wrap in the expected element format and append
                elements.append({"data": node_data})
                injected.append(nid)

            # Persist back to disk in the same shape we loaded it
            if as_dict:
                GRAPH_PATH.write_text(json.dumps({"elements": elements}))
            else:
                GRAPH_PATH.write_text(json.dumps(elements))

            server.logger.info(f"/debug/inject_source: injected {count} nodes for {source}")

            # Trigger a background 3D rebuild so client will pick up the new payload
            def _bg_build():
                try:
                    from src.three.export_3d import main as build_3d  # type: ignore
                    build_3d()
                    server.logger.info("debug inject: build_3d complete")
                except Exception as e:
                    server.logger.exception("debug inject: build failed: %s", e)

            t = threading.Thread(target=_bg_build, daemon=True)
            t.start()

            return jsonify({"ok": True, "injected": len(injected), "ids": injected})
        except Exception as e:
            server.logger.exception("/debug/inject_source failed")
            return jsonify({"ok": False, "error": str(e)}), 500

    @server.get("/graph_3d.json")
    def graph_3d_json():
        """Serve graph_3d.json with optional filtering via query params:
        - q: search string to match label, id, source, or subsource (case-insensitive)
        - live: if '1' return only live_preserve nodes
        """
        _ensure_graph3d_fresh()
        if not GRAPH3D_PATH.exists():
            return Response('{"nodes":[],"edges":[]}', mimetype="application/json")
        q = (request.args.get("q") or "").strip().lower()
        live_only = request.args.get("live") == "1"
        try:
            j = json.loads(GRAPH3D_PATH.read_text())
        except Exception:
            return send_file(str(GRAPH3D_PATH), mimetype="application/json", conditional=True)

        nodes = j.get("nodes", [])
        edges = j.get("edges", [])
        if q or live_only:
            # filter nodes
            keep_ids = set()
            for n in nodes:
                nid = str(n.get("id") or "")
                nid_lower = nid.lower()
                label = str(n.get("label") or "").lower()
                src = str(n.get("source") or "").lower()
                sub = str(n.get("subsource") or "").lower()
                if live_only and not n.get("live_preserve"):
                    continue
                if q:
                    if q in nid_lower or q in label or q in src or q in sub:
                        keep_ids.add(nid)
                    else:
                        continue
                else:
                    keep_ids.add(nid)
            nodes = [n for n in nodes if n.get("id") in keep_ids]
            edges = [e for e in edges if str(e.get("source") or "") in keep_ids and str(e.get("target") or "") in keep_ids]

        # Debug logging to help diagnose empty 3D loads
        try:
            server.logger.info(f"/graph_3d.json q={q!r} live_only={live_only} nodes={len(nodes)} edges={len(edges)}")
        except Exception:
            pass

        built_at = None
        try:
            built_at = j.get("meta", {}).get("built_at")
        except Exception:
            built_at = None

        payload = {"nodes": nodes, "edges": edges, "meta": {"built_at": built_at}}
        resp = Response(json.dumps(payload), mimetype="application/json")
        resp.headers["X-Graph-Nodes"] = str(len(nodes))
        resp.headers["X-Graph-Edges"] = str(len(edges))
        resp.headers["X-Start-Empty"] = "1" if START_EMPTY else "0"
        resp.headers["X-Graph-Built-At"] = str(built_at if built_at is not None else "")
        try:
            server.logger.info(f"/graph_3d.json built_at={built_at} nodes={len(nodes)} edges={len(edges)}")
        except Exception:
            pass
        return resp

    @server.get("/api/graph")
    def api_graph():
        # For 3D view, return the 3D graph data with positions
        if GRAPH3D_PATH.exists():
            try:
                data = json.loads(GRAPH3D_PATH.read_text(encoding="utf-8"))
                return jsonify(data)
            except Exception:
                pass
        
        # Fallback to filtered 2D data
        if not STATE.loaded:
            STATE.load_full()
        
        severities = request.args.getlist("severity")
        time_window = request.args.get("time_window", "all")
        search = request.args.get("search", "")
        
        filtered = STATE.filter(severities, time_window, search)
        
        return jsonify({
            "nodes": filtered.nodes,
            "edges": filtered.edges
        })

    @server.route('/surveillance/toggle', methods=['POST'])
    def _surv_toggle_route():
        try:
            payload = request.get_json() or {}
            nid = str(payload.get('id') or '')
            if not nid:
                return jsonify({'ok': False, 'error': 'missing_id'}), 400
            surv = _load_surveillance()
            entry = surv.setdefault(nid, {})
            entry['enabled'] = not bool(entry.get('enabled'))
            now = int(time.time())
            if entry['enabled']:
                entry.setdefault('last_activity', now)
                entry.setdefault('activity_count', 0)
                entry['activity_level'] = _compute_activity_level(entry, now)
            _save_surveillance(surv)
            return jsonify({'ok': True, 'id': nid, 'enabled': bool(entry.get('enabled'))})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

    @server.get('/surveillance/list')
    def _surv_list():
        try:
            return jsonify(_load_surveillance())
        except Exception:
            return jsonify({})

    @server.get('/graph_3d/meta')
    def graph_3d_meta():
        """Return exported graph_3d.json meta (built_at etc) for clients to decide on updates."""
        try:
            if not GRAPH3D_PATH.exists():
                return jsonify({"meta": {}})
            j = json.loads(GRAPH3D_PATH.read_text())
            return jsonify({"meta": j.get("meta", {})})
        except Exception:
            return jsonify({"meta": {}})

    @server.route('/group/toggle', methods=['POST'])
    def _group_toggle_route():
        try:
            payload = request.get_json() or {}
            gid = str(payload.get('id') or '')
            if not gid:
                return jsonify({'ok': False, 'error': 'missing_id'}), 400
            gs = _load_group_state()
            entry = gs.setdefault(gid, {})
            entry['collapsed'] = not bool(entry.get('collapsed'))
            _save_group_state(gs)
            return jsonify({'ok': True, 'id': gid, 'collapsed': bool(entry.get('collapsed'))})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

    @server.get('/group/list')
    def _group_list():
        try:
            return jsonify(_load_group_state())
        except Exception:
            return jsonify({})

    app.layout = html.Div(
        style={
            "margin": "0",
            "padding": "0",
            "backgroundColor": BG_VANTA,
            "color": TEXT_MAIN,
            "minHeight": "100vh",
            "height": "100vh",
            "width": "100vw",
            "overflow": "hidden",
            "display": "flex",
            "flexDirection": "column",
        },
        children=[
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Span("Severity", className="control-title"),
                                    dcc.Dropdown(
                                        id="severity",
                                        options=[{"label": s.capitalize(), "value": s} for s in ["all", "low", "medium", "high", "critical"]],
                                        value=[],
                                        multi=True,
                                        style={**CONTROL_BASE_STYLE, "minWidth": "190px"},
                                        className="control-select",
                                    ),
                                ],
                                className="control-field",
                            ),
                            html.Div(
                                [
                                    html.Span("Window", className="control-title"),
                                    dcc.Dropdown(
                                        id="time-window",
                                        options=cast(Any, TIME_WINDOW_OPTIONS),
                                        value=DEFAULT_TIME_WINDOW,
                                        clearable=False,
                                        style=CONTROL_BASE_STYLE,
                                        className="control-select",
                                    ),
                                ],
                                className="control-field",
                            ),
                        ],
                        className="cluster-left",
                    ),
                    html.Div("ACE\u00B7T", className="ace-pill"),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Span("Search", className="control-title"),
                                    html.Div(
                                        dcc.Input(
                                            id="search",
                                            type="text",
                                            value="",
                                            placeholder="Search nodes, sources, actors",
                                            style={"width": "100%", "height": CONTROL_HEIGHT},
                                            name="search",
                                        ),
                                        className="search-shell",
                                    ),
                                ],
                                className="control-field",
                                style={"minWidth": "220px"},
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.Button(
                                                "Fit view",
                                                id="fit-view-btn",
                                                n_clicks=0,
                                                className="fit-button",
                                                style={
                                                    "background": "#0ea5e9",
                                                    "color": "#001",
                                                    "border": "1px solid #22d3ee",
                                                    "borderRadius": "10px",
                                                    "height": CONTROL_HEIGHT,
                                                    "padding": "0 12px",
                                                    "fontSize": "12px",
                                                    "fontWeight": 600,
                                                    "cursor": "pointer",
                                                },
                                            ),
                                            html.Button(
                                                "Auto Spin",
                                                id="auto-spin-btn",
                                                n_clicks=0,
                                                className="fit-button",
                                                style={
                                                    "background": "#0ea5e9",
                                                    "color": "#001",
                                                    "border": "1px solid #22d3ee",
                                                    "borderRadius": "10px",
                                                    "height": CONTROL_HEIGHT,
                                                    "padding": "0 12px",
                                                    "fontSize": "12px",
                                                    "fontWeight": 600,
                                                    "cursor": "pointer",
                                                },
                                            ),
                                            html.Button(
                                                "Reset",
                                                id="reset-btn",
                                                n_clicks=0,
                                                className="fit-button",
                                                style={
                                                    "background": "transparent",
                                                    "color": "#00e6d0",
                                                    "border": "1px solid rgba(34,211,238,0.2)",
                                                    "borderRadius": "10px",
                                                    "height": CONTROL_HEIGHT,
                                                    "padding": "0 12px",
                                                    "fontSize": "12px",
                                                    "fontWeight": 600,
                                                    "cursor": "pointer",
                                                },
                                            ),
                                        ],
                                        style={"display": "flex", "gap": "8px", "alignItems": "center"},
                                    )
                                ],
                                className="control-field",
                                style={"minWidth": "260px", "display": "flex", "alignItems": "center"},
                            ),
                        ],
                        className="cluster-right",
                    ),
                ],
                className="control-cluster",
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "padding": "12px 20px",
                },
            ),


            html.Div(
                [],
                className="command-bar",
            ),
            html.Div(
                children=[
                    cyto.Cytoscape(
                        id="cytoscape",
                        elements=elements,
                        layout=_layout_config(layout_name, int(time.time())),
                        stylesheet=base_stylesheet,
                        style={
                            "width": "100%",
                            "height": "100%",
                            "backgroundColor": BG_VANTA,
                            "border": "none",
                        },
                        minZoom=0.05,
                        maxZoom=50,
                        wheelSensitivity=1.0,
                        userZoomingEnabled=True,
                        userPanningEnabled=True,
                        boxSelectionEnabled=True,
                        zoom=1,
                        pan={"x": 0, "y": 0},
                    )
                ],
                style={"flex": 1, "minHeight": "0"},
            ),
            html.Div(
                id="node-panel",
                style=dict(NODE_PANEL_STYLE),
                children=[
                    html.H3("Node Details", style={"marginTop": 0, "textAlign": "center"}),
                    html.Div(
                        id="node-panel-content",
                        style={
                            "whiteSpace": "pre-wrap",
                            "wordBreak": "break-word",
                            "fontSize": "12px",
                            "color": "#bffcff",
                            "fontFamily": "monospace",
                        },
                    ),
                ],
            ),
            dcc.Store(id=ID_STORE_FULL, data={"elements": [], "meta": {}, "node_signatures": {}}),
            dcc.Store(id=ID_STORE_FILTERED, data={"elements": [], "meta": {}, "node_signatures": {}}),
            dcc.Store(id=ID_STORE_SELECTED, data=""),
            dcc.Store(id="focus-depth", data=FOCUS_CONFIG["depth"]),
            dcc.Store(id="surveillance-store", data=_load_surveillance()),
            dcc.Store(id="group-store", data=_load_group_state()),
            dcc.Store(id="render-stats", data={"nodes": 0, "edges": 0}),
            dcc.Store(id="layout", data="cola"),
            dcc.Store(id="user-has-interacted", data=False),

            # Legend (bottom-left) containing sources list so it does not cover top controls
            html.Div(
                [
                    html.Div(
                        "SOURCES",
                        style={
                            "fontSize": "10px",
                            "fontWeight": 800,
                            "color": "rgba(34, 211, 238, 0.95)",
                            "marginBottom": "6px",
                            "letterSpacing": "0.18em",
                            "textTransform": "uppercase",
                            "display": "flex",
                            "justifyContent": "space-between",
                            "alignItems": "center",
                        },
                    ),
                    html.Div(
                        [
                            html.Button("All", id="source-all-btn", n_clicks=0, className="fit-button", style={"height":"26px","padding":"0 8px","fontSize":"11px","background":"transparent","border":"1px solid rgba(34,211,238,0.12)","color":"#bffcff"}),
                            html.Button("None", id="source-none-btn", n_clicks=0, className="fit-button", style={"height":"26px","padding":"0 8px","fontSize":"11px","background":"transparent","border":"1px solid rgba(34,211,238,0.12)","color":"#bffcff","marginLeft":"8px"}),
                        ],
                        style={"display":"flex","justifyContent":"flex-end","marginBottom":"8px"},
                    ),
                    dcc.Store(id="source-filter", data=list(SOURCE_COLORS.keys())),
                    html.Div(id="source-filter-container", style={"display":"flex","flexWrap":"wrap","gap":"6px","justifyContent":"flex-start","maxWidth":"420px","maxHeight":"220px","overflowY":"auto"}),
                ],
                id="legend",
            ),

            html.Div(
                [
                    dcc.Input(id="layout-form-field", name="layout", type="hidden", value=layout_name),
                    dcc.Input(id="severity-form-field", name="severity", type="hidden", value=""),
                    dcc.Input(
                        id="time-window-form-field",
                        name="time-window",
                        type="hidden",
                        value=DEFAULT_TIME_WINDOW,
                    ),
                ],
                style={"display": "none"},
            ),
            dcc.Interval(id="interval", interval=max(args.reload, 0) * 1000, n_intervals=0, disabled=(args.reload <= 0)),
            dcc.Interval(id="status-interval", interval=5_000, n_intervals=0),
            dcc.Interval(id="surveillance-interval", interval=3000, n_intervals=0),
            dcc.Interval(id="incident-interval", interval=5000, n_intervals=0),  # Poll for new incidents every 5s
            # gentle floating nudge - runs until the user interacts
            dcc.Interval(id="float-interval", interval=4000, n_intervals=0),
            dcc.Store(id="auto-spin", data=False),
            dcc.Interval(id="spin-interval", interval=160, n_intervals=0, disabled=True),
            # Interval used to control a short chip animation after All/None is toggled
            dcc.Interval(id="chip-anim-interval", interval=700, n_intervals=0, disabled=True),
            html.Div(
                id="status-bar",
                className="status-bar",
                style={
                    "position": "fixed",
                    "bottom": "0",
                    "left": "0",
                    "right": "0",
                    "height": "38px",
                    "background": "rgba(1, 3, 7, 0.92)",
                    "borderTop": "1px solid rgba(34, 211, 238, 0.3)",
                    "display": "flex",
                    "flexDirection": "column",
                    "justifyContent": "center",
                    "alignItems": "center",
                    "gap": "2px",
                    "fontSize": "11px",
                    "color": "rgba(34, 211, 238, 0.7)",
                    "letterSpacing": "0.12em",
                    "zIndex": 999,
                },
            ),
        ],
    )

    @app.callback(
        Output("cytoscape", "layout"),
        Input("search", "value"),
        Input("severity", "value"),
        Input("time-window", "value"),
        prevent_initial_call=False,
    )
    def _set_layout(_search: str, _sev: List[str], _window: str) -> Dict[str, Any]:
        triggered_props = {t.get("prop_id") for t in (callback_context.triggered or [])}
        # Fit on first paint only; never refit on filter changes
        fit_viewport = not triggered_props
        return _layout_config("grouped", int(time.time()), fit_viewport=fit_viewport)

    @app.callback(
        Output("cytoscape", "zoom", allow_duplicate=True),
        Output("cytoscape", "pan", allow_duplicate=True),
        Input("fit-view-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def _fit_view(_n: int):
        # Manual recenter button keeps user in control of viewport.
        return 1.0, {"x": 0, "y": 0}

    @app.callback(
        Output("auto-spin-btn", "children"),
        Output("auto-spin-btn", "className"),
        Output("spin-interval", "disabled"),
        Output("auto-spin", "data"),
        Input("auto-spin-btn", "n_clicks"),
        State("auto-spin", "data"),
        prevent_initial_call=True,
    )
    def _toggle_auto_spin(n_clicks: int, current: bool):
        """Toggle automatic panning/spin of the cytoscape view."""
        new_state = not bool(current)
        label = "Stop Spin" if new_state else "Auto Spin"
        cls = "fit-button active" if new_state else "fit-button"
        disabled = not new_state
        return label, cls, disabled, new_state

    @app.callback(Output("cytoscape", "pan"), Input("spin-interval", "n_intervals"), State("cytoscape", "pan"), prevent_initial_call=True)
    def _spin_step(n_intervals: int, pan: Dict[str, float] | None):
        try:
            pan = pan or {"x": 0.0, "y": 0.0}
            angle = 0.06  # small rotation step
            x = float(pan.get("x", 0.0))
            y = float(pan.get("y", 0.0))
            new_x = x * math.cos(angle) - y * math.sin(angle)
            new_y = x * math.sin(angle) + y * math.cos(angle)
            return {"x": new_x, "y": new_y}
        except Exception:
            return no_update

    @app.callback(Output("cytoscape", "zoom"), Output("cytoscape", "pan"), Input("reset-btn", "n_clicks"), prevent_initial_call=True)
    def _reset_view(_n: int):
        return 1.0, {"x": 0, "y": 0}
    @app.callback(
        Output("layout-form-field", "value"),
        Output("severity-form-field", "value"),
        Output("time-window-form-field", "value"),
        Input("severity", "value"),
        Input("time-window", "value"),
        prevent_initial_call=False,
    )
    def _mirror_form_fields(severity_values: List[str], time_window_value: str) -> tuple[str, str, str]:
        sev_serialized = ",".join(severity_values or [])
        return "cola", sev_serialized, time_window_value or ""

    @app.callback(
        Output(ID_STORE_FILTERED, "data"),
        Output(ID_STORE_FULL, "data"),
        Input("interval", "n_intervals"),
        State(ID_SEV, "value"),
        State(ID_WIN, "value"),
        State(ID_SEARCH, "value"),
        State("source-filter", "data"),
        prevent_initial_call=False,
    )
    def load_and_filter(n_intervals, severities, time_window, search, sources):
        # Reload the graph snapshot each interval so the UI reflects live changes on disk
        try:
            STATE.load_full()
        except Exception:
            server.logger.exception("Failed to reload graph_data.json")

        # Apply filters using the shared in-process filter so source-filter is respected
        full_elements = STATE.full.elements if STATE.full else []
        _prime_visual_defaults(full_elements)
        filtered_elements = _apply_filters_to_elements(full_elements, severities or [], time_window or "all", search or "", "", FOCUS_CONFIG["depth"], sources or [])

        meta = getattr(STATE.full, "meta", {}) if hasattr(STATE, "full") else {}
        node_signatures = getattr(STATE.full, "node_signatures", {}) if hasattr(STATE, "full") else {}

        # Return filtered and full
        return {"elements": filtered_elements, "meta": meta, "node_signatures": node_signatures}, {"elements": full_elements, "meta": meta, "node_signatures": node_signatures}

    @app.callback(
        Output("source-filter-container", "children"),
        Output("source-filter", "data"),
        Input(ID_STORE_FULL, "data"),
        Input("source-filter", "data"),
        prevent_initial_call=False,
    )
    def populate_sources(full_data, current_value):
        """Populate the source chips (rendered buttons) with counts and preserve selection via the store."""
        elements = (full_data or {}).get("elements", []) if full_data else []
        counts: dict = {}
        for el in elements:
            d = el.get("data", {}) if isinstance(el, dict) else {}
            s = str(d.get("subsource") or d.get("source") or "").strip().lower()
            if s:
                counts[s] = counts.get(s, 0) + 1
                _source_color(s)

        # Ensure known sources exist in the options even with zero counts
        for s in SOURCE_COLORS.keys():
            counts.setdefault(s, 0)

        # Sort by descending count (most relevant first)
        sorted_sources = [s for s, c in sorted(counts.items(), key=lambda x: -x[1])]

        # Determine selected values, preserving previous selection if possible
        if current_value:
            keep = [v for v in (current_value or []) if v in sorted_sources]
            selected = keep if keep else sorted_sources
        else:
            selected = sorted_sources

        # Build chip buttons with a small color swatch and count badge
        children = []
        for s in sorted_sources:
            c = counts.get(s, 0)
            active = s in selected
            btn_style = {
                "padding": "6px 10px",
                "borderRadius": "999px",
                "background": "rgba(255,255,255,0.02)",
                "color": "#bffcff",
                "border": "1px solid rgba(34,211,238,0.06)",
                "fontSize": "11px",
                "fontWeight": 700,
                "cursor": "pointer",
                "display": "inline-flex",
                "alignItems": "center",
                "gap": "8px",
            }
            if active:
                btn_style.update({"transform": "translateY(-2px)", "boxShadow": "0 6px 22px rgba(2,18,32,0.6)"})

            swatch = html.Span(className="swatch", style={"width": "10px", "height": "10px", "borderRadius": "2px", "background": _source_color(s)})
            label_text = f"{s} ({c})" if c else s
            btn = html.Button([swatch, html.Span(label_text)], id={"type": "source-btn", "index": s}, n_clicks=0, className=("source-chip active" if active else "source-chip"), style=btn_style)
            children.append(btn)

        return children, selected

    @app.callback(
        Output("source-filter", "data"),
        Output("legend", "className"),
        Output("chip-anim-interval", "disabled"),
        Input("source-all-btn", "n_clicks"),
        Input("source-none-btn", "n_clicks"),
        State("source-filter", "data"),
        prevent_initial_call=True,
    )
    def _source_select_all_none(all_n, none_n, current):
        triggered = (callback_context.triggered or [])
        if not triggered:
            return no_update, no_update, no_update
        prop = (triggered[0].get("prop_id") or "")
        if prop.startswith("source-all-btn"):
            return list(SOURCE_COLORS.keys()), "legend pulse", False
        if prop.startswith("source-none-btn"):
            return [], "legend pulse", False
        return no_update, no_update, no_update

    @app.callback(
        Output("legend", "className"),
        Output("chip-anim-interval", "disabled"),
        Input("chip-anim-interval", "n_intervals"),
        State("legend", "className"),
        prevent_initial_call=True,
    )
    def _chip_anim_clear(n_intervals, current_class):
        # Clear the pulse class after the interval fires once
        return "legend", True
    @app.callback(
        Output(ID_CY, "elements"),
        Input(ID_STORE_FILTERED, "data"),
        prevent_initial_call=False,
    )
    def update_elements(filtered_data):
        return filtered_data["elements"]

    @app.callback(
        Output("source-filter", "data"),
        Input({'type': 'source-btn', 'index': ALL}, 'n_clicks'),
        State('source-filter', 'data'),
        prevent_initial_call=True,
    )
    def _toggle_source(btn_clicks, current_selected):
        triggered = (callback_context.triggered or [])
        if not triggered:
            return no_update
        prop = triggered[0].get('prop_id', '')
        # prop is like '{"type":"source-btn","index":"reddit"}.n_clicks'
        try:
            idx = json.loads(prop.split('.')[0]).get('index')
        except Exception:
            return no_update
        current = list(current_selected or [])
        if idx in current:
            current.remove(idx)
        else:
            current.append(idx)
        return current

    app.clientside_callback(
        ClientsideFunction(namespace="clientside", function_name="cy_fit"),
        Output(ID_CY, "zoom", allow_duplicate=True),
        Output(ID_CY, "pan", allow_duplicate=True),
        Input(ID_FIT_BTN, "n_clicks"),
        prevent_initial_call=True,
    )

    @app.callback(
        Output("filtered-graph", "data"),
        Input("full-graph", "data"),
        Input("severity", "value"),
        Input("time-window", "value"),
        Input("search", "value"),
        Input("source-filter", "data"),
        Input("selected-node", "data"),
        Input("focus-depth", "data"),
        prevent_initial_call=False,
    )
    def filter_graph(full_data, severities, time_window, search, sources, selected_id, focus_depth):
        if not full_data or "elements" not in full_data:
            return {"elements": [], "meta": {}, "node_signatures": {}}
        elements = full_data["elements"]
        # Apply filters similar to the main function, now allowing source filtering
        filtered = _apply_filters_to_elements(elements, severities, time_window, search, selected_id, focus_depth, sources or [])
        print(f"Filtered elements: {len(filtered)}")
        return {"elements": filtered, "meta": full_data["meta"], "node_signatures": full_data["node_signatures"]}


    @app.callback(
        Output("cytoscape", "elements"),
        Input("filtered-graph", "data"),
        prevent_initial_call=False,
    )
    def update_cytoscape_elements(filtered_data):
        if not filtered_data or "elements" not in filtered_data:
            print("ERROR: No filtered data")
            return []
        elements = filtered_data["elements"]
        print(f"Cytoscape elements: {len(elements)}")
        if len(elements) == 0:
            print("WARNING: Filtered to 0 elements")
        return elements


    @app.callback(
        Output("cytoscape", "layout"),
        Input("float-interval", "n_intervals"),
        State("user-has-interacted", "data"),
        prevent_initial_call=True,
    )
    def _floating_nudge(n: int, user_has_interacted: bool):
        """Run a very small layout nudge to create a gentle floating/elastic effect.
        This runs until the user interacts with the graph (zooms, drags, clicks).
        """
        if bool(user_has_interacted):
            # Stop nudging once the user interacts
            return no_update
        # Use a short animated layout to nudge positions but do not fit or randomize
        cfg = _layout_config("grouped", int(time.time()), fit_viewport=False)
        cfg.update({
            "animate": True,
            "randomize": False,
            "numIter": 8,
            "coolingFactor": 0.9,
        })
        return cfg


    @app.callback(
        Output("node-panel", "style"),
        Output("node-panel-content", "children"),
        Output("cytoscape", "stylesheet"),
        Output("selected-node", "data"),
        Output("focus-depth", "data"),
        Input("cytoscape", "tapNodeData"),
        Input("cytoscape", "selectedNodeData"),
        Input("cytoscape", "tapEdgeData"),
        Input("cytoscape", "tapNode"),
        Input("cytoscape", "zoom"),
        State("cytoscape", "selectedEdgeData"),
        State("node-panel", "style"),
        State("graph-store", "data"),
        State("selected-node", "data"),
        State("focus-depth", "data"),
        State("surveillance-store", "data"),
        State("group-store", "data"),
    )
    def show_node_panel(
        node_data: Dict[str, Any] | None,
        selected_nodes: List[Dict[str, Any]] | None,
        tap_edge: Dict[str, Any] | None,
        tap_node_event: Any,
        zoom: float,
        selected_edges: List[Dict[str, Any]] | None,
        style: Dict[str, Any],
        _store: Dict[str, Any] | None,
        last_selected: str,
        focus_depth: int,
        surv_store: Dict[str, Any] | None = None,
        group_store: Dict[str, Any] | None = None,
    ) -> tuple[Dict[str, Any], Any, List[Dict[str, Any]], str, int]:
        print(f"Panel triggered: node_data={node_data}, selected_nodes={selected_nodes}, tap_edge={tap_edge}, zoom={zoom}")
        layout_value = "cola"
        # Ensure we have readable stores
        surv_store = surv_store or {}
        group_store = group_store or {}
        state_style = style or {}
        style = copy.deepcopy(NODE_PANEL_STYLE)
        style.update(state_style)
        lod_stage = _derive_lod_stage(zoom)
        stylesheet = build_stylesheet(lod_stage, layout_value)
        current = str(last_selected or "")
        closed_style = dict(style)
        closed_style["right"] = f"-{DETAILS_WIDTH}px"

        def _lookup_node_data(node_id: str) -> Dict[str, Any] | None:
            store = _store or {}
            for el in store.get("elements") or []:
                d = el.get("data") or {}
                if str(d.get("id") or "") == str(node_id):
                    return d
            return None

        triggered = callback_context.triggered or []
        triggered_props = {t.get("prop_id") for t in triggered}

        try:
            server.logger.info(
                "tap_event",
                extra={
                    "tap_node": node_data,
                    "tap_edge": tap_edge,
                    "selected_nodes": selected_nodes,
                    "selected_edges": selected_edges,
                    "triggered": list(triggered_props),
                },
            )
        except Exception:
            pass

        # Fall back to selection arrays if tap events are noisy
        if not node_data and selected_nodes:
            node_data = (selected_nodes or [None])[0]
        if not tap_edge and selected_edges:
            tap_edge = (selected_edges or [None])[0]

        # Sometimes only the id makes it through; hydrate from graph-store if so
        if isinstance(node_data, dict) and node_data.get("id") and not node_data.get("label"):
            hydrated = _lookup_node_data(str(node_data["id"]))
            if hydrated:
                node_data = hydrated

        # Zoom or layout-only updates should keep the panel/content intact while refreshing styles
        if ("cytoscape.zoom" in triggered_props or "layout.value" in triggered_props) and not (node_data or tap_edge or tap_node_event):
            return style, no_update, stylesheet, current, focus_depth

        blank_tap = (
            ("cytoscape.selectedNodeData" in triggered_props and not (selected_nodes or []))
            or ("cytoscape.tapNodeData" in triggered_props and not node_data)
        )
        # Clicking blank space or tapping an edge closes panel
        if tap_edge or blank_tap:
            closed_style["display"] = "none"
            return closed_style, [], stylesheet, "", FOCUS_CONFIG["depth"]
        if not node_data:
            closed_style["display"] = "none"
            return closed_style, [], stylesheet, current, focus_depth

        node_id = str(node_data.get("id") or "")

        # Clicking the same node toggles panel closed
        if style.get("right") == "0px" and node_id and node_id == current:
            closed_style["display"] = "none"
            return closed_style, [], stylesheet, "", FOCUS_CONFIG["depth"]

        # Open panel for new selection
        default_depth = FOCUS_CONFIG["depth"]
        new_focus_depth = (default_depth + 1) if _event_shifted(tap_node_event) else default_depth
        style["right"] = "0px"
        style["display"] = "block"
        ts = node_data.get("timestamp")
        ts_fmt = format_ts(ts) if ts else "N/A"

        links: List[Any] = []
        if node_data.get("source") == "reddit":
            nid = node_data.get("id", "")
            if nid.startswith("reddit_user:"):
                username = nid.split("reddit_user:", 1)[1]
                links.append(
                    html.A(
                        f"View Reddit Profile ({username})",
                        href=f"https://www.reddit.com/user/{username}",
                        target="_blank",
                        className="detail-link",
                        style={"color": CYAN},
                    )
                )
            if node_data.get("kind") == "alert" and node_data.get("reddit_url"):
                links.append(
                    html.A(
                        "View Reddit Post",
                        href=node_data["reddit_url"],
                        target="_blank",
                        className="detail-link",
                        style={"color": CYAN},
                    )
                )
            if node_data.get("post_url"):
                links.append(
                    html.A(
                        "View Reddit Post",
                        href=node_data["post_url"],
                        target="_blank",
                        className="detail-link",
                        style={"color": CYAN},
                    )
                )

        # If the selected node is a relation hub, add expand/collapse actions
        if node_data.get("kind") == "relation_hub":
            gid = str(node_data.get("id") or "")
            gs = (surv_store or {}).get(gid) or {}
            collapsed = bool(gs.get("collapsed"))
            act_label = "Expand Group" if collapsed else "Collapse Group"
            links.append(html.Button(act_label, id="toggle-group", n_clicks=0, style={"background": "#00d0ff", "border": "none", "padding": "6px 10px", "borderRadius": "6px", "color": "#001"}))

        last_activity = node_data.get("last_activity") or node_data.get("activity_last") or None
        last_activity_fmt = format_ts(last_activity) if last_activity else "N/A"

        is_surv = bool(node_data.get("surveillance"))
        surv_btn_label = "Remove Surveillance" if is_surv else "Watch / Flag"

        content_children: List[Any] = [
            html.Div(f"Label: {node_data.get('label', '')}"),
            html.Div(f"Kind: {node_data.get('kind', '')}"),
            html.Div(f"Severity: {node_data.get('severity', '')}"),
            html.Div(
                f"Source: {node_data.get('source', '')}"
                + (f" / r/{node_data.get('subsource')}" if node_data.get("subsource") else "")
            ),
            html.Div(f"Timestamp: {ts_fmt}"),
            html.Div(f"Last Activity: {last_activity_fmt}"),
            html.Div(html.Button(surv_btn_label, id="toggle-surveillance", n_clicks=0, style={"background": "#ffb347", "border": "none", "padding": "6px 10px", "borderRadius": "6px", "color": "#001"})),
            html.Hr(),
            html.Div("Links:"),
            html.Div(links),
        ]

        full_payload = _pretty_json(node_data)
        content_children.extend(
            [
                html.Hr(),
                html.Div("Full Node Payload", style={"fontWeight": 600, "marginTop": "6px"}),
                html.Pre(
                    full_payload,
                    style={
                        "background": "#04111a",
                        "padding": "10px",
                        "borderRadius": "6px",
                        "fontSize": "11px",
                        "color": "#bffcff",
                        "border": "1px solid #0d2a3a",
                        "maxHeight": "60vh",
                        "overflowY": "auto",
                    },
                ),
            ]
        )

        return style, content_children, stylesheet, node_id, new_focus_depth

    @app.callback(
        Output("group-store", "data"),
        Output("graph-store", "data", allow_duplicate=True),
        Input("toggle-group", "n_clicks"),
        State("selected-node", "data"),
        State("group-store", "data"),
        State("graph-store", "data"),
        prevent_initial_call=True,
    )
    def _toggle_group(n_clicks: int, node_id: str, group_store: Dict[str, Any], graph_store: Dict[str, Any]):
        if not node_id:
            return group_store or {}, graph_store or {}
        group_store = group_store or {}
        graph_store = graph_store or {}
        entry = group_store.setdefault(node_id, {})
        entry["collapsed"] = not bool(entry.get("collapsed"))
        _save_group_state(group_store)

        # apply to graph elements immediately: hide member nodes when collapsed
        els = graph_store.get("elements") or []
        # nodes that are members of this hub: find edges where source==node_id or target==node_id
        member_ids = set()
        for el in els:
            d = el.get("data") or {}
            if d.get("source") == node_id:
                member_ids.add(str(d.get("target")))
            if d.get("target") == node_id:
                member_ids.add(str(d.get("source")))
        if entry.get("collapsed"):
            for el in els:
                d = el.get("data") or {}
                nid = str(d.get("id") or "")
                # do not hide preserved nodes (top nodes or watched)
                if str(d.get("id")) in member_ids and not d.get("kind") == "relation_hub" and not d.get("live_preserve"):
                    # mark hidden
                    el["classes"] = (el.get("classes") or "") + " hidden"
        else:
            # when expanding, only unhide members that are not members of any other collapsed hub
            collapsed_others = {k for k, v in (group_store or {}).items() if v.get("collapsed") and k != node_id}
            other_members = set()
            if collapsed_others:
                for el in els:
                    d = el.get("data") or {}
                    if "source" in d and "target" in d and d.get("relation") == "relation_cluster":
                        s, t = d.get("source"), d.get("target")
                        if s in collapsed_others and t:
                            other_members.add(str(t))
                        if t in collapsed_others and s:
                            other_members.add(str(s))
            for el in els:
                d = el.get("data") or {}
                nid = str(d.get("id") or "")
                if nid in member_ids and not d.get("kind") == "relation_hub":
                    if nid in other_members:
                        continue
                    classes = set(filter(None, (el.get("classes") or "").split()))
                    classes.discard("hidden")
                    el["classes"] = " ".join(sorted(classes))

        graph_store["elements"] = els
        return group_store, graph_store

    @app.callback(
        Output("surveillance-store", "data", allow_duplicate=True),
        Output("graph-store", "data", allow_duplicate=True),
        Input("toggle-surveillance", "n_clicks"),
        State("selected-node", "data"),
        State("surveillance-store", "data"),
        State("graph-store", "data"),
        prevent_initial_call=True,
    )
    def _toggle_surveillance(n_clicks: int, node_id: str, surv_store: Dict[str, Any], graph_store: Dict[str, Any]):
        if not node_id:
            return surv_store or {}, graph_store or {}
        surv_store = surv_store or {}
        graph_store = graph_store or {}
        now = int(time.time())
        entry = surv_store.setdefault(node_id, {})
        enabled = not bool(entry.get("enabled"))
        entry["enabled"] = enabled
        if enabled:
            entry.setdefault("last_activity", now)
            entry.setdefault("activity_count", 0)
            entry["activity_level"] = _compute_activity_level(entry, now)
        else:
            # keep stats but disable
            entry["activity_level"] = entry.get("activity_level") or "low"
        _save_surveillance(surv_store)

        # Update graph-store elements so UI reflects change immediately
        els = (graph_store.get("elements") or [])

        # Update node flags and color pulsing initialization
        for el in els:
            d = el.get("data") or {}
            if str(d.get("id") or "") == str(node_id):
                d["surveillance"] = bool(entry.get("enabled"))
                if entry.get("last_activity"):
                    d["last_activity"] = int(entry.get("last_activity"))
                d["activity_count"] = int(entry.get("activity_count", 0))
                d["activity_level"] = entry.get("activity_level") or "low"
                # store original color so we can pulse then restore
                if d.get("surveillance"):
                    d.setdefault("_orig_color", d.get("color") or severity_to_color(d.get("severity" or "medium")))
                else:
                    # on disable, restore base color
                    d["color"] = severity_to_color(d.get("severity") or "medium")

        # When enabling surveillance, add lightweight 'surveillance' edges connecting to nodes with same source (up to 6)
        if entry.get("enabled"):
            try:
                # collect candidate node ids that share the same source
                node_source = None
                for el in els:
                    d = el.get("data") or {}
                    if str(d.get("id") or "") == str(node_id):
                        node_source = str(d.get("source") or d.get("subsource") or "")
                        break
                candidates = []
                if node_source:
                    for el in els:
                        d = el.get("data") or {}
                        nid = str(d.get("id") or "")
                        if nid == node_id:
                            continue
                        src = str(d.get("source") or d.get("subsource") or "")
                        if src and src == node_source:
                            candidates.append(nid)
                # fallback: nearest by same severity
                if not candidates:
                    sev = None
                    for el in els:
                        d = el.get("data") or {}
                        if str(d.get("id") or "") == str(node_id):
                            sev = d.get("severity")
                            break
                    if sev:
                        for el in els:
                            d = el.get("data") or {}
                            nid = str(d.get("id") or "")
                            if nid == node_id:
                                continue
                            if d.get("severity") == sev:
                                candidates.append(nid)
                # limit candidates and add edges if not present
                seen_ids = {e.get("data", {}).get("id") for e in els}
                added = 0
                for cand in candidates:
                    if added >= 6:
                        break
                    eid = f"surv::{node_id}::{cand}"
                    if eid in seen_ids:
                        continue
                    edge = {"data": {"id": eid, "source": node_id, "target": cand, "relation": "surveillance_link", "weight": 1.5}, "classes": "surveillance-link"}
                    els.append(edge)
                    added += 1
            except Exception:
                pass
        else:
            # Remove surveillance_link edges for this node when disabling
            new_els = []
            for el in els:
                d = el.get("data") or {}
                if str(d.get("id") or "").startswith("surv::") and (str(d.get("source") or "") == str(node_id) or str(d.get("target") or "") == str(node_id)):
                    continue
                new_els.append(el)
            els = new_els

        graph_store["elements"] = els
        # also update the watched checklist UI by returning the updated surv_store
        return surv_store, graph_store

    @app.callback(Output("graph-store", "data", allow_duplicate=True), Input("surveillance-interval", "n_intervals"), State("surveillance-store", "data"), State("graph-store", "data"), prevent_initial_call=True)
    def _surveillance_pulse(n_intervals: int, surv_store: Dict[str, Any] | None, graph_store: Dict[str, Any] | None):
        """Pulse monitored nodes' colors over time to make them visually distinct."""
        if not graph_store or "elements" not in graph_store:
            return no_update
        surv_store = surv_store or {}
        els = graph_store.get("elements") or []
        try:
            for el in els:
                d = el.get("data") or {}
                nid = str(d.get("id") or "")
                entry = surv_store.get(nid) or {}
                if entry.get("enabled"):
                    # Pulse factor using sine wave based on interval counter
                    t = (math.sin((n_intervals or 0) * 0.6) + 1.0) / 2.0  # ranges 0..1
                    base = severity_to_color(str(d.get("severity") or "medium"))
                    # mix toward white to create a pulsing highlight
                    pulse_color = _mix_hex(base, "#ffffff", 0.35 + 0.5 * t)
                    d["color"] = pulse_color
                else:
                    # restore original color if present, otherwise base
                    if d.get("_orig_color"):
                        d["color"] = d.pop("_orig_color")
                    else:
                        d["color"] = severity_to_color(str(d.get("severity") or "medium"))
            graph_store["elements"] = els
            return graph_store
        except Exception:
            return no_update

    @app.callback(Output("status-bar", "children"), Input("status-interval", "n_intervals"), State("render-stats", "data"))
    def update_status(_n: int, render_stats: Dict[str, Any]):
        node_count, edge_count, last_update = get_graph_status()
        r_nodes = (render_stats or {}).get("nodes", "?")
        r_edges = (render_stats or {}).get("edges", "?")
        return [
            html.Div(f"Nodes: {node_count}   •   Edges: {edge_count}   •   Rendered: {r_nodes}/{r_edges}"),
            html.Div(f"Last Update: {last_update}"),
        ]

    print(f"[cyto_gui] starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
