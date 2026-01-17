from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


WINDOW_TO_SECONDS = {
    "all": None,
    "1d": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
}


def _now() -> float:
    return time.time()


def _parse_ts(v: Any) -> Optional[float]:
    """
    Accepts epoch seconds, epoch ms, or ISO-like strings if already pre-parsed upstream.
    We keep it strict: if not parseable, return None so node is treated as "unknown time".
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        # epoch ms vs seconds
        if v > 10_000_000_000:  # ms
            return float(v) / 1000.0
        return float(v)
    # If upstream stored ISO string, best is to pre-normalize in ingestion.
    # Here we avoid heavy parsing to keep UI fast and deterministic.
    return None


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    # Index helpers
    node_ids: Set[str]
    # Edge sanity stats
    orphan_edges: int
    kept_edges: int

    @property
    def elements(self):
        return self.nodes + self.edges

    @property
    def meta(self):
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "orphan_edges": self.orphan_edges,
            "kept_edges": self.kept_edges,
        }

    @property
    def node_signatures(self):
        return {}

    def to_dict(self):
        return {
            "elements": self.elements,
            "meta": self.meta,
            "node_signatures": self.node_signatures
        }


class GraphState:
    """
    Loads graph_data.json once and serves filtered snapshots.
    Avoids Dash callbacks ever clearing cytoscape elements by accident.
    """
    def __init__(self, graph_path: Path):
        self.graph_path = Path(graph_path)
        self._full: Optional[GraphSnapshot] = None
        self._last_mtime: float = 0.0
        self.loaded = False

    def load_full(self, force: bool = False) -> GraphSnapshot:
        p = self.graph_path
        mtime = p.stat().st_mtime if p.exists() else 0.0
        if self._full is not None and not force and mtime <= self._last_mtime:
            return self._full

        # If the graph file does not exist, return an empty snapshot instead
        if not p.exists():
            snap = GraphSnapshot(nodes=[], edges=[], node_ids=set(), orphan_edges=0, kept_edges=0)
            self._full = snap
            self._last_mtime = 0.0
            self.loaded = True
            return snap

        try:
            raw = p.read_text(encoding="utf-8")
            data = json.loads(raw) if raw else []
        except Exception:
            # Corrupted or unreadable file - fall back to empty snapshot
            snap = GraphSnapshot(nodes=[], edges=[], node_ids=set(), orphan_edges=0, kept_edges=0)
            self._full = snap
            self._last_mtime = mtime
            self.loaded = True
            return snap

        if isinstance(data, dict):
            elements = data.get("elements") or data.get("data") or data
        else:
            elements = data

        # Support either:
        # - {"elements":[{"data":...,"group":"nodes/edges"}...]}
        # - {"nodes":[...], "edges":[...]}
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        if isinstance(elements, dict) and "nodes" in elements and "edges" in elements:
            nodes = elements["nodes"]
            edges = elements["edges"]
        elif isinstance(elements, list):
            for el in elements:
                if not isinstance(el, dict):
                    continue
                d = el.get("data", {})
                if "source" in d and "target" in d:
                    edges.append(el)
                else:
                    nodes.append(el)
        else:
            raise ValueError("Unsupported graph_data.json structure")

        node_ids: Set[str] = set()
        for n in nodes:
            d = n.get("data", n)
            nid = d.get("id")
            if nid is None:
                continue
            node_ids.add(str(nid))

        kept: List[Dict[str, Any]] = []
        orphan = 0
        for e in edges:
            d = e.get("data", e)
            s = d.get("source")
            t = d.get("target")
            if s is None or t is None:
                orphan += 1
                continue
            if str(s) not in node_ids or str(t) not in node_ids:
                orphan += 1
                continue
            kept.append(e)

        snap = GraphSnapshot(
            nodes=nodes,
            edges=kept,
            node_ids=node_ids,
            orphan_edges=orphan,
            kept_edges=len(kept),
        )
        self._full = snap
        self._last_mtime = mtime
        self.loaded = True
        return snap

    @property
    def full(self) -> GraphSnapshot:
        return self.load_full()

    def filter(
        self,
        severities: List[str] = None,
        window: str = "all",
        q: str = "",
    ) -> GraphSnapshot:
        full = self.load_full()
        secs = WINDOW_TO_SECONDS.get(window, None)
        cutoff = _now() - secs if secs else None
        qn = (q or "").strip().lower()

        def sev_ok(n: Dict[str, Any]) -> bool:
            if not severities or "all" in [s.lower() for s in severities]:
                return True
            d = n.get("data", n)
            v = d.get("severity") or d.get("sev") or d.get("level")
            if v is None:
                return False
            # Normalize: allow numeric or string labels
            sv = str(v).strip().lower()
            return sv in [s.lower() for s in severities]

        def time_ok(n: Dict[str, Any]) -> bool:
            if cutoff is None:
                return True
            d = n.get("data", n)
            ts = _parse_ts(d.get("timestamp") or d.get("ts") or d.get("time"))
            if ts is None:
                # If unknown time and user picked a window, keep it out of the filtered view
                return False
            return ts >= cutoff

        def q_ok(n: Dict[str, Any]) -> bool:
            if not qn:
                return True
            d = n.get("data", n)
            hay = " ".join([
                str(d.get("id", "")),
                str(d.get("label", "")),
                str(d.get("name", "")),
                str(d.get("source", "")),
                str(d.get("actor", "")),
                str(d.get("ioc", "")),
                str(d.get("value", "")),
            ]).lower()
            return qn in hay

        kept_nodes: List[Dict[str, Any]] = []
        kept_ids: Set[str] = set()

        for n in full.nodes:
            d = n.get("data", n)
            nid = d.get("id")
            if nid is None:
                continue
            if not sev_ok(n):
                continue
            if not time_ok(n):
                continue
            if not q_ok(n):
                continue
            kept_nodes.append(n)
            kept_ids.add(str(nid))

        kept_edges: List[Dict[str, Any]] = []
        orphan = 0
        for e in full.edges:
            d = e.get("data", e)
            s = str(d.get("source"))
            t = str(d.get("target"))
            if s in kept_ids and t in kept_ids:
                kept_edges.append(e)

        return GraphSnapshot(
            nodes=kept_nodes,
            edges=kept_edges,
            node_ids=kept_ids,
            orphan_edges=orphan,
            kept_edges=len(kept_edges),
        )

    @staticmethod
    def to_cytoscape_elements(snap: GraphSnapshot) -> List[Dict[str, Any]]:
        # Pass-through, but enforce "group" so dash_cytoscape behaves consistently.
        out: List[Dict[str, Any]] = []
        for n in snap.nodes:
            if "group" not in n:
                out.append({"group": "nodes", "data": n.get("data", n)})
            else:
                out.append(n)
        for e in snap.edges:
            if "group" not in e:
                out.append({"group": "edges", "data": e.get("data", e)})
            else:
                out.append(e)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "elements": self.to_cytoscape_elements(self),
            "meta": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "orphan_edges": self.orphan_edges,
                "kept_edges": self.kept_edges,
            }
        }