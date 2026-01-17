from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from adapters.emit_graph import emit_graph


def _ts(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).timestamp()
    except Exception:
        return 0.0


def _severity_from_confidence(conf: float) -> str:
    if conf >= 0.85:
        return "high"
    if conf >= 0.65:
        return "medium"
    return "low"


def _source_from_object(obj: Dict[str, Any]) -> str:
    tags = obj.get("tags") or []
    labels = obj.get("labels") or []
    for item in tags + labels:
        if item and isinstance(item, str):
            return item
    return "intel"


def build_graph_elements(objects: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "edge":
            edges.append(
                {
                    "id": obj.get("id"),
                    "source": obj.get("from"),
                    "target": obj.get("to"),
                    "relation": obj.get("edge_type"),
                    "weight": obj.get("weight", 1.0),
                    "band": obj.get("band"),
                    "confidence": obj.get("confidence"),
                    "object_type": "edge",
                }
            )
            continue

        if obj_type in {"entity", "cluster"}:
            label = obj.get("name") or obj.get("cluster_type") or obj_type
            conf = float(obj.get("confidence", 0.5) or 0.5)
            source = _source_from_object(obj)
            nodes.append(
                {
                    "id": obj.get("id"),
                    "label": label,
                    "kind": "entity" if obj_type == "entity" else "group",
                    "severity": _severity_from_confidence(conf),
                    "source": source,
                    "subsource": source,
                    "timestamp": _ts(obj.get("created_at")),
                    "band": obj.get("band"),
                    "confidence": conf,
                    "object_type": obj_type,
                }
            )
    return nodes, edges


def write_graph_data(objects: Iterable[Dict[str, Any]]) -> None:
    nodes, edges = build_graph_elements(objects)
    emit_graph(nodes, edges)
