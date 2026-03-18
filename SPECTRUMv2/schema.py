from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Set, Tuple

ALLOWED_KINDS = {"alert", "ioc", "entity", "source", "source_hub", "relation_hub", "group"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED_NODE_FIELDS = {"id", "label", "kind", "severity", "source", "timestamp"}
REQUIRED_EDGE_FIELDS = {"id", "source", "target"}


def _require_fields(data: dict, required: Set[str], label: str) -> None:
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"{label} missing fields: {sorted(missing)}")


def validate_node(node: dict) -> None:
    if not isinstance(node, dict) or "data" not in node:
        raise ValueError("Node element must be a dict with a 'data' key")

    data = node["data"]
    _require_fields(data, REQUIRED_NODE_FIELDS, "Node")

    if data["kind"] not in ALLOWED_KINDS:
        raise ValueError(f"Invalid node.kind: {data['kind']}")
    if data["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid node.severity: {data['severity']}")

    size = data.get("size")
    if size is not None and not (1 <= int(size) <= 100):
        raise ValueError("node.size must be between 1 and 100 when provided")

    confidence = data.get("confidence")
    if confidence is not None and not (0.0 <= float(confidence) <= 1.0):
        raise ValueError("node.confidence must be between 0.0 and 1.0 when provided")


def validate_edge(edge: dict) -> None:
    if not isinstance(edge, dict) or "data" not in edge:
        raise ValueError("Edge element must be a dict with a 'data' key")

    data = edge["data"]
    _require_fields(data, REQUIRED_EDGE_FIELDS, "Edge")


def validate_elements(elements: Iterable[dict]) -> None:
    node_ids: Set[str] = set()
    edge_keys: Set[Tuple[str, str, str]] = set()

    nodes: List[dict] = []
    edges: List[dict] = []
    for el in elements:
        data = el.get("data") or {}
        if "source" in data and "target" in data:
            edges.append(el)
        else:
            nodes.append(el)

    for node in nodes:
        validate_node(node)
        node_id = node["data"]["id"]
        if node_id in node_ids:
            raise ValueError(f"Duplicate node id: {node_id}")
        node_ids.add(node_id)

    for edge in edges:
        validate_edge(edge)
        data = edge["data"]
        key = (data.get("source"), data.get("target"), data.get("relation"))
        if key in edge_keys:
            raise ValueError(f"Duplicate edge (source,target,relation): {key}")
        edge_keys.add(key)
        if data.get("source") not in node_ids or data.get("target") not in node_ids:
            raise ValueError(f"Edge references unknown node(s): {data.get('source')} -> {data.get('target')}")


# Helpers for deterministic IDs (aligns with schema rules)
def hash_alert(source: str, external_id: str) -> str:
    return hashlib.sha256(f"{source}:{external_id}".encode("utf-8")).hexdigest()


def hash_url(normalized_url: str, content_hash: str) -> str:
    return hashlib.sha256(f"url:{normalized_url}:{content_hash}".encode("utf-8")).hexdigest()


def hash_ioc(ioc_type: str, canonical_value: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{canonical_value}".encode("utf-8")).hexdigest()


def hash_reddit(post_id: str) -> str:
    return hashlib.sha256(f"reddit:{post_id}".encode("utf-8")).hexdigest()


def hash_url_source(normalized_url: str) -> str:
    return hashlib.sha256(f"urlsrc:{normalized_url}".encode("utf-8")).hexdigest()


# Adapters expect dict-based helpers
def hash_alert_id(alert: Dict[str, Any]) -> str:
    source = str(alert.get("source") or "unknown").strip()
    external_id = (
        alert.get("id")
        or alert.get("external_id")
        or alert.get("uuid")
        or alert.get("guid")
        or alert.get("alert_id")
    )
    if external_id is None or str(external_id).strip() == "":
        raise ValueError("Alert requires an external id for deterministic hashing")
    return hash_alert(source, str(external_id).strip())


def hash_ioc_id(ioc: Dict[str, Any]) -> str:
    ioc_type = str(ioc.get("type") or ioc.get("ioc_type") or "ioc").strip().lower()
    canonical_value = ioc.get("canonical") or ioc.get("value") or ioc.get("indicator") or ioc.get("ioc")
    if canonical_value is None or str(canonical_value).strip() == "":
        raise ValueError("IOC requires a canonical value for deterministic hashing")
    value = str(canonical_value).strip().lower()
    return hash_ioc(ioc_type, value)


def hash_reddit_id(post: Dict[str, Any]) -> str:
    post_id = post.get("id") or post.get("post_id") or post.get("external_id")
    if post_id is None or str(post_id).strip() == "":
        raise ValueError("Reddit post requires an id")
    return hash_reddit(str(post_id).strip())


def hash_url_id(url: str, content_hash: str) -> str:
    normalized = str(url).strip()
    if not normalized:
        raise ValueError("URL cannot be empty for hashing")
    return hash_url(normalized, content_hash)


def hash_url_source_id(normalized_url: str) -> str:
    normalized = str(normalized_url).strip()
    if not normalized:
        raise ValueError("URL source cannot be empty for hashing")
    return hash_url_source(normalized)
