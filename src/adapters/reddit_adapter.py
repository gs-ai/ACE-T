from __future__ import annotations

import time
from typing import Dict, Iterable, List, Tuple

from schema import hash_ioc_id, hash_reddit_id, validate_edge, validate_node

DEFAULT_SEVERITY = "medium"
try:
    from runners.subreddit_targets import SUBREDDIT_COLORS
except Exception:
    SUBREDDIT_COLORS = {}
DEFAULT_REDDIT_COLOR = "#00bcd4"
SUBREDDIT_CONFIDENCE = {
    "cybersecurity": 0.72,
    "darknet": 0.55,
    "deepweb": 0.42,
    "onions": 0.35,
}


def _timestamp(post: Dict) -> int:
    ts = post.get("timestamp") or post.get("created_utc") or post.get("created")
    if ts is None:
        ts = time.time()
    return int(ts)


def reddit_post_to_node(post: Dict) -> Dict:
    """
    Map a Reddit post/comment to a schema-compliant alert node.
    Expected fields in post:
      - id (str): Reddit thing ID
      - title or body/summary for label
      - source: "reddit" (fallback provided)
      - timestamp: unix seconds (int)
      - severity (optional)
      - score / weight (optional) -> size
      - confidence (optional)
    """
    label = post.get("title") or post.get("summary") or post.get("body") or "reddit post"
    subsource = str(post.get("subsource") or "").strip().lower()
    color = SUBREDDIT_COLORS.get(subsource.lower(), DEFAULT_REDDIT_COLOR)
    default_conf = SUBREDDIT_CONFIDENCE.get(subsource.lower(), 0.5)
    ts = _timestamp(post)
    node = {
        "data": {
            "id": hash_reddit_id(post),
            "label": label,
            "kind": "alert",
            "severity": (post.get("severity") or DEFAULT_SEVERITY).lower(),
            "size": min(max(int(post.get("score", 10)), 1), 100),
            "confidence": float(post.get("confidence", default_conf)),
            "source": post.get("source", "reddit"),
            "subsource": subsource,
            "color": color,
            "timestamp": ts,
            "post_url": post.get("post_url") or post.get("url") or post.get("permalink"),
        }
    }
    validate_node(node)
    return node


def reddit_author_to_node(post: Dict) -> Dict:
    """
    Represent the author as an entity node. Author id/name must be present.
    """
    author = post.get("author") or post.get("user") or "unknown"
    subsource = str(post.get("subsource") or "").strip().lower()
    color = SUBREDDIT_COLORS.get(subsource.lower(), DEFAULT_REDDIT_COLOR)
    default_conf = SUBREDDIT_CONFIDENCE.get(subsource.lower(), 0.6)
    author_id = f"reddit_user:{str(author).strip().lower()}"
    node = {
        "data": {
            "id": author_id,
            "label": str(author),
            "kind": "entity",
            "severity": DEFAULT_SEVERITY,
            "size": 12,
            "confidence": float(post.get("author_confidence", default_conf)),
            "source": "reddit",
            "subsource": subsource,
            "color": color,
            "timestamp": _timestamp(post),
            "author_url": f"https://www.reddit.com/user/{author}",
        }
    }
    validate_node(node)
    return node


def ioc_to_node(ioc: Dict, timestamp: int, source: str = "reddit") -> Dict:
    """
    IOC structure expected: {"value": "...", "type": "...", "severity": optional, "confidence": optional, "weight": optional}
    """
    subsource = str(ioc.get("subsource") or "").strip().lower()
    color = SUBREDDIT_COLORS.get(subsource.lower(), DEFAULT_REDDIT_COLOR)
    node = {
        "data": {
            "id": hash_ioc_id(ioc),
            "label": ioc["value"],
            "kind": "ioc",
            "severity": (ioc.get("severity") or DEFAULT_SEVERITY).lower(),
            "size": min(max(int(ioc.get("weight", 10)), 1), 100),
            "confidence": float(ioc.get("confidence", 0.5)),
            "source": ioc.get("source", source),
            "subsource": subsource,
            "color": color,
            "timestamp": int(timestamp),
        }
    }
    validate_node(node)
    return node


def link_post_to_author(post_node: Dict, author_node: Dict) -> Dict:
    edge = {
        "data": {
            "id": f"{post_node['data']['id']}→{author_node['data']['id']}",
            "source": post_node["data"]["id"],
            "target": author_node["data"]["id"],
            "relation": "authored_by",
            "weight": 1.0,
        }
    }
    validate_edge(edge)
    return edge


def link_post_to_ioc(post_node: Dict, ioc_node: Dict) -> Dict:
    edge = {
        "data": {
            "id": f"{post_node['data']['id']}→{ioc_node['data']['id']}",
            "source": post_node["data"]["id"],
            "target": ioc_node["data"]["id"],
            "relation": "mentions",
            "weight": 1.0,
        }
    }
    validate_edge(edge)
    return edge


def adapt_reddit_items(items: Iterable[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Convert iterable of reddit posts/comments (dicts) into schema-compliant nodes/edges.
    Each item may include a list of IOCs under "iocs".
    """
    nodes: List[Dict] = []
    edges: List[Dict] = []

    for post in items:
        post_ts = _timestamp(post)
        post_node = reddit_post_to_node(post)
        nodes.append(post_node)

        author_node = reddit_author_to_node(post)
        nodes.append(author_node)
        edges.append(link_post_to_author(post_node, author_node))

        for ioc in post.get("iocs", []) or []:
            if isinstance(ioc, dict) and "subsource" not in ioc:
                ioc["subsource"] = post.get("subsource")
            ioc_node = ioc_to_node(ioc, timestamp=post_ts, source="reddit")
            nodes.append(ioc_node)
            edges.append(link_post_to_ioc(post_node, ioc_node))

    return nodes, edges
