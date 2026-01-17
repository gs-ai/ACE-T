#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from adapters.reddit_adapter import adapt_reddit_items
from adapters.emit_graph import emit_graph
from db.db_utils import connect
from modules.realtime_open_feeds import (
    GROUP_LIMIT,
    _alert_node,
    _indicator_group_key,
    _ioc_node,
    _ioc_timestamp,
    _link_alert_to_ioc,
    _load_config,
)
from schema import hash_alert_id


def _parse_json(raw: str) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _retention_days() -> int:
    try:
        return int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    except Exception:
        return 30


def _replay_max_iocs() -> int:
    try:
        return int(os.getenv("ACE_T_REPLAY_MAX_IOCS") or "2000")
    except Exception:
        return 2000


def _replay_max_iocs_per_feed() -> int:
    return _env_int("ACE_T_REPLAY_MAX_IOCS_PER_FEED", 500)


def _replay_max_reddit() -> int:
    return _env_int("ACE_T_REPLAY_MAX_REDDIT", 1500)


def _replay_max_reddit_per_subsource() -> int:
    return _env_int("ACE_T_REPLAY_MAX_REDDIT_PER_SUBSOURCE", 300)


def _enabled_feeds() -> List[str]:
    config = _load_config()
    sources_cfg = config.get("sources") if isinstance(config, dict) else {}
    realtime_cfg = sources_cfg.get("realtime_open_feeds") if isinstance(sources_cfg, dict) else {}
    enabled = realtime_cfg.get("enabled_feeds") if isinstance(realtime_cfg, dict) else None
    if not enabled:
        return []
    return [str(feed).strip().lower() for feed in enabled if str(feed).strip()]


def _load_recent_iocs(days: int, enabled_feeds: List[str]) -> List[Dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT ioc_hash, indicator, ioc_type, source_feed, first_seen, last_seen,
                   confidence, severity, ioc_metadata, tags
            FROM iocs
            WHERE datetime(last_seen) >= datetime('now', ?)
            ORDER BY datetime(last_seen) DESC
            """,
            (f"-{days} days",),
        ).fetchall()
    finally:
        conn.close()

    iocs: List[Dict[str, Any]] = []
    for row in rows:
        source_feed = str(row["source_feed"] or "").strip().lower()
        if enabled_feeds and source_feed not in enabled_feeds:
            continue
        iocs.append(
            {
                "ioc_hash": row["ioc_hash"],
                "indicator": row["indicator"],
                "ioc_type": row["ioc_type"],
                "source_feed": source_feed,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "confidence": row["confidence"],
                "severity": row["severity"],
                "metadata": _parse_json(row["ioc_metadata"] or ""),
                "tags": _parse_json(row["tags"] or ""),
            }
        )
    return iocs


def _build_replay_iocs(days: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    enabled = _enabled_feeds()
    raw_iocs = _load_recent_iocs(days, enabled)
    if not raw_iocs:
        print("[replay] no recent IOCs found to replay")
        return [], [], 0

    group_counts: Dict[str, int] = {}
    max_iocs = _replay_max_iocs()
    max_per_feed = _replay_max_iocs_per_feed()
    filtered: List[Dict[str, Any]] = []
    per_feed_counts: Dict[str, int] = {}
    for ioc in raw_iocs:
        group_key = _indicator_group_key(ioc)
        count = group_counts.get(group_key, 0)
        if count >= GROUP_LIMIT:
            continue
        if max_per_feed > 0:
            feed = str(ioc.get("source_feed") or "").strip().lower()
            if feed:
                feed_count = per_feed_counts.get(feed, 0)
                if feed_count >= max_per_feed:
                    continue
                per_feed_counts[feed] = feed_count + 1
        group_counts[group_key] = count + 1
        filtered.append(ioc)
        if max_iocs > 0 and len(filtered) >= max_iocs:
            break

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for ioc in filtered:
        ts = _ioc_timestamp(ioc)
        ioc_node = _ioc_node(ioc, ts)
        nodes.append(ioc_node)
        alert_id = hash_alert_id({"source": "realtime_open_feeds", "id": ioc["ioc_hash"]})
        alert_node = _alert_node(
            alert_id,
            f"Indicator detected: {ioc['indicator']}",
            str(ioc.get("source_feed") or "").lower(),
            (ioc.get("severity") or "medium").lower(),
            float(ioc.get("confidence", 50)) / 100.0,
            ts,
            ioc.get("indicator") or "",
        )
        nodes.append(alert_node)
        edges.append(_link_alert_to_ioc(alert_node, ioc_node))

    print(f"[replay] prepared {len(filtered)} IOCs for graph replay (last {days} days)")
    return nodes, edges, len(filtered)


def _parse_detected_at(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return time.time()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return time.time()


_REDDIT_POST_RE = re.compile(r"/comments/([a-z0-9]+)/", re.I)
_REDDIT_COMMENT_RE = re.compile(r"/comments/([a-z0-9]+)/[^/]+/([a-z0-9]+)/", re.I)
_REDDIT_SHORT_RE = re.compile(r"redd\.it/([a-z0-9]+)", re.I)


def _extract_reddit_ids(url: str) -> Tuple[str | None, str | None]:
    if not url:
        return None, None
    match = _REDDIT_COMMENT_RE.search(url)
    if match:
        return match.group(1), match.group(2)
    match = _REDDIT_POST_RE.search(url)
    if match:
        return match.group(1), None
    match = _REDDIT_SHORT_RE.search(url)
    if match:
        return match.group(1), None
    return None, None


def _load_recent_reddit_alerts(days: int) -> List[Dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT content_hash, detected_at, payload
            FROM alerts
            WHERE source_name = ?
              AND datetime(detected_at) >= datetime('now', ?)
            ORDER BY datetime(detected_at) DESC
            """,
            ("reddit", f"-{days} days"),
        ).fetchall()
    finally:
        conn.close()

    alerts: List[Dict[str, Any]] = []
    for row in rows:
        payload = _parse_json(row["payload"] or "")
        if not isinstance(payload, dict):
            payload = {}
        alerts.append(
            {
                "content_hash": row["content_hash"],
                "detected_at": row["detected_at"],
                "payload": payload,
            }
        )
    return alerts


def _payload_to_reddit_item(alert: Dict[str, Any]) -> Dict[str, Any]:
    payload = alert.get("payload") or {}
    detected_at = alert.get("detected_at")
    content_hash = alert.get("content_hash")

    url = str(payload.get("comment_url") or payload.get("url") or payload.get("post_url") or payload.get("permalink") or "").strip()
    post_id, comment_id = _extract_reddit_ids(url)
    if not post_id:
        post_id = str(payload.get("post_id") or payload.get("link_id") or "").strip() or None
    if not comment_id:
        comment_id = str(payload.get("comment_id") or "").strip() or None

    reddit_id = str(payload.get("reddit_id") or payload.get("id") or "").strip() or None
    if not reddit_id:
        if post_id and comment_id:
            reddit_id = f"{post_id}:{comment_id}"
        elif post_id:
            reddit_id = post_id
        else:
            reddit_id = str(content_hash or "").strip() or None

    subreddit = str(payload.get("subreddit") or payload.get("subsource") or "").strip().lower()
    base_url = ""
    if subreddit and post_id:
        base_url = f"https://www.reddit.com/r/{subreddit}/comments/{post_id}/"

    item = {
        "id": reddit_id,
        "title": payload.get("title"),
        "body": payload.get("content"),
        "author": payload.get("author"),
        "created_utc": _parse_detected_at(detected_at),
        "url": url or base_url,
        "post_url": url or base_url,
        "source": "reddit",
        "subsource": subreddit,
        "score": payload.get("score"),
        "num_comments": payload.get("num_comments"),
        "parent_id": payload.get("parent_id"),
        "link_id": payload.get("link_id") or post_id,
    }
    return item


def _build_replay_reddit(days: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    raw_alerts = _load_recent_reddit_alerts(days)
    if not raw_alerts:
        print("[replay] no recent Reddit alerts found to replay")
        return [], [], 0

    max_total = _replay_max_reddit()
    max_per_sub = _replay_max_reddit_per_subsource()
    per_sub_counts: Dict[str, int] = {}
    items: List[Dict[str, Any]] = []
    seen_hashes: set[str] = set()

    for alert in raw_alerts:
        content_hash = str(alert.get("content_hash") or "")
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)
        payload = alert.get("payload") or {}
        subsource = str(payload.get("subreddit") or payload.get("subsource") or "").strip().lower()
        if max_per_sub > 0 and subsource:
            count = per_sub_counts.get(subsource, 0)
            if count >= max_per_sub:
                continue
            per_sub_counts[subsource] = count + 1
        items.append(_payload_to_reddit_item(alert))
        if max_total > 0 and len(items) >= max_total:
            break

    if not items:
        print("[replay] Reddit alerts filtered out by replay limits")
        return [], [], 0

    nodes, edges = adapt_reddit_items(items)
    print(f"[replay] prepared {len(items)} Reddit alerts for graph replay (last {days} days)")
    return nodes, edges, len(items)


def replay_recent_iocs() -> int:
    nodes, edges, count = _build_replay_iocs(_retention_days())
    if nodes or edges:
        emit_graph([n["data"] for n in nodes], [e["data"] for e in edges])
    if count:
        print(f"[replay] replayed {count} IOCs into graph")
    return count


def replay_recent_reddit() -> int:
    days = _retention_days()
    nodes, edges, count = _build_replay_reddit(days)
    if nodes or edges:
        emit_graph([n["data"] for n in nodes], [e["data"] for e in edges])
    if count:
        print(f"[replay] replayed {count} Reddit alerts into graph")
    return count


def replay_all() -> Tuple[int, int]:
    days = _retention_days()
    ioc_nodes, ioc_edges, ioc_count = _build_replay_iocs(days)
    reddit_nodes, reddit_edges, reddit_count = _build_replay_reddit(days)
    if not ioc_nodes and not ioc_edges and not reddit_nodes and not reddit_edges:
        return 0, 0
    nodes = [n["data"] for n in ioc_nodes] + [n["data"] for n in reddit_nodes]
    edges = [e["data"] for e in ioc_edges] + [e["data"] for e in reddit_edges]
    emit_graph(nodes, edges)
    if ioc_count:
        print(f"[replay] replayed {ioc_count} IOCs into graph")
    if reddit_count:
        print(f"[replay] replayed {reddit_count} Reddit alerts into graph")
    return ioc_count, reddit_count


if __name__ == "__main__":
    start = time.time()
    replay_all()
    print(f"[replay] done in {time.time() - start:.2f}s")
