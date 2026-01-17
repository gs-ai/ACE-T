from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
import hashlib

import os

from adapters.legacy_adapter import (
    alert_to_artifact,
    domain_signal_from_url,
    ioc_to_artifact,
    ioc_to_signal,
    target_to_signal,
    url_to_signal,
)
from core.models import Claim, Cluster, Edge, Entity, Event, Signal
from db.db_utils import connect
from modules.realtime_open_feeds import ingest_realtime_open_feeds
from runners.reddit_live_ingest import ingest_comments, ingest_posts
from pipeline.state import load_state, save_state

NEWS_SUBS = {
    "infosecnews",
    "threatintel",
    "osint",
    "netsec",
    "cybersecurity",
}


def _iso(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    text = str(value or "").strip()
    if text:
        return text
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: str) -> str:
    raw = ":".join([prefix, *[str(p) for p in parts if p]])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_json(raw: str) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_alerts(days: int) -> List[Dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT content_hash, source_name, detected_at, payload
            FROM alerts
            WHERE datetime(detected_at) >= datetime('now', ?)
            ORDER BY datetime(detected_at) DESC
            """,
            (f"-{days} days",),
        ).fetchall()
    finally:
        conn.close()
    alerts = []
    for row in rows:
        payload = _parse_json(row["payload"] or "")
        if "payload" in payload and isinstance(payload.get("payload"), dict):
            payload = payload["payload"]
        alerts.append(
            {
                "content_hash": row["content_hash"],
                "source_name": row["source_name"],
                "detected_at": row["detected_at"],
                "payload": payload,
            }
        )
    return alerts


def _load_iocs(days: int) -> List[Dict[str, Any]]:
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
    iocs = []
    for row in rows:
        iocs.append(
            {
                "ioc_hash": row["ioc_hash"],
                "indicator": row["indicator"],
                "ioc_type": row["ioc_type"],
                "source_feed": row["source_feed"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "confidence": row["confidence"],
                "severity": row["severity"],
                "metadata": _parse_json(row["ioc_metadata"] or ""),
                "tags": _parse_json(row["tags"] or ""),
            }
        )
    return iocs


def _news_alerts(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for alert in alerts:
        payload = alert.get("payload") or {}
        sub = str(payload.get("subreddit") or "").strip().lower()
        title = str(payload.get("title") or "").lower()
        if sub in NEWS_SUBS or "news" in title:
            output.append(alert)
    return output


def _archive_alerts(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    for alert in alerts:
        payload = alert.get("payload") or {}
        url = str(payload.get("url") or payload.get("post_url") or "")
        if any(token in url for token in ("archive.org", "webcache", "wayback")):
            output.append(alert)
    return output


def validate_stage(stage: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    seed = inputs.get("seed") or {}
    targets = seed.get("targets") or []
    normalized = []
    seen = set()
    for target in targets:
        signal = target_to_signal(target, band="AM")
        if not signal:
            continue
        key = (signal.get("signal_type"), signal.get("normalized") or signal.get("value"))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(signal)
    return {"validated_targets": normalized}


def collect_stage(stage: Dict[str, Any], inputs: Dict[str, Any], retention_days: int) -> Dict[str, List[Dict[str, Any]]]:
    band = stage.get("band")
    collectors = set(stage.get("collectors") or [])
    outputs: Dict[str, List[Dict[str, Any]]] = {name: [] for name in stage.get("outputs") or []}

    if os.getenv("ACE_T_PIPELINE_LIVE_COLLECT", "").strip().lower() in {"1", "true", "yes"}:
        if "posts" in collectors:
            subreddits = []
            for target in inputs.get("validated_targets") or []:
                if not isinstance(target, dict):
                    continue
                if target.get("signal_type") == "HANDLE":
                    subreddits.append(str(target.get("normalized") or target.get("value") or "").strip())
            subreddits = [s for s in subreddits if s]
            if not subreddits:
                ingest_posts()
                ingest_comments()
            else:
                for sub in subreddits:
                    ingest_posts(subreddit=sub)
                    ingest_comments(subreddit=sub)
        if collectors & {"rss", "open_datasets", "official_feeds", "public_apis", "dns", "certs", "asns"}:
            ingest_realtime_open_feeds()

    alerts = _load_alerts(retention_days)
    iocs = _load_iocs(retention_days)

    targets = inputs.get("validated_targets") or []
    target_values = {
        str(t.get("normalized") or t.get("value")).lower()
        for t in targets
        if isinstance(t, dict) and (t.get("normalized") or t.get("value"))
    }
    if target_values:
        filtered_alerts = []
        for alert in alerts:
            payload = alert.get("payload") or {}
            blob = " ".join(
                [
                    str(payload.get("title") or ""),
                    str(payload.get("content") or payload.get("context") or ""),
                    str(payload.get("url") or payload.get("post_url") or ""),
                    str(payload.get("author") or ""),
                    str(payload.get("subreddit") or ""),
                ]
            ).lower()
            if any(val in blob for val in target_values):
                filtered_alerts.append(alert)
        alerts = filtered_alerts

        filtered_iocs = []
        for ioc in iocs:
            indicator = str(ioc.get("indicator") or "").lower()
            if any(val in indicator for val in target_values):
                filtered_iocs.append(ioc)
        iocs = filtered_iocs

    if "posts" in collectors:
        reddit_alerts = [a for a in alerts if str(a.get("source_name") or "").lower() == "reddit"]
        artifacts = [alert_to_artifact(a, band=band or "VISIBLE") for a in reddit_alerts]
        for name in outputs:
            if name.startswith("artifacts_visible"):
                outputs[name] = artifacts

    if {"archives", "mirrors", "cache_hunts", "reuploads"} & collectors:
        archive_alerts = _archive_alerts(alerts)
        artifacts = [alert_to_artifact(a, band=band or "SHORTWAVE") for a in archive_alerts]
        for name in outputs:
            if name.startswith("artifacts_mirrors"):
                outputs[name] = artifacts

    if {"news", "press", "high_reach_mentions"} & collectors:
        news_alerts = _news_alerts(alerts)
        artifacts = [alert_to_artifact(a, band=band or "TV") for a in news_alerts]
        for name in outputs:
            if name.startswith("artifacts_narrative"):
                outputs[name] = artifacts

    if {"rss", "open_datasets", "official_feeds", "public_apis"} & collectors:
        artifacts = [ioc_to_artifact(ioc, band=band or "FM") for ioc in iocs]
        for name in outputs:
            if name.startswith("artifacts_structured"):
                outputs[name] = artifacts

    if {"dns", "certs", "asns", "repos", "exposure_discovery"} & collectors:
        artifacts = []
        signals = []
        for ioc in iocs:
            artifact = ioc_to_artifact(ioc, band=band or "XRAY")
            artifacts.append(artifact)
            signals.append(ioc_to_signal(ioc, artifact_id=artifact.get("id"), band=band or "XRAY"))
        for name in outputs:
            if name.startswith("artifacts_infra"):
                outputs[name] = artifacts
            if name.startswith("signals_infra"):
                outputs[name] = signals

    if not any(outputs.values()) and band in {"VISIBLE", "SHORTWAVE", "TV"}:
        artifacts = [alert_to_artifact(a, band=band or "VISIBLE") for a in alerts]
        for name in outputs:
            if name.startswith("artifacts"):
                outputs[name] = artifacts
    return outputs


def extract_stage(stage: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    outputs: Dict[str, List[Dict[str, Any]]] = {name: [] for name in stage.get("outputs") or []}
    artifacts: List[Dict[str, Any]] = []
    for key, value in inputs.items():
        if key.startswith("artifacts") and isinstance(value, list):
            artifacts.extend(value)

    for artifact in artifacts:
        artifact_id = artifact.get("id")
        captured_at = artifact.get("captured_at")
        band = artifact.get("band") or "UV"
        evidence = [{"artifact_id": artifact_id}] if artifact_id else []

        time_signal = Signal(
            id=f"time::{artifact_id}",
            type="signal",
            created_at=_iso(captured_at),
            band="UV",
            confidence=0.6,
            labels=["time"],
            signal_type="TIME",
            value=_iso(captured_at),
            normalized=_iso(captured_at),
            evidence=evidence,
        ).to_dict()
        outputs.setdefault("signals_uv", []).append(time_signal)

        uri = str(artifact.get("uri") or "")
        if uri.startswith("http"):
            outputs.setdefault("signals_uv", []).append(url_to_signal(uri, artifact_id, "UV"))
            domain_signal = domain_signal_from_url(uri, artifact_id, "UV")
            if domain_signal:
                outputs.setdefault("signals_uv", []).append(domain_signal)

        doc_meta = Signal(
            id=f"meta::{artifact_id}",
            type="signal",
            created_at=_iso(captured_at),
            band="UV",
            confidence=0.6,
            labels=["doc_meta"],
            signal_type="DOC_META",
            value={
                "content_type": artifact.get("content_type"),
                "size_bytes": artifact.get("size_bytes"),
                "source": (artifact.get("source") or {}).get("platform"),
            },
            normalized=None,
            evidence=evidence,
        ).to_dict()
        outputs.setdefault("signals_uv", []).append(doc_meta)

        tags = artifact.get("tags") or artifact.get("labels") or []
        for tag in tags:
            if not tag:
                continue
            outputs.setdefault("signals_ir", []).append(
                Signal(
                    id=f"topic::{artifact_id}:{tag}",
                    type="signal",
                    created_at=_iso(captured_at),
                    band="IR",
                    confidence=0.55,
                    labels=["topic"],
                    signal_type="TOPIC",
                    value=str(tag),
                    normalized=str(tag).lower(),
                    evidence=evidence,
                ).to_dict()
            )

        note_text = str(artifact.get("notes") or "")
        if note_text:
            claim = Claim(
                id=f"claim::{artifact_id}",
                type="claim",
                created_at=_iso(captured_at),
                band="VISIBLE",
                confidence=0.5,
                labels=["extracted"],
                text=note_text[:512],
                claim_type="ASSERTION",
                evidence=evidence,
            ).to_dict()
            outputs.setdefault("claims", []).append(claim)

        platform = (artifact.get("source") or {}).get("platform") or ""
        event_type = "POST_PUBLISHED" if platform.lower() == "reddit" else "INCIDENT_REPORTED"
        event = Event(
            id=f"event::{artifact_id}",
            type="event",
            created_at=_iso(captured_at),
            band="UV",
            confidence=0.55,
            labels=[platform] if platform else None,
            event_type=event_type,
            time_start=_iso(captured_at),
            participants=[],
            evidence=evidence,
        ).to_dict()
        outputs.setdefault("events_raw", []).append(event)

    return outputs


def resolve_stage(stage: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    outputs: Dict[str, List[Dict[str, Any]]] = {name: [] for name in stage.get("outputs") or []}
    signals: List[Dict[str, Any]] = []
    artifacts: List[Dict[str, Any]] = []
    for key, value in inputs.items():
        if key.startswith("signals") and isinstance(value, list):
            signals.extend(value)
        if key.startswith("artifacts") and isinstance(value, list):
            artifacts.extend(value)

    artifact_sources = {}
    for artifact in artifacts:
        source = artifact.get("source") or {}
        key = artifact.get("id")
        if not key:
            continue
        channel = source.get("channel")
        platform = source.get("platform")
        value = channel or platform
        if value:
            artifact_sources[key] = str(value).strip().lower()
    entities: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for signal in signals:
        signal_type = signal.get("signal_type")
        value = signal.get("normalized") or signal.get("value")
        if not signal_type or value is None:
            continue
        entity_type = {
            "HANDLE": "ACCOUNT",
            "DOMAIN": "DOMAIN",
            "IP": "HOST",
            "URL": "DOCUMENT",
            "EMAIL": "ACCOUNT",
        }.get(signal_type, "TOPIC")
        key = (entity_type, str(value))
        if key in entities:
            continue
        evidence = signal.get("evidence") or []
        source_tags = []
        for ref in evidence:
            if not isinstance(ref, dict):
                continue
            source = artifact_sources.get(ref.get("artifact_id"))
            if source:
                source_tags.append(source)
        if source_tags:
            source_tags = list(dict.fromkeys(source_tags))
        entities[key] = Entity(
            id=_stable_id("entity", entity_type, str(value)),
            type="entity",
            created_at=_iso(signal.get("created_at")),
            band="GAMMA",
            confidence=signal.get("confidence", 0.6),
            labels=[signal_type],
            tags=source_tags or None,
            entity_type=entity_type,
            name=str(value),
            evidence=evidence or None,
        ).to_dict()

    outputs.setdefault("entities", []).extend(list(entities.values()))

    edges: List[Dict[str, Any]] = []
    artifact_to_entities: Dict[str, List[str]] = {}
    for entity in entities.values():
        for ref in entity.get("evidence") or []:
            artifact_id = ref.get("artifact_id")
            if artifact_id:
                artifact_to_entities.setdefault(artifact_id, []).append(entity["id"])

    for artifact_id, member_ids in artifact_to_entities.items():
        if len(member_ids) < 2:
            continue
        for i in range(len(member_ids)):
            for j in range(i + 1, len(member_ids)):
                a = member_ids[i]
                b = member_ids[j]
                edges.append(
                    Edge(
                        id=_stable_id("edge", a, b, artifact_id),
                        type="edge",
                        created_at=_iso(None),
                        band="GAMMA",
                        confidence=0.7,
                        from_id=a,
                        to_id=b,
                        edge_type="CO_OCCURS_WITH",
                        weight=45.0,
                        evidence=[{"artifact_id": artifact_id}],
                    ).to_dict()
                )

    outputs.setdefault("edges_identity", []).extend(edges)

    clusters: List[Dict[str, Any]] = []
    domain_groups: Dict[str, List[str]] = {}
    for entity in entities.values():
        if entity.get("entity_type") != "DOMAIN":
            continue
        name = str(entity.get("name") or "")
        parts = [p for p in name.split(".") if p]
        if len(parts) < 2:
            continue
        root = ".".join(parts[-2:])
        domain_groups.setdefault(root, []).append(entity["id"])
    for root, members in domain_groups.items():
        if len(members) < 2:
            continue
        clusters.append(
            Cluster(
                id=_stable_id("cluster", "domain", root),
                type="cluster",
                created_at=_iso(None),
                band="GAMMA",
                confidence=0.7,
                labels=["domain_group"],
                cluster_type="IDENTITY",
                members=members,
            ).to_dict()
        )
    outputs.setdefault("clusters_identity", []).extend(clusters)
    return outputs


def track_stage(stage: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    outputs: Dict[str, List[Dict[str, Any]]] = {name: [] for name in stage.get("outputs") or []}
    artifacts: List[Dict[str, Any]] = []
    signals: List[Dict[str, Any]] = []
    for key, value in inputs.items():
        if key.startswith("artifacts") and isinstance(value, list):
            artifacts.extend(value)
        if key.startswith("signals") and isinstance(value, list):
            signals.extend(value)

    state = load_state()
    artifact_ids = {a.get("id") for a in artifacts if a.get("id")}
    signal_ids = {s.get("id") for s in signals if s.get("id")}
    new_artifacts = artifact_ids - state.get("artifacts", set())
    new_signals = signal_ids - state.get("signals", set())

    events: List[Dict[str, Any]] = []
    for artifact in artifacts:
        if artifact.get("id") not in new_artifacts:
            continue
        event_type = "POST_PUBLISHED" if (artifact.get("source") or {}).get("platform") == "reddit" else "INCIDENT_REPORTED"
        events.append(
            Event(
                id=f"track::{artifact['id']}",
                type="event",
                created_at=_iso(artifact.get("captured_at")),
                band="RADAR",
                confidence=0.6,
                labels=["track"],
                event_type=event_type,
                time_start=_iso(artifact.get("captured_at")),
                participants=[],
                evidence=[{"artifact_id": artifact["id"]}],
            ).to_dict()
        )

    delta_signals = [s for s in signals if s.get("id") in new_signals]
    outputs.setdefault("events_tracking", []).extend(events)
    outputs.setdefault("signals_deltas", []).extend(delta_signals)

    save_state(artifact_ids, signal_ids)
    return outputs
