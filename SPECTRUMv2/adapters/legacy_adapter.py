from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from core.models import Artifact, Signal


def _iso(value: Optional[str]) -> str:
    if value:
        return value
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    raw = ":".join([prefix, *[str(p) for p in parts if p]])
    return _sha256(raw)


def _infer_content_type(payload: Dict[str, Any]) -> str:
    if payload.get("content") or payload.get("title"):
        return "text/plain"
    if payload:
        return "application/json"
    return "text/plain"


def _clamp_conf(value: Any, default: float = 0.5) -> float:
    try:
        num = float(value)
    except Exception:
        num = default
    return max(0.0, min(1.0, num))


def _artifact_source(
    platform: str,
    account_handle: str | None,
    method: str,
    channel: str | None = None,
) -> Dict[str, Any]:
    source = {"platform": platform, "collection_method": method}
    if channel:
        source["channel"] = channel
    if account_handle:
        source["account_handle"] = account_handle
    return source


def _hash_bundle(content_hash: str, payload: Dict[str, Any]) -> Dict[str, str]:
    if content_hash and re.fullmatch(r"[a-fA-F0-9]{64}", content_hash):
        return {"sha256": content_hash}
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return {"sha256": _sha256(serialized)}


def _infer_band_for_source(source_name: str) -> str:
    key = str(source_name or "").lower()
    if key == "reddit":
        return "VISIBLE"
    return "FM"


def alert_to_artifact(alert: Dict[str, Any], band: Optional[str] = None) -> Dict[str, Any]:
    payload = alert.get("payload") or {}
    content_hash = str(alert.get("content_hash") or "")
    source_name = str(alert.get("source_name") or payload.get("source_name") or "ace-t")
    detected_at = _iso(alert.get("detected_at"))
    url = (
        payload.get("url")
        or payload.get("post_url")
        or payload.get("comment_url")
        or payload.get("source_url")
        or ""
    )
    if not url:
        url = f"ace-t://alert/{content_hash}"
    account = payload.get("author") or payload.get("account_handle")
    channel = payload.get("subreddit") or payload.get("channel")
    method = "API" if source_name.lower() == "reddit" else "INGEST"
    tags = payload.get("tags") or []
    notes = payload.get("content") or payload.get("context") or ""
    title = payload.get("title")
    if title and notes:
        notes = f"{title}\n\n{notes}"
    elif title and not notes:
        notes = str(title)
    artifact = Artifact(
        id=_stable_id("artifact", source_name, content_hash, url),
        type="artifact",
        created_at=detected_at,
        updated_at=detected_at,
        band=band or _infer_band_for_source(source_name),
        confidence=_clamp_conf(payload.get("confidence"), 0.55),
        labels=[source_name],
        tags=list(tags) if tags else None,
        notes=notes or None,
        uri=str(url),
        captured_at=detected_at,
        content_type=_infer_content_type(payload),
        source=_artifact_source(source_name, account, method, channel=channel),
        hashes=_hash_bundle(content_hash, payload),
    )
    return artifact.to_dict()


def ioc_to_artifact(ioc: Dict[str, Any], band: Optional[str] = None) -> Dict[str, Any]:
    source_feed = str(ioc.get("source_feed") or "feed")
    indicator = str(ioc.get("indicator") or "")
    ioc_hash = str(ioc.get("ioc_hash") or _stable_id("ioc", source_feed, indicator))
    uri = ioc.get("metadata", {}).get("reference") or indicator or f"ace-t://ioc/{ioc_hash}"
    detected_at = _iso(ioc.get("first_seen") or ioc.get("last_seen"))
    tags = ioc.get("tags") or []
    notes = f"Indicator {indicator} ({ioc.get('ioc_type')})"
    artifact = Artifact(
        id=_stable_id("artifact", source_feed, ioc_hash, uri),
        type="artifact",
        created_at=detected_at,
        updated_at=detected_at,
        band=band or "FM",
        confidence=_clamp_conf(float(ioc.get("confidence", 50)) / 100.0, 0.5),
        labels=[source_feed],
        tags=list(tags) if tags else None,
        notes=notes,
        uri=str(uri),
        captured_at=detected_at,
        content_type="application/json",
        source=_artifact_source(source_feed, None, "INGEST"),
        hashes=_hash_bundle(ioc_hash, ioc),
    )
    return artifact.to_dict()


def ioc_to_signal(ioc: Dict[str, Any], artifact_id: Optional[str], band: Optional[str] = None) -> Dict[str, Any]:
    ioc_type = str(ioc.get("ioc_type") or "").lower()
    value = ioc.get("indicator")
    signal_type = {
        "ip": "IP",
        "domain": "DOMAIN",
        "url": "URL",
        "hash": "MEDIA_HASH",
    }.get(ioc_type, "ID_TOKEN")
    evidence = [{"artifact_id": artifact_id}] if artifact_id else []
    signal = Signal(
        id=_stable_id("signal", signal_type, str(value)),
        type="signal",
        created_at=_iso(ioc.get("first_seen") or ioc.get("last_seen")),
        band=band or "XRAY",
        confidence=_clamp_conf(float(ioc.get("confidence", 50)) / 100.0, 0.5),
        labels=[str(ioc.get("source_feed") or "feed")],
        signal_type=signal_type,
        value=value,
        normalized=str(value).lower() if isinstance(value, str) else value,
        evidence=evidence or None,
    )
    return signal.to_dict()


def target_to_signal(target: Dict[str, Any], band: Optional[str] = None) -> Dict[str, Any]:
    value = target.get("value") or target.get("target") or target.get("id")
    target_type = str(target.get("type") or "").lower()
    if not value:
        return {}
    signal_type = "ID_TOKEN"
    if target_type in ("handle", "account", "username"):
        signal_type = "HANDLE"
    elif target_type in ("domain", "hostname"):
        signal_type = "DOMAIN"
    elif target_type == "url":
        signal_type = "URL"
    elif target_type == "ip":
        signal_type = "IP"
    elif target_type == "email":
        signal_type = "EMAIL"
    normalized = value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if signal_type == "URL":
            normalized = normalized.strip()
        elif signal_type == "DOMAIN":
            normalized = normalized.strip(".")
        elif signal_type == "HANDLE":
            normalized = normalized.lstrip("@")
            if normalized.startswith("r/"):
                normalized = normalized[2:]
    signal = Signal(
        id=_stable_id("signal", signal_type, str(normalized)),
        type="signal",
        created_at=_iso(target.get("created_at")),
        band=band or "AM",
        confidence=_clamp_conf(target.get("confidence", 0.4), 0.4),
        labels=["seed"],
        signal_type=signal_type,
        value=value,
        normalized=normalized,
    )
    return signal.to_dict()


def url_to_signal(url: str, artifact_id: Optional[str], band: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.netloc or url
    evidence = [{"artifact_id": artifact_id}] if artifact_id else []
    return Signal(
        id=_stable_id("signal", "URL", url),
        type="signal",
        created_at=_iso(None),
        band=band,
        confidence=0.6,
        labels=["url"],
        signal_type="URL",
        value=url,
        normalized=url,
        evidence=evidence or None,
    ).to_dict()


def domain_signal_from_url(url: str, artifact_id: Optional[str], band: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.netloc or ""
    if not host:
        return {}
    host = host.split(":")[0].strip(".")
    evidence = [{"artifact_id": artifact_id}] if artifact_id else []
    return Signal(
        id=_stable_id("signal", "DOMAIN", host),
        type="signal",
        created_at=_iso(None),
        band=band,
        confidence=0.6,
        labels=["domain"],
        signal_type="DOMAIN",
        value=host,
        normalized=host,
        evidence=evidence or None,
    ).to_dict()
