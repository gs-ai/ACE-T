"""
Real-time Open Threat Intelligence Feeds Module

Integrates multiple open-source threat intelligence feeds into ACE-T:
- Abuse.ch (ThreatFox, URLhaus, FeodoTracker, SSL Blacklist)
- Blocklist.de attacker IPs
- SANS ISC/DShield data
- FireHOL aggregated lists
- Emerging Threats Open rules
- Tor exit nodes
- GitHub IOC mirrors

All feeds are pulled anonymously without API keys or authentication.
Indicators are normalized into ACE-T IOC objects and correlated with existing alerts.
"""

import asyncio
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import logging
import ipaddress
import time
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
from adapters.emit_graph import emit_graph
from db.alert_writer import write_alerts
from db.ioc_writer import write_iocs
from schema import hash_alert_id, hash_ioc_id, validate_edge, validate_node

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
SEEN_DIR = DATA_DIR / "realtime_feed_seen"
GRAPH_PATH = DATA_DIR / "graph_data.json"
DB_PATH = ROOT_DIR / "db" / "osint.db"
CONFIG_PATH = ROOT_DIR / "config.yml"

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False
    yaml = None


class _NoopTorEnforcer:
    async def gate_request(self, reason: str = "") -> None:
        return None


try:
    from tor_enforcer import get_tor_enforcer as _legacy_get_tor_enforcer
except Exception:
    _legacy_get_tor_enforcer = None


def get_tor_enforcer() -> _NoopTorEnforcer:
    if _legacy_get_tor_enforcer:
        try:
            return _legacy_get_tor_enforcer()
        except Exception:
            return _NoopTorEnforcer()
    return _NoopTorEnforcer()


def _load_config() -> Dict[str, Any]:
    if not YAML_AVAILABLE or not CONFIG_PATH.exists():
        return {}
    try:
        payload = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


# Feed definitions with URLs, types, and parsing metadata
THREAT_FEEDS = {
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "json",
        "indicator_types": ["ip", "domain", "url", "hash"],
        "description": "ThreatFox IOC feed from Abuse.ch",
        "interval": 300,  # 5 minutes
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv",
        "indicator_types": ["url", "domain", "hash"],
        "description": "URLhaus malware URLs from Abuse.ch",
        "interval": 300,
    },
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "csv",
        "indicator_types": ["ip"],
        "description": "Feodo Tracker C2 IPs from Abuse.ch",
        "interval": 600,
    },
    "sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "csv",
        "indicator_types": ["ip"],
        "description": "SSL Blacklist from Abuse.ch",
        "interval": 3600,
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "txt",
        "indicator_types": ["ip"],
        "description": "Blocklist.de attacker IPs",
        "interval": 1800,
    },
    "dshield_top": {
        "url": "https://isc.sans.edu/api/sources/attacks/10000/",
        "type": "txt",
        "indicator_types": ["ip"],
        "description": "SANS DShield top attackers",
        "interval": 3600,
    },
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "type": "txt",
        "indicator_types": ["ip"],
        "description": "FireHOL Level 1 threat IPs",
        "interval": 3600,
    },
    "emerging_threats_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "txt",
        "indicator_types": ["ip"],
        "description": "Emerging Threats compromised IPs",
        "interval": 3600,
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "type": "txt",
        "indicator_types": ["ip"],
        "description": "Tor Project exit node list",
        "interval": 3600,
    },
    "stamparm_maltrail": {
        "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt",
        "type": "txt",
        "indicator_types": ["domain", "url", "ip"],
        "description": "Maltrail generic malware indicators",
        "interval": 7200,
    },
    "cybercrime_tracker": {
        "url": "https://raw.githubusercontent.com/CybercrimeTracker/Feeds/main/all.txt",
        "type": "txt",
        "indicator_types": ["url", "domain", "ip"],
        "description": "Cybercrime Tracker C2 indicators",
        "interval": 3600,
    },
}

GROUP_LIMIT = int(os.getenv("REALTIME_FEED_GROUP_MAX", "50") or "50")
ALERT_BURST_THRESHOLD = int(os.getenv("REALTIME_FEED_ALERT_THRESHOLD", "120") or "120")
ALERT_MAX_PER_RUN = int(os.getenv("REALTIME_FEED_ALERT_MAX", "60") or "60")


def _retention_cutoff() -> float:
    try:
        days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    except Exception:
        days = 30
    return time.time() - (days * 86400)


def _ioc_timestamp(ioc: Dict[str, Any]) -> float:
    ts = _parse_ts(str(ioc.get("first_seen") or ioc.get("last_seen") or ""))
    if ts:
        return ts.replace(tzinfo=timezone.utc).timestamp()
    return time.time()


def _get_existing_graph() -> tuple[list[dict], list[dict]]:
    if not GRAPH_PATH.exists():
        return [], []
    try:
        elements = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return [], []
    nodes = [e.get("data", {}) for e in elements if not {"source", "target"} <= set((e.get("data") or {}).keys())]
    edges = [e.get("data", {}) for e in elements if {"source", "target"} <= set((e.get("data") or {}).keys())]
    return nodes, edges


def _alert_node(alert_id: str, label: str, source_feed: str, severity: str, confidence: float, ts: float, indicator: str) -> Dict[str, Any]:
    node = {
        "data": {
            "id": alert_id,
            "label": label,
            "kind": "alert",
            "severity": severity,
            "size": 22,
            "confidence": confidence,
            "source": "realtime_open_feeds",
            "subsource": source_feed,
            "timestamp": int(ts),
            "indicator": indicator,
        }
    }
    validate_node(node)
    return node


def _ioc_node(ioc: Dict[str, Any], ts: float) -> Dict[str, Any]:
    payload = {
        "value": ioc.get("indicator"),
        "type": ioc.get("ioc_type"),
        "severity": ioc.get("severity"),
        "confidence": float(ioc.get("confidence", 50)) / 100.0,
        "source": "realtime_open_feeds",
        "subsource": str(ioc.get("source_feed") or "").lower(),
        "timestamp": int(ts),
    }
    node = {
        "data": {
            "id": hash_ioc_id(payload),
            "label": payload["value"],
            "kind": "ioc",
            "severity": (payload.get("severity") or "medium").lower(),
            "size": 18,
            "confidence": float(payload.get("confidence", 0.5)),
            "source": payload.get("source", "realtime_open_feeds"),
            "subsource": payload.get("subsource"),
            "timestamp": int(payload.get("timestamp") or ts),
            "indicator": payload["value"],
            "ioc_type": payload.get("type"),
        }
    }
    validate_node(node)
    return node


def _link_alert_to_ioc(alert_node: Dict[str, Any], ioc_node: Dict[str, Any]) -> Dict[str, Any]:
    edge = {
        "data": {
            "id": f"{alert_node['data']['id']}→{ioc_node['data']['id']}",
            "source": alert_node["data"]["id"],
            "target": ioc_node["data"]["id"],
            "relation": "mentions",
            "weight": 1.2,
        }
    }
    validate_edge(edge)
    return edge


def _seen_file(base_dir: Path, store: str) -> Path:
    return base_dir / f"{store}_seen.json"


def _load_seen_hashes(base_dir: Path, store: str) -> Set[str]:
    """Safely load the seen hash checkpoint, healing corrupt files on the fly."""
    path = _seen_file(base_dir, store)
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return set(payload) if isinstance(payload, list) else set()
    except json.JSONDecodeError as exc:
        logger.warning(
            "realtime_open_feeds_seen_store_corrupt",
            extra={"store": store, "path": str(path), "error": str(exc)},
        )
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    except Exception as exc:
        logger.error(
            "realtime_open_feeds_seen_store_load_failed",
            extra={"store": store, "error": str(exc)},
        )
    return set()


def _persist_seen_hashes(base_dir: Path, store: str, values: Set[str]) -> None:
    """Persist updated seen hashes in a single atomic write to avoid corruption."""
    base_dir.mkdir(parents=True, exist_ok=True)
    path = _seen_file(base_dir, store)
    tmp_path = path.with_suffix(".tmp")
    data = sorted(values)
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle)
    tmp_path.replace(path)


def _root_domain(value: str) -> str:
    host = value.lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or value


def _indicator_group_key(ioc: Dict[str, Any]) -> str:
    indicator = (ioc.get("indicator") or "").strip()
    ioc_type = (ioc.get("ioc_type") or "").lower()
    source = (ioc.get("source_feed") or "feed").lower()
    if not indicator:
        return f"{source}:unknown"
    if ioc_type == "ip":
        try:
            base = indicator.split(":")[0]
            ip_obj = ipaddress.ip_address(base)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = base.split(".")
                if len(octets) == 4:
                    return f"{source}:{'.'.join(octets[:3])}.0/24"
            return f"{source}:{ip_obj.compressed[:24]}"
        except Exception:
            return f"{source}:{indicator}"
    if ioc_type in ("url", "domain"):
        host = indicator
        if ioc_type == "url":
            with contextlib.suppress(Exception):
                host = urlparse(indicator).netloc or indicator
        return f"{source}:{_root_domain(host)}"
    return f"{source}:{indicator[:40]}"


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        value = ts
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except Exception:
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None


def _severity_weight(severity: Optional[str]) -> int:
    sev = (severity or "").lower()
    if sev == "critical":
        return 4
    if sev == "high":
        return 3
    if sev == "medium":
        return 2
    if sev == "mild":
        return 1
    return 0


def _alert_priority_score(ioc: Dict[str, Any]) -> float:
    """Compute a priority score used when throttling alert floods."""
    severity_bonus = _severity_weight(ioc.get("severity")) * 100
    confidence = max(0, min(100, int(ioc.get("confidence", 50)))) / 100
    confidence_bonus = confidence * 25
    recency_bonus = 0.0
    first_seen = _parse_ts(ioc.get("first_seen"))
    if first_seen:
        age_hours = max(0.0, (datetime.now(timezone.utc) - first_seen).total_seconds() / 3600.0)
        # Give full credit to indicators younger than 6h, taper to zero at 48h+
        recency_bonus = max(0.0, 48.0 - age_hours) / 48.0 * 25
    return severity_bonus + confidence_bonus + recency_bonus


def _dedupe_alert_candidates(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate indicators before alerting."""
    seen: Set[str] = set()
    output: List[Dict[str, Any]] = []
    for ioc in iocs:
        indicator_key = (ioc.get("indicator") or "").strip().lower()
        if not indicator_key:
            indicator_key = ioc.get("group_key") or ioc.get("ioc_hash")
        indicator_key = str(indicator_key or "")
        if indicator_key in seen:
            continue
        seen.add(indicator_key)
        output.append(ioc)
    return output


def _select_relevant_alerts(iocs: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    """Pick the most relevant alerts when feeds spike."""
    limit = max(1, limit)
    ranked = sorted(iocs, key=_alert_priority_score, reverse=True)
    selected: List[Dict[str, Any]] = []
    seen_groups: Set[str] = set()
    for ioc in ranked:
        group_key = (ioc.get("group_key") or _indicator_group_key(ioc)).lower()
        if group_key in seen_groups:
            continue
        seen_groups.add(group_key)
        selected.append(ioc)
        if len(selected) >= limit:
            break
    return selected


def _sentiment_for_severity(severity: str) -> str:
    sev = (severity or "").lower()
    if sev in ("critical", "high"):
        return "negative"
    if sev in ("medium",):
        return "neutral"
    return "info"


def _build_context(ioc: Dict[str, Any]) -> str:
    meta = ioc.get("metadata", {}) or {}
    pieces = [
        f"Indicator {ioc.get('indicator')} ({ioc.get('ioc_type')})",
        f"Severity {(ioc.get('severity') or 'unknown').upper()}",
        f"Confidence {ioc.get('confidence', 0)}",
    ]
    malware = meta.get("malware") or meta.get("family")
    if malware and malware != "unknown":
        pieces.append(f"Malware {malware}")
    threat = meta.get("threat_type") or meta.get("description")
    if threat:
        pieces.append(threat)
    first_seen = ioc.get("first_seen")
    if first_seen:
        pieces.append(f"First seen {first_seen}")
    feed = ioc.get("source_feed")
    if feed:
        pieces.append(f"Feed {feed}")
    return " | ".join(pieces)


def _build_geo(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "country": meta.get("country") or meta.get("geo") or "",
        "state": meta.get("state") or "",
        "city": meta.get("city") or "",
        "lat": meta.get("lat"),
        "lon": meta.get("lon"),
    }


def _build_entities(ioc: Dict[str, Any]) -> Dict[str, List[str]]:
    indicator = ioc.get("indicator", "")
    ioc_type = ioc.get("ioc_type", "")
    tags = ioc.get("tags", []) or []
    entities = {
        "orgs": [],
        "persons": [],
        "keywords": list({ioc.get("source_feed", ""), ioc_type} - {""}),
    }
    if indicator:
        entities["keywords"].append(indicator)
    entities["keywords"].extend(tags[:4])
    return entities


class IOCNormalizer:
    """Normalize threat indicators into ACE-T IOC format."""

    @staticmethod
    def normalize_ioc(
        indicator: str,
        ioc_type: str,
        source_feed: str,
        confidence: int = 50,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize an indicator into ACE-T IOC object format.

        Args:
            indicator: The raw indicator value (IP, domain, URL, hash)
            ioc_type: Type of indicator (ip, domain, url, hash, hash_md5, hash_sha256)
            source_feed: Name of the originating feed
            confidence: Confidence score 0-100
            severity: low, medium, high, critical
            metadata: Additional feed-specific metadata

        Returns:
            Normalized IOC dictionary
        """
        now = datetime.now(timezone.utc).isoformat()
        ioc_hash = hashlib.sha256(f"{source_feed}:{ioc_type}:{indicator}".encode()).hexdigest()

        return {
            "ioc_hash": ioc_hash,
            "indicator": indicator.strip(),
            "ioc_type": ioc_type,
            "source_feed": source_feed,
            "first_seen": now,
            "last_seen": now,
            "confidence": confidence,
            "severity": severity,
            "metadata": metadata or {},
            "tags": [source_feed, ioc_type],
        }

    @staticmethod
    def classify_severity(metadata: Dict[str, Any], ioc_type: str) -> str:
        """
        Classify IOC severity based on metadata and type.

        Args:
            metadata: Feed-specific metadata
            ioc_type: Type of indicator

        Returns:
            Severity level: low, medium, high, critical
        """
        # Check for explicit severity indicators
        if metadata.get("malware_type") in ["ransomware", "banker", "stealer"]:
            return "critical"
        if metadata.get("threat_type") in ["c2", "botnet", "exploit"]:
            return "high"
        if metadata.get("confidence_level", 0) >= 80:
            return "high"
        if ioc_type == "hash":
            return "high"  # File hashes are high confidence
        if metadata.get("last_seen_days", 999) <= 7:
            return "high"  # Recently active
        if ioc_type == "ip" and metadata.get("port") in [22, 3389]:
            return "medium"  # SSH/RDP scanning
        return "medium"


class ThreatFeedParser:
    """Parse threat intelligence feeds into normalized IOCs."""

    @staticmethod
    async def parse_threatfox(data: str) -> List[Dict[str, Any]]:
        """Parse ThreatFox JSON feed."""
        iocs: List[Dict[str, Any]] = []
        try:
            feed_data = json.loads(data)
            entries = feed_data.get("data", [])
            if isinstance(entries, dict):
                entries = list(entries.values())
            if not isinstance(entries, list):
                entries = []

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                ioc_type = entry.get("ioc_type", "").lower()
                indicator = entry.get("ioc_value", "").strip()
                if not indicator:
                    continue

                # Map ThreatFox types to ACE-T types
                type_map = {
                    "ip:port": "ip",
                    "domain": "domain",
                    "url": "url",
                    "md5_hash": "hash_md5",
                    "sha256_hash": "hash_sha256",
                }
                normalized_type = type_map.get(ioc_type, ioc_type.split(":")[0] if ioc_type else "unknown")
                if not normalized_type:
                    normalized_type = "unknown"

                metadata = {
                    "malware": entry.get("malware", "unknown"),
                    "malware_printable": entry.get("malware_printable", ""),
                    "threat_type": entry.get("threat_type", ""),
                    "confidence_level": entry.get("confidence_level", 50),
                    "first_seen": entry.get("first_seen") or entry.get("first_seen_utc", ""),
                    "last_seen": entry.get("last_seen") or entry.get("last_seen_utc", ""),
                    "tags": entry.get("tags", []),
                }

                severity = IOCNormalizer.classify_severity(metadata, normalized_type)

                ioc = IOCNormalizer.normalize_ioc(
                    indicator=indicator,
                    ioc_type=normalized_type,
                    source_feed="threatfox",
                    confidence=metadata["confidence_level"],
                    severity=severity,
                    metadata=metadata,
                )
                iocs.append(ioc)
        except Exception:
            # Log error but don't fail the entire feed
            pass
        return iocs

    @staticmethod
    async def parse_urlhaus(data: str) -> List[Dict[str, Any]]:
        """Parse URLhaus CSV feed."""
        iocs = []
        try:
            reader = csv.DictReader(io.StringIO(data))
            for row in reader:
                url = row.get("url", "").strip()
                if not url or url.startswith("#"):
                    continue

                metadata = {
                    "threat": row.get("threat", "unknown"),
                    "status": row.get("url_status", ""),
                    "tags": row.get("tags", "").split(",") if row.get("tags") else [],
                    "dateadded": row.get("dateadded", ""),
                }

                severity = "high" if "ransomware" in metadata.get("tags", []) else "medium"

                ioc = IOCNormalizer.normalize_ioc(
                    indicator=url,
                    ioc_type="url",
                    source_feed="urlhaus",
                    confidence=70,
                    severity=severity,
                    metadata=metadata,
                )
                iocs.append(ioc)

                # Extract domain from URL
                domain_match = re.search(r"https?://([^/:]+)", url)
                if domain_match:
                    domain = domain_match.group(1)
                    domain_ioc = IOCNormalizer.normalize_ioc(
                        indicator=domain,
                        ioc_type="domain",
                        source_feed="urlhaus",
                        confidence=70,
                        severity=severity,
                        metadata=metadata,
                    )
                    iocs.append(domain_ioc)
        except Exception:
            pass
        return iocs

    @staticmethod
    async def parse_feodotracker(data: str) -> List[Dict[str, Any]]:
        """Parse Feodo Tracker CSV feed."""
        iocs = []
        try:
            lines = data.strip().split("\n")
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        metadata = {
                            "first_seen": parts[0].strip() if len(parts) > 0 else "",
                            "port": parts[2].strip() if len(parts) > 2 else "",
                            "malware": "feodo",
                            "threat_type": "botnet",
                        }

                        ioc = IOCNormalizer.normalize_ioc(
                            indicator=ip,
                            ioc_type="ip",
                            source_feed="feodotracker",
                            confidence=80,
                            severity="high",
                            metadata=metadata,
                        )
                        iocs.append(ioc)
        except Exception:
            pass
        return iocs

    @staticmethod
    async def parse_sslbl(data: str) -> List[Dict[str, Any]]:
        """Parse SSL Blacklist CSV feed."""
        iocs = []
        try:
            lines = data.strip().split("\n")
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        metadata = {
                            "listing_date": parts[0].strip() if len(parts) > 0 else "",
                            "port": parts[2].strip() if len(parts) > 2 else "",
                            "threat_type": "malicious_ssl",
                        }

                        ioc = IOCNormalizer.normalize_ioc(
                            indicator=ip,
                            ioc_type="ip",
                            source_feed="sslbl",
                            confidence=75,
                            severity="high",
                            metadata=metadata,
                        )
                        iocs.append(ioc)
        except Exception:
            pass
        return iocs

    @staticmethod
    async def parse_txt_list(data: str, source_feed: str, ioc_type: str = "ip") -> List[Dict[str, Any]]:
        """Parse simple text list feeds (IPs, domains, URLs)."""
        iocs = []
        try:
            lines = data.strip().split("\n")
            for line in lines:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                # Extract IP from lines like "1.2.3.4 # comment"
                indicator = line.split("#")[0].split(";")[0].strip()
                if not indicator:
                    continue

                # Basic validation based on type
                if ioc_type == "ip" and not re.match(r"^\d+\.\d+\.\d+\.\d+$", indicator):
                    continue

                # Determine severity based on feed
                severity = "medium"
                confidence = 60
                if source_feed in ["feodotracker", "emerging_threats_compromised"]:
                    severity = "high"
                    confidence = 75
                elif source_feed == "tor_exit_nodes":
                    severity = "low"
                    confidence = 90

                ioc = IOCNormalizer.normalize_ioc(
                    indicator=indicator,
                    ioc_type=ioc_type,
                    source_feed=source_feed,
                    confidence=confidence,
                    severity=severity,
                    metadata={"feed_type": "txt_list"},
                )
                iocs.append(ioc)
        except Exception:
            pass
        return iocs


async def fetch_feed(session, feed_name: str, feed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Fetch and parse a single threat intelligence feed.

    Args:
        session: aiohttp session
        feed_name: Name of the feed
        feed_config: Feed configuration dictionary

    Returns:
        List of normalized IOC dictionaries
    """
    url = feed_config["url"]
    feed_type = feed_config["type"]

    try:
        await get_tor_enforcer().gate_request(reason=f"realtime-feed:{feed_name}")
        async with session.get(url, timeout=30) as response:
            if response.status != 200:
                return []

            data = await response.text()

            # Parse based on feed type
            if feed_name == "threatfox":
                return await ThreatFeedParser.parse_threatfox(data)
            elif feed_name == "urlhaus":
                return await ThreatFeedParser.parse_urlhaus(data)
            elif feed_name == "feodotracker":
                return await ThreatFeedParser.parse_feodotracker(data)
            elif feed_name == "sslbl":
                return await ThreatFeedParser.parse_sslbl(data)
            elif feed_type == "txt":
                # Determine primary IOC type for this feed
                ioc_types = feed_config.get("indicator_types", ["ip"])
                primary_type = ioc_types[0]
                return await ThreatFeedParser.parse_txt_list(data, feed_name, primary_type)
            else:
                return []

    except Exception:
        return []


async def monitor_realtime_feeds(session, config: Dict[str, Any], sqlite_writer=None):
    """
    Monitor all real-time threat intelligence feeds.

    This is the main entry point called by ACE-T scheduler.

    Args:
        session: aiohttp session
        config: ACE-T configuration dictionary
    """
    # Get feed configuration
    feed_config = config.get("sources", {}).get("realtime_open_feeds", {})
    enabled_feeds = feed_config.get("enabled_feeds", list(THREAT_FEEDS.keys()))

    # Fetch all enabled feeds concurrently
    tasks: List[Tuple[str, Any]] = []
    for feed_name in enabled_feeds:
        if feed_name in THREAT_FEEDS:
            tasks.append((feed_name, fetch_feed(session, feed_name, THREAT_FEEDS[feed_name])))

    results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)

    # Flatten all IOCs
    all_iocs = []
    for (feed_name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            logger.error(
                "realtime_open_feeds_feed_error",
                extra={"feed": feed_name, "error": str(result)},
            )
            continue
        if isinstance(result, list):
            all_iocs.extend(result)

    # Deduplicate by ioc_hash
    unique_iocs = {ioc["ioc_hash"]: ioc for ioc in all_iocs}

    # Deduplicate against historical seen hashes to avoid bloating DB
    seen_dir = SEEN_DIR
    seen_hashes = _load_seen_hashes(seen_dir, "ioc_hashes")
    filtered_iocs: Dict[str, Dict[str, Any]] = {}
    group_counts: Dict[str, int] = {}
    cutoff = _retention_cutoff()
    for ioc_hash, ioc in unique_iocs.items():
        if ioc_hash in seen_hashes:
            continue
        if _ioc_timestamp(ioc) < cutoff:
            continue
        group_key = _indicator_group_key(ioc)
        ioc["group_key"] = group_key
        count = group_counts.get(group_key, 0)
        if count >= GROUP_LIMIT:
            continue
        group_counts[group_key] = count + 1
        filtered_iocs[ioc_hash] = ioc
        seen_hashes.add(ioc_hash)

    if filtered_iocs:
        with contextlib.suppress(Exception):
            _persist_seen_hashes(seen_dir, "ioc_hashes", seen_hashes)

    if not filtered_iocs:
        return

    # Log IOCs into ACE-T SPECTRUM/db/osint.db
    with contextlib.suppress(Exception):
        write_iocs(filtered_iocs.values())

    # Generate alerts for high-severity IOCs with burst protection
    alert_candidates = [
        ioc for ioc in filtered_iocs.values()
        if ioc["severity"] in ["medium", "high", "critical"]
    ]
    alert_candidates = _dedupe_alert_candidates(alert_candidates)
    selected_alerts = alert_candidates
    if len(alert_candidates) > ALERT_BURST_THRESHOLD:
        limit = min(len(alert_candidates), ALERT_MAX_PER_RUN)
        selected_alerts = _select_relevant_alerts(alert_candidates, limit)
        logger.warning(
            "realtime_open_feeds_alert_throttle",
            extra={
                "candidate_alerts": len(alert_candidates),
                "selected_alerts": len(selected_alerts),
                "threshold": ALERT_BURST_THRESHOLD,
                "limit": limit,
            },
        )

    alert_rows = []
    for ioc in selected_alerts:
        metadata = ioc.get("metadata", {}) or {}
        geo_info = _build_geo(metadata)
        sentiment = _sentiment_for_severity(ioc["severity"])
        context = _build_context(ioc)
        alert_payload = {
            "content_hash": ioc["ioc_hash"],
            "source_name": ioc["source_feed"],
            "detected_at": ioc["first_seen"],
            "payload": {
                "title": f"Indicator detected: {ioc['indicator']}",
                "content": context,
                "context": context,
                "url": metadata.get("reference", ""),
                "entities": _build_entities(ioc),
                "threat_analysis": {
                    "summary": context,
                    "risk_vector": ioc["ioc_type"],
                    "related_terms": list({ioc["ioc_type"], *ioc.get("tags", [])}),
                },
                "sentiment": sentiment,
                "tags": ioc.get("tags", []),
                "classification": ioc["severity"],
                "source_name": ioc["source_feed"],
                "malware": metadata.get("malware", "unknown"),
                "region": geo_info.get("country") or "Unknown",
                "geo_info": geo_info,
                "signal_type": ioc["ioc_type"],
                "group_key": ioc.get("group_key"),
                "indicator": ioc["indicator"],
                "indicator_group": ioc.get("group_key"),
            },
        }
        alert_rows.append(alert_payload)

    if alert_rows:
        with contextlib.suppress(Exception):
            write_alerts(alert_rows)

    # Check for correlations and trigger alerts
    correlation_alerts = await check_correlations(filtered_iocs, config, None)
    if correlation_alerts:
        with contextlib.suppress(Exception):
            write_alerts(correlation_alerts)

    if os.getenv("ACE_T_PIPELINE_MODE", "").strip().lower() not in {"1", "true", "yes"}:
        # Emit to graph
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        for ioc in filtered_iocs.values():
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

        if nodes or edges:
            existing_nodes, existing_edges = _get_existing_graph()
            emit_graph(existing_nodes + [n["data"] for n in nodes], existing_edges + [e["data"] for e in edges])


async def check_correlations(iocs: Dict[str, Dict[str, Any]], config: Dict[str, Any], sqlite_writer=None) -> List[Dict[str, Any]]:
    """
    Check IOCs against existing alerts and trigger high-severity correlations.

    Args:
        iocs: Dictionary of IOC hash -> IOC data
        config: ACE-T configuration
    """
    # Get correlation config
    correlation_config = config.get("sources", {}).get("realtime_open_feeds", {}).get("correlation", {})
    min_severity = correlation_config.get("min_severity", "high")
    
    # Map severity strings to weights for comparison
    severity_weights = {"mild": 1, "medium": 2, "high": 3, "critical": 4}
    min_weight = severity_weights.get(min_severity.lower(), 3)  # Default to high if invalid
    
    # Get recent alerts from database
    db_path = str(DB_PATH)
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash VARCHAR NOT NULL,
            simhash VARCHAR,
            source_name VARCHAR NOT NULL,
            detected_at VARCHAR NOT NULL,
            first_seen VARCHAR,
            last_seen VARCHAR,
            payload JSON
        )
        """
    )

    # Query recent alerts (last 24 hours) - temporarily changed to all alerts for testing
    cursor.execute("""
        SELECT content_hash, source_name, payload
        FROM alerts
        WHERE detected_at >= datetime('now', '-30 days')
    """)
    recent_alerts = cursor.fetchall()

    correlation_alerts: List[Dict[str, Any]] = []
    # Extract indicators from alert payloads
    for content_hash, source_name, payload_json in recent_alerts:
        try:
            payload = json.loads(payload_json)
            
            # Handle different payload structures
            if "payload" in payload:
                # Nested structure (realtime feeds alerts)
                inner = payload["payload"]
                alert_text = f"{inner.get('title', '')} {inner.get('content', '')} {inner.get('url', '')}"
            else:
                # Flat structure (regular alerts)
                alert_text = f"{payload.get('threat_analysis', {}).get('summary', '')} {payload.get('content_excerpt', '')} {payload.get('source_url', '')}"
            
            # Skip if no text content
            if not alert_text.strip():
                continue

            # Check for IOC matches
            matched_iocs = []
            for ioc_hash, ioc in iocs.items():
                indicator = ioc["indicator"]
                if indicator.lower() in alert_text.lower():
                    matched_iocs.append(ioc)

            # If we have matches, create correlation alert
            if matched_iocs:
                # Only trigger for IOCs meeting minimum severity threshold
                qualifying_matches = [
                    ioc for ioc in matched_iocs 
                    if severity_weights.get(ioc["severity"].lower(), 0) >= min_weight
                ]

                if qualifying_matches:
                    correlation_alert = {
                        "content_hash": hashlib.sha256(
                            f"correlation:{content_hash}:{','.join(m['ioc_hash'] for m in qualifying_matches)}".encode()
                        ).hexdigest(),
                        "source_name": "realtime_open_feeds",
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                        "payload": {
                            "title": f"IOC Correlation: {len(qualifying_matches)} threat indicators found",
                            "original_alert": content_hash,
                            "original_source": source_name,
                            "matched_iocs": [
                                {
                                    "indicator": m["indicator"],
                                    "type": m["ioc_type"],
                                    "severity": m["severity"],
                                    "source_feed": m["source_feed"],
                                    "confidence": m["confidence"],
                                }
                                for m in qualifying_matches
                            ],
                            "correlation_score": sum(m["confidence"] for m in qualifying_matches)
                            / len(qualifying_matches),
                        },
                    }
                    correlation_alerts.append(correlation_alert)

        except Exception:
            continue

    conn.close()
    return correlation_alerts


def ingest_realtime_open_feeds() -> None:
    """Run realtime open feeds ingestion once (for scheduler use)."""
    config = _load_config()
    sources_cfg = config.get("sources") if isinstance(config, dict) else {}
    realtime_cfg = sources_cfg.get("realtime_open_feeds") if isinstance(sources_cfg, dict) else {}
    enabled_feeds = realtime_cfg.get("enabled_feeds") if isinstance(realtime_cfg, dict) else None
    if not enabled_feeds:
        enabled_feeds = list(THREAT_FEEDS.keys())
    config = {
        "sources": {
            "realtime_open_feeds": {
                "enabled_feeds": enabled_feeds,
                "correlation": {"min_severity": "high"},
            }
        }
    }

    async def _run_once() -> None:
        async with aiohttp.ClientSession() as session:
            await monitor_realtime_feeds(session, config)

    asyncio.run(_run_once())
