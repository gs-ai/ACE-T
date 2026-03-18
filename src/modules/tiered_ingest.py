from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False
    yaml = None

from modules.realtime_open_feeds import ThreatFeedParser

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT_DIR / "config" / "ingest_sources.yaml"

DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "ingest_cache"
PRIMARY_DIR = DATA_DIR / "primary_incidents"
INFRA_DIR = DATA_DIR / "infrastructure_intel"
REPUTATION_DIR = DATA_DIR / "reputation_context"
BACKGROUND_DIR = DATA_DIR / "background_knowledge"

DEFAULT_CONFIG: Dict[str, Any] = {
    "ransomware_live": {
        "enabled": True,
        "api_base": "https://api-pro.ransomware.live/victims/search",
        "query": "law",
        "order": "discovered",
        "min_interval_minutes": 60,
        "daily_limit": 200,
    },
    "abuse_ch": {
        "threatfox": {
            "enabled": True,
            "url": "https://threatfox.abuse.ch/export/json/recent/",
            "type": "json",
        },
        "urlhaus": {
            "enabled": True,
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "type": "csv",
        },
        "feodotracker": {
            "enabled": True,
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            "type": "csv",
        },
        "ja3": {
            "enabled": False,
        },
    },
    "c2_intel": {
        "c2intelfeeds_verified": {"enabled": False},
        "c2intelfeeds_30d": {"enabled": False},
        "montysecurity_c2": {"enabled": False},
        "carbon_black_shadowpad": {"enabled": False},
    },
    "reputation": {
        "blocklist_de": {
            "enabled": True,
            "url": "https://lists.blocklist.de/lists/all.txt",
            "type": "txt",
            "indicator_type": "ip",
        },
        "ipsum": {
            "enabled": True,
            "base_url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels",
            "levels": [3, 4, 5, 6, 7, 8],
            "type": "txt",
            "indicator_type": "ip",
        },
        "alienvault": {"enabled": False},
        "proofpoint_compromised": {"enabled": False},
    },
    "background": {
        "cisa_kev": {
            "enabled": True,
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        },
        "nvd_cve": {
            "enabled": False,
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        },
        "ecrimelabs_cve": {"enabled": False},
        "tool_fingerprints_dir": "data/tool_fingerprints",
    },
}


def _load_config() -> Dict[str, Any]:
    if YAML_AVAILABLE and CONFIG_PATH.exists():
        try:
            data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            logger.warning("tiered_ingest_config_load_failed", extra={"path": str(CONFIG_PATH)})
    return DEFAULT_CONFIG


def _ensure_dirs() -> None:
    for path in (CACHE_DIR, PRIMARY_DIR, INFRA_DIR, REPUTATION_DIR, BACKGROUND_DIR):
        path.mkdir(parents=True, exist_ok=True)


def _stable_hash(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _iso(value: Optional[str]) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    text = str(value).strip()
    if not text:
        return datetime.now(timezone.utc).isoformat()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                continue
    return datetime.now(timezone.utc).isoformat()


def _normalize_domain(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "Unknown"
    if "://" in text:
        text = text.split("://", 1)[1]
    if "/" in text:
        text = text.split("/", 1)[0]
    return text.strip().lower() or "Unknown"


def _cache_path(name: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name.lower())
    return CACHE_DIR / f"{safe}.json"


def _load_cache(name: str) -> Dict[str, Any]:
    path = _cache_path(name)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(name: str, payload: Dict[str, Any]) -> None:
    path = _cache_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _fetch_url(url: str, cache_name: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[Optional[bytes], Dict[str, Any]]:
    cache = _load_cache(cache_name)
    request_headers = {"User-Agent": "ACE-T-SPECTRUM/ingest"}
    if headers:
        request_headers.update(headers)
    if cache.get("etag"):
        request_headers["If-None-Match"] = str(cache["etag"])
    if cache.get("last_modified"):
        request_headers["If-Modified-Since"] = str(cache["last_modified"])

    req = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            etag = resp.headers.get("ETag")
            last_modified = resp.headers.get("Last-Modified")
            sha = hashlib.sha256(body).hexdigest()
            cache.update(
                {
                    "etag": etag,
                    "last_modified": last_modified,
                    "sha256": sha,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "url": url,
                }
            )
            _save_cache(cache_name, cache)
            return body, cache
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, cache
        logger.error("tiered_ingest_fetch_failed", extra={"url": url, "error": str(exc)})
    except Exception as exc:
        logger.error("tiered_ingest_fetch_failed", extra={"url": url, "error": str(exc)})
    return None, cache


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]], key: str = "id") -> None:
    items = _dedupe_records(records, key)
    items.sort(key=lambda r: str(r.get(key) or ""))
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)


def _dedupe_records(records: Iterable[Dict[str, Any]], key: str = "id") -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for record in records:
        record_id = str(record.get(key) or "")
        if not record_id:
            continue
        seen[record_id] = record
    return list(seen.values())


def _run_async(coro: Any) -> Any:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()
    return asyncio.run(coro)


def _normalize_ioc(ioc: Dict[str, Any], source: str, tier: str) -> Dict[str, Any]:
    first_seen = _iso(ioc.get("first_seen"))
    last_seen = _iso(ioc.get("last_seen"))
    indicator = str(ioc.get("indicator") or "").strip()
    ioc_type = str(ioc.get("ioc_type") or ioc.get("type") or "unknown").lower()
    payload = {
        "id": ioc.get("ioc_hash") or _stable_hash([source, ioc_type, indicator, first_seen]),
        "source": source,
        "tier": tier,
        "indicator": indicator or "Unknown",
        "indicator_type": ioc_type or "unknown",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "confidence": ioc.get("confidence", 0),
        "severity": ioc.get("severity", "unknown"),
        "metadata": ioc.get("metadata", {}) or {},
        "tags": ioc.get("tags", []) or [],
    }
    return payload


def _normalize_ransomware_live(victim: Dict[str, Any]) -> Dict[str, Any]:
    victim_name = str(victim.get("post_title") or victim.get("victim") or "Unknown").strip() or "Unknown"
    group = str(victim.get("group_name") or victim.get("group") or "Unknown").strip() or "Unknown"
    country = str(victim.get("country") or "Unknown").strip() or "Unknown"
    description = str(victim.get("description") or "N/A").strip() or "N/A"
    website = victim.get("website") or victim.get("victim_domain") or ""
    victim_domain = _normalize_domain(str(website))
    published = _iso(victim.get("published") or victim.get("discovered"))
    source_url = str(victim.get("permalink") or victim.get("post_url") or "Unknown").strip() or "Unknown"
    record = {
        "id": _stable_hash(
            {
                "source": "ransomware.live",
                "victim": victim_name,
                "group": group,
                "published": published,
                "source_url": source_url,
            }
        ),
        "source": "ransomware.live",
        "victim_name": victim_name,
        "victim_domain": victim_domain,
        "group": group,
        "sector": str(victim.get("sector") or "Unknown").strip() or "Unknown",
        "country": country,
        "first_observed": published,
        "last_observed": published,
        "description": description,
        "source_url": source_url,
        "raw": victim,
    }
    return record


def _load_ransomware_live_cache(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_ransomware_live_cache(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _extract_ransomware_live_victims(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = payload.get("data") or {}
    if isinstance(data, dict):
        victims = data.get("victims") or []
        return victims if isinstance(victims, list) else []
    if isinstance(data, list):
        return data
    return []


def _load_ransomware_live(api_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_key = os.environ.get("RANSOMWARE_LIVE_API_KEY", "").strip()
    if not api_key:
        key_file = ROOT_DIR / "outside_data" / "ransomware_live_api_key.txt"
        if key_file.exists():
            api_key = key_file.read_text(encoding="utf-8").strip()
    if not api_key:
        logger.error("ransomware_live_missing_api_key")
        return []

    cache_path = ROOT_DIR / "outside_data" / "ransomware_live_cache.json"
    cache = _load_ransomware_live_cache(cache_path)
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    min_interval = int(api_cfg.get("min_interval_minutes", 60))
    daily_limit = int(api_cfg.get("daily_limit", 200))
    query = str(api_cfg.get("query") or "law")
    order = str(api_cfg.get("order") or "discovered")

    last_fetch = cache.get("last_fetch_utc")
    daily_date = cache.get("daily_date")
    daily_count = int(cache.get("daily_count") or 0)

    if daily_date != today:
        daily_date = today
        daily_count = 0

    if last_fetch:
        try:
            last_dt = datetime.fromisoformat(last_fetch)
            if (now - last_dt).total_seconds() < min_interval * 60:
                return _extract_ransomware_live_victims(cache)
        except Exception:
            pass

    if daily_count >= daily_limit:
        return _extract_ransomware_live_victims(cache)

    params = urllib.parse.urlencode({"q": query, "order": order})
    url = f"{api_cfg.get('api_base')}?{params}"
    headers = {"X-API-KEY": api_key}

    body, _ = _fetch_url(url, "ransomware_live", headers=headers, timeout=30)
    if body is None:
        return _extract_ransomware_live_victims(cache)
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        logger.error("ransomware_live_invalid_json")
        return _extract_ransomware_live_victims(cache)

    cache_payload = {
        "daily_date": daily_date,
        "daily_count": daily_count + 1,
        "last_fetch_utc": now.isoformat(),
        "query": query,
        "order": order,
        "data": payload.get("data") if isinstance(payload, dict) else payload,
    }
    _save_ransomware_live_cache(cache_path, cache_payload)
    return _extract_ransomware_live_victims(cache_payload)


def _ingest_ransomware_live(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_cfg = cfg.get("ransomware_live", {})
    if not isinstance(api_cfg, dict) or not api_cfg.get("enabled", False):
        return []
    victims = _load_ransomware_live(api_cfg)
    return [_normalize_ransomware_live(v) for v in victims]


def _ingest_abuse_ch(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    abuse_cfg = cfg.get("abuse_ch", {})
    if not isinstance(abuse_cfg, dict):
        return output

    threatfox_cfg = abuse_cfg.get("threatfox", {})
    if threatfox_cfg.get("enabled") and threatfox_cfg.get("url"):
        body, _ = _fetch_url(threatfox_cfg["url"], "abuse_ch_threatfox")
        if body:
            iocs = _run_async(ThreatFeedParser.parse_threatfox(body.decode("utf-8")))
            output.extend(_normalize_ioc(ioc, "threatfox", "infrastructure_intel") for ioc in iocs)

    urlhaus_cfg = abuse_cfg.get("urlhaus", {})
    if urlhaus_cfg.get("enabled") and urlhaus_cfg.get("url"):
        body, _ = _fetch_url(urlhaus_cfg["url"], "abuse_ch_urlhaus")
        if body:
            iocs = _run_async(ThreatFeedParser.parse_urlhaus(body.decode("utf-8")))
            output.extend(_normalize_ioc(ioc, "urlhaus", "infrastructure_intel") for ioc in iocs)

    feodo_cfg = abuse_cfg.get("feodotracker", {})
    if feodo_cfg.get("enabled") and feodo_cfg.get("url"):
        body, _ = _fetch_url(feodo_cfg["url"], "abuse_ch_feodotracker")
        if body:
            iocs = _run_async(ThreatFeedParser.parse_feodotracker(body.decode("utf-8")))
            output.extend(_normalize_ioc(ioc, "feodotracker", "infrastructure_intel") for ioc in iocs)

    ja3_cfg = abuse_cfg.get("ja3", {})
    if ja3_cfg.get("enabled") and ja3_cfg.get("url"):
        body, _ = _fetch_url(ja3_cfg["url"], "abuse_ch_ja3")
        if body:
            iocs = _parse_ja3_feed(body.decode("utf-8"), "abuse_ch_ja3")
            output.extend(_normalize_ioc(ioc, "abuse_ch_ja3", "infrastructure_intel") for ioc in iocs)

    return output


def _parse_ja3_feed(data: str, source: str) -> List[Dict[str, Any]]:
    lines = [ln.strip() for ln in data.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    output: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for line in lines:
        token = line.split(",")[0].strip()
        if not token:
            continue
        output.append(
            {
                "ioc_hash": _stable_hash([source, "ja3", token]),
                "indicator": token,
                "ioc_type": "ja3",
                "source_feed": source,
                "first_seen": now,
                "last_seen": now,
                "confidence": 70,
                "severity": "medium",
                "metadata": {"feed_type": "ja3"},
                "tags": [source, "ja3"],
            }
        )
    return output


def _parse_simple_list(data: str, source: str, indicator_type: str) -> List[Dict[str, Any]]:
    lines = [ln.strip() for ln in data.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    now = datetime.now(timezone.utc).isoformat()
    output: List[Dict[str, Any]] = []
    for line in lines:
        indicator = line.split()[0].strip()
        if not indicator:
            continue
        output.append(
            {
                "ioc_hash": _stable_hash([source, indicator_type, indicator]),
                "indicator": indicator,
                "ioc_type": indicator_type,
                "source_feed": source,
                "first_seen": now,
                "last_seen": now,
                "confidence": 60,
                "severity": "medium",
                "metadata": {"feed_type": "txt_list"},
                "tags": [source, indicator_type],
            }
        )
    return output


def _ingest_c2_intel(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    c2_cfg = cfg.get("c2_intel", {})
    if not isinstance(c2_cfg, dict):
        return output
    for name, entry in c2_cfg.items():
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or os.environ.get(f"{name.upper()}_URL", "")
        if not entry.get("enabled") or not url:
            continue
        indicator_type = str(entry.get("indicator_type") or "ip")
        body, _ = _fetch_url(str(url), f"c2_{name}")
        if body:
            iocs = _parse_simple_list(body.decode("utf-8"), name, indicator_type)
            output.extend(_normalize_ioc(ioc, name, "infrastructure_intel") for ioc in iocs)
    return output


def _ingest_reputation(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    rep_cfg = cfg.get("reputation", {})
    if not isinstance(rep_cfg, dict):
        return output

    block_cfg = rep_cfg.get("blocklist_de", {})
    if block_cfg.get("enabled") and block_cfg.get("url"):
        body, _ = _fetch_url(block_cfg["url"], "blocklist_de")
        if body:
            iocs = _parse_simple_list(body.decode("utf-8"), "blocklist_de", block_cfg.get("indicator_type", "ip"))
            output.extend(_normalize_ioc(ioc, "blocklist_de", "reputation_context") for ioc in iocs)

    ipsum_cfg = rep_cfg.get("ipsum", {})
    if ipsum_cfg.get("enabled") and ipsum_cfg.get("base_url"):
        levels = ipsum_cfg.get("levels") or []
        for level in levels:
            url = f"{ipsum_cfg['base_url']}/{level}.txt"
            body, _ = _fetch_url(url, f"ipsum_level_{level}")
            if body:
                iocs = _parse_simple_list(body.decode("utf-8"), f"ipsum_level_{level}", "ip")
                output.extend(_normalize_ioc(ioc, f"ipsum_level_{level}", "reputation_context") for ioc in iocs)

    for name in ("alienvault", "proofpoint_compromised"):
        entry = rep_cfg.get(name, {})
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or os.environ.get(f"{name.upper()}_URL", "")
        if not entry.get("enabled") or not url:
            continue
        indicator_type = str(entry.get("indicator_type") or "ip")
        body, _ = _fetch_url(str(url), f"reputation_{name}")
        if body:
            iocs = _parse_simple_list(body.decode("utf-8"), name, indicator_type)
            output.extend(_normalize_ioc(ioc, name, "reputation_context") for ioc in iocs)

    return output


def _ingest_background(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    bg_cfg = cfg.get("background", {})
    if not isinstance(bg_cfg, dict):
        return output

    kev_cfg = bg_cfg.get("cisa_kev", {})
    if kev_cfg.get("enabled") and kev_cfg.get("url"):
        body, _ = _fetch_url(kev_cfg["url"], "cisa_kev")
        if body:
            output.extend(_parse_cisa_kev(body.decode("utf-8")))

    nvd_cfg = bg_cfg.get("nvd_cve", {})
    if nvd_cfg.get("enabled") and nvd_cfg.get("url"):
        headers = {}
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key:
            headers["apiKey"] = api_key
        body, _ = _fetch_url(nvd_cfg["url"], "nvd_cve", headers=headers)
        if body:
            output.extend(_parse_nvd(body.decode("utf-8")))

    ecrime_cfg = bg_cfg.get("ecrimelabs_cve", {})
    if ecrime_cfg.get("enabled") and ecrime_cfg.get("url"):
        body, _ = _fetch_url(ecrime_cfg["url"], "ecrimelabs_cve")
        if body:
            output.extend(_parse_generic_cve(body.decode("utf-8"), "ecrimelabs_cve"))

    tool_dir = bg_cfg.get("tool_fingerprints_dir")
    if tool_dir:
        output.extend(_load_tool_fingerprints(ROOT_DIR / str(tool_dir)))

    return output


def _parse_cisa_kev(raw: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(raw)
    except Exception:
        return []
    catalog = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(catalog, list):
        return []
    output: List[Dict[str, Any]] = []
    for entry in catalog:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID") or entry.get("cve") or "Unknown"
        record = {
            "id": _stable_hash(["cisa_kev", cve_id]),
            "source": "cisa_kev",
            "tier": "background_knowledge",
            "cve_id": cve_id,
            "vendor": entry.get("vendorProject") or "Unknown",
            "product": entry.get("product") or "Unknown",
            "vulnerability_name": entry.get("vulnerabilityName") or "Unknown",
            "date_added": entry.get("dateAdded") or "Unknown",
            "due_date": entry.get("dueDate") or "Unknown",
            "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse") or "Unknown",
            "short_description": entry.get("shortDescription") or "N/A",
            "required_action": entry.get("requiredAction") or "N/A",
        }
        output.append(record)
    return output


def _parse_nvd(raw: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(raw)
    except Exception:
        return []
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, list):
        return []
    output: List[Dict[str, Any]] = []
    for item in vulnerabilities:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or "Unknown"
        metrics = cve.get("metrics") or {}
        record = {
            "id": _stable_hash(["nvd_cve", cve_id]),
            "source": "nvd_cve",
            "tier": "background_knowledge",
            "cve_id": cve_id,
            "published": cve.get("published") or "Unknown",
            "last_modified": cve.get("lastModified") or "Unknown",
            "descriptions": cve.get("descriptions") or [],
            "metrics": metrics,
        }
        output.append(record)
    return output


def _parse_generic_cve(raw: str, source: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if isinstance(data, dict):
        entries = data.get("items") or data.get("cves") or data.get("data") or []
    else:
        entries = data
    if not isinstance(entries, list):
        return []
    output: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cve") or entry.get("cve_id") or entry.get("id") or "Unknown"
        record = {
            "id": _stable_hash([source, cve_id]),
            "source": source,
            "tier": "background_knowledge",
            "cve_id": cve_id,
            "published": entry.get("published") or entry.get("date") or "Unknown",
            "description": entry.get("description") or entry.get("summary") or "N/A",
            "raw": entry,
        }
        output.append(record)
    return output


def _load_tool_fingerprints(path: Path) -> List[Dict[str, Any]]:
    if not path.exists() or not path.is_dir():
        return []
    output: List[Dict[str, Any]] = []
    for file in sorted(path.iterdir()):
        if file.suffix not in {".json", ".jsonl"}:
            continue
        try:
            if file.suffix == ".jsonl":
                lines = file.read_text(encoding="utf-8").splitlines()
                entries = [json.loads(line) for line in lines if line.strip()]
            else:
                entries = json.loads(file.read_text(encoding="utf-8"))
                if isinstance(entries, dict):
                    entries = [entries]
            if not isinstance(entries, list):
                continue
        except Exception:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            tool = entry.get("tool") or entry.get("name") or "Unknown"
            indicator = entry.get("indicator") or entry.get("value") or "Unknown"
            record = {
                "id": _stable_hash(["tool_fingerprint", tool, indicator]),
                "source": "tool_fingerprints",
                "tier": "background_knowledge",
                "tool": tool,
                "indicator": indicator,
                "indicator_type": entry.get("indicator_type") or "unknown",
                "raw": entry,
            }
            output.append(record)
    return output


def ingest_all() -> Dict[str, int]:
    _ensure_dirs()
    cfg = _load_config()

    primary = _ingest_ransomware_live(cfg)
    infra = []
    infra.extend(_ingest_abuse_ch(cfg))
    infra.extend(_ingest_c2_intel(cfg))
    reputation = _ingest_reputation(cfg)
    background = _ingest_background(cfg)

    _write_jsonl(PRIMARY_DIR / "ransomware_live.jsonl", primary)
    _write_jsonl(INFRA_DIR / "infrastructure_intel.jsonl", infra)
    _write_jsonl(REPUTATION_DIR / "reputation_context.jsonl", reputation)
    _write_jsonl(BACKGROUND_DIR / "background_knowledge.jsonl", background)

    summary = {
        "primary_incidents": len(primary),
        "infrastructure_intel": len(infra),
        "reputation_context": len(reputation),
        "background_knowledge": len(background),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    (DATA_DIR / "ingest_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
