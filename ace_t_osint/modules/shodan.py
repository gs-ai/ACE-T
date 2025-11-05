"""
Shodan / GreyNoise OSINT Module
-------------------------------

Passive-scan intelligence collector correlating Shodan search with GreyNoise classification
to detect mass-scan events, attack infrastructure, and anomalies linked to triggers.

Features:
- Queries Shodan host search for patterns, with HTML scrape fallback without API key
- Queries GreyNoise community API to classify IPs (malicious/benign/unknown)
- Correlates results and computes trend velocity and risk level
- Saves evidence and raw JSON under evidence/shodan and evidence/raw
- Structured logging and state tracking (last seen, volumes, persistent scanners)

Env/CLI:
- SHODAN_API_KEY, GREYNOISE_API_KEY
- --interval (default 300), --max-results (default 100), --save-evidence, --debug
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import urllib.parse

import requests

from ace_t_osint.utils import utils


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _logs_setup(debug: bool = False) -> Tuple[logging.Logger, logging.Logger]:
    logs_dir = _repo_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("shodan_monitor")
    err_logger = logging.getLogger("shodan_errors")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        err_logger.setLevel(logging.WARNING)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(logs_dir / "shodan_monitor.log")
        eh = logging.FileHandler(logs_dir / "shodan_errors.log")
        ch = logging.StreamHandler()
        for h in (fh, ch):
            h.setFormatter(fmt)
            logger.addHandler(h)
        eh.setFormatter(fmt)
        err_logger.addHandler(eh)
        logger.propagate = False
        err_logger.propagate = False
    return logger, err_logger


def _state_path() -> Path:
    return _repo_root() / "state" / "shodan_state.json"


def _load_state() -> Dict[str, Any]:
    p = _state_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        return {"last_seen": {}, "volumes": {}, "ip_counts": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"last_seen": {}, "volumes": {}, "ip_counts": {}}
        data.setdefault("last_seen", {})
        data.setdefault("volumes", {})
        data.setdefault("ip_counts", {})
        return data
    except Exception:
        return {"last_seen": {}, "volumes": {}, "ip_counts": {}}


def _save_state(state: Dict[str, Any]) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _evidence_dirs() -> Tuple[Path, Path]:
    base = _repo_root() / "evidence"
    shodan_dir = base / "shodan"
    raw_dir = base / "raw"
    shodan_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    return shodan_dir, raw_dir


def _save_raw(prefix: str, payload: Any) -> Path:
    _, raw_dir = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    p = raw_dir / f"{prefix}_{ts}.json"
    try:
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        p.write_text(json.dumps({"error": "serialize"}), encoding="utf-8")
    return p


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_evidence(filename_key: str, evidence: Dict[str, Any], save: bool = True) -> Optional[Path]:
    shodan_dir, _ = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", filename_key)[:60]
    p = shodan_dir / f"{ts}_{safe}.json"
    if not save:
        return None
    p.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    # Append to manifest
    sha = _sha256_path(p)
    manifest = shodan_dir / "manifest.jsonl"
    with open(manifest, "a", encoding="utf-8") as mf:
        mf.write(json.dumps({"path": str(p), "sha256": sha, "ts": ts}) + "\n")
    return p


def _headers() -> Dict[str, str]:
    return {
        "User-Agent": "ACE-T/1.0 (+https://github.com/gs-ai/ACE-T)",
        "Accept": "application/json",
    }


def _backoff(attempt: int) -> None:
    time.sleep(min(30, (2 ** attempt)) + random.uniform(0.1, 0.4))


def fetch_shodan_search(pattern: str, api_key: Optional[str], max_results: int, logger: logging.Logger) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if api_key:
        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": api_key, "query": pattern}
        for attempt in range(3):
            try:
                r = requests.get(url, params=params, headers=_headers(), timeout=30)
                if r.status_code in (429, 503):
                    logger.info(f"shodan rate {r.status_code}; backoff")
                    _backoff(attempt)
                    continue
                r.raise_for_status()
                data = r.json()
                matches = data.get("matches", [])
                for m in matches[:max_results]:
                    results.append(m)
                _save_raw("shodan_search", data)
                break
            except Exception as e:
                logger.info(f"shodan-fetch-error: {e}")
                _backoff(attempt)
    else:
        # HTML scrape fallback (best-effort)
        try:
            html = requests.get(f"https://www.shodan.io/search?query={urllib.parse.quote_plus(pattern)}", headers={"User-Agent": "Mozilla/5.0"}, timeout=30).text
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", html)
            for ip in list(dict.fromkeys(ips))[:max_results]:
                results.append({"ip_str": ip, "org": None, "location": {}, "data": "", "port": None, "vulns": []})
            _save_raw("shodan_scrape", {"pattern": pattern, "ips": results})
        except Exception:
            pass
    return results


def fetch_greynoise(ip: str, api_key: Optional[str], logger: logging.Logger) -> Dict[str, Any]:
    if not api_key:
        return {"classification": "unknown"}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
        "key": api_key,
    }
    for attempt in range(3):
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code in (429, 503):
                _backoff(attempt)
                continue
            r.raise_for_status()
            data = r.json()
            _save_raw("greynoise_ip", {"ip": ip, "data": data})
            return data
        except Exception as e:
            logger.info(f"greynoise-fetch-error {ip}: {e}")
            _backoff(attempt)
    return {"classification": "unknown"}


def _normalize_triggers(triggers: Any) -> List[Dict[str, Any]]:
    try:
        return utils.normalize_triggers(triggers)
    except Exception:
        out = []
        if isinstance(triggers, list):
            for t in triggers:
                if isinstance(t, str):
                    out.append({"include": [t], "pattern": t, "severity": "medium", "trigger_id": t, "context": ""})
                elif isinstance(t, dict):
                    inc = []
                    incl = t.get("include")
                    if isinstance(incl, list):
                        inc = [s for s in incl if isinstance(s, str)]
                    elif isinstance(t.get("pattern"), str):
                        inc = [t.get("pattern")]
                    out.append({
                        "include": inc,
                        "pattern": inc[0] if inc else None,
                        "severity": str(t.get("severity", "medium")),
                        "trigger_id": t.get("trigger_id", t.get("id", "unknown")),
                        "context": t.get("context", t.get("description", "")),
                        "regex": t.get("regex", False),
                    })
        return out


def _match(text: str, trig: Dict[str, Any]) -> bool:
    include: List[str] = []
    inc = trig.get("include")
    if isinstance(inc, list):
        include = [s for s in inc if isinstance(s, str)]
    elif isinstance(trig.get("pattern"), str):
        include = [str(trig.get("pattern"))]
    use_regex = bool(trig.get("regex"))
    tl = (text or "").lower()
    for pat in include:
        if not pat:
            continue
        if use_regex:
            try:
                if re.search(pat, text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        else:
            if pat.lower() in tl:
                return True
    return False


def _risk_level(base: str, text: str, greynoise_cls: str) -> str:
    base = (base or "medium").lower()
    lv = ["low", "medium", "high"]
    idx = lv.index(base) if base in lv else 1
    t = (text or "").lower()
    if greynoise_cls == "malicious" or any(k in t for k in ("ransomware", "botnet", "exploit")):
        idx = 2
    elif any(k in t for k in ("scan", "scanner", "mass-scan")):
        idx = max(idx, 1)
    return lv[idx]


def _extract_entities_from_match(m: Dict[str, Any]) -> Dict[str, Any]:
    org = m.get("org") or (m.get("asn") or {})
    org_name = org if isinstance(org, str) else (org.get("name") if isinstance(org, dict) else None)
    loc = m.get("location") or {}
    country = loc.get("country_code") or loc.get("country_name")
    banners = []
    if isinstance(m.get("data"), str):
        banners.append(m.get("data"))
    entities = {
        "organizations": [x for x in [org_name] if x],
        "keywords": list({w.lower() for w in re.findall(r"[A-Za-z0-9_-]{4,}", " ".join(banners or []))})[:100],
        "countries": [country] if country else [],
    }
    return entities


def monitor_shodan(triggers, interval: int = 300, max_results: int = 100, save_evidence: bool = True, debug: bool = False) -> None:
    print("[shodan] monitor_shodan started")
    logger, err_logger = _logs_setup(debug)
    interval = int(os.getenv("POLL_INTERVAL", interval))
    max_results = int(os.getenv("MAX_RESULTS", max_results))
    save_evidence = str(os.getenv("SAVE_EVIDENCE", "1")).lower() in ("1", "true", "yes", "on") if save_evidence is None else save_evidence

    shodan_key = os.getenv("SHODAN_API_KEY")
    greynoise_key = os.getenv("GREYNOISE_API_KEY")

    state = _load_state()
    norm_triggers = _normalize_triggers(triggers)

    def trend_for(tid: str, increment: int) -> Dict[str, Any]:
        vols = state.setdefault("volumes", {})
        prev = int(vols.get(tid, 0))
        cur = prev + int(increment)
        vols[tid] = cur
        _save_state(state)
        inc_pct = 0
        if prev:
            try:
                inc_pct = int(round(((cur - prev) / max(prev, 1)) * 100))
            except Exception:
                inc_pct = 0
        return {"increase_percent": inc_pct, "previous": prev, "current": cur}

    def already_seen(tid: str, ip: str) -> bool:
        last = state.setdefault("last_seen", {}).setdefault(tid, [])
        if ip in last:
            return True
        last.append(ip)
        if len(last) > 1000:
            del last[:-1000]
        _save_state(state)
        return False

    def increment_ip(ip: str) -> int:
        ip_counts = state.setdefault("ip_counts", {})
        c = int(ip_counts.get(ip, 0)) + 1
        ip_counts[ip] = c
        _save_state(state)
        return c

    while True:
        cycle_hits = 0
        try:
            logger.info(f"Cycle start | triggers={len(norm_triggers)} | max_results={max_results}")
            for trig in norm_triggers:
                pat = trig.get("pattern") or (trig.get("include") or [""])[0]
                if not pat:
                    continue
                time.sleep(random.uniform(0.8, 1.2))  # respect Shodan ~1 rps
                matches = fetch_shodan_search(pat, shodan_key, max_results, logger)
                for m in matches:
                    ip = m.get("ip_str") or m.get("ip")
                    if not ip:
                        continue
                    # Normalize banner text for matching
                    banner_text = " ".join([
                        str(m.get("data", "")), str(m.get("hostnames", "")), str(m.get("org", "")), str(m.get("tags", "")),
                        " ".join(m.get("vulns", []) if isinstance(m.get("vulns"), list) else (list(m.get("vulns", {}).keys()) if isinstance(m.get("vulns"), dict) else []))
                    ])
                    if not _match(banner_text, trig):
                        # still consider if IP provided by scrape fallback
                        if not shodan_key:
                            pass
                        else:
                            continue
                    if already_seen(trig.get("trigger_id", "unknown"), ip):
                        continue
                    g = fetch_greynoise(ip, greynoise_key, logger)
                    g_cls = g.get("classification") or ("malicious" if g.get("noise") else "unknown")
                    entities = _extract_entities_from_match(m)
                    risk = _risk_level(trig.get("severity", "medium"), banner_text, g_cls)
                    trend = trend_for(trig.get("trigger_id", "unknown"), 1)
                    seen_count = increment_ip(ip)
                    if seen_count >= 3:
                        risk = "high"

                    ports = []
                    if isinstance(m.get("port"), int):
                        ports = [m.get("port")]
                    elif isinstance(m.get("ports"), list):
                        ports = [p for p in (m.get("ports") or []) if isinstance(p, int)]
                    vulns = m.get("vulns")
                    if isinstance(vulns, dict):
                        vulns = list(vulns.keys())
                    elif not isinstance(vulns, list):
                        vulns = []
                    loc = m.get("location") or {}
                    country = loc.get("country_code") or loc.get("country_name")
                    org = m.get("org")

                    evidence = {
                        "id": str(uuid.uuid4()),
                        "source": "shodan",
                        "pattern": pat,
                        "ip": ip,
                        "org": org,
                        "country": country,
                        "ports": ports,
                        "vulns": vulns,
                        "greynoise_classification": g_cls,
                        "seen": datetime.now(timezone.utc).isoformat(),
                        "risk_level": risk,
                        "trend_velocity": trend,
                        "entities": entities,
                        "classification": "Confidential",
                    }
                    ev_path = _save_evidence(ip or pat, evidence, save=save_evidence)
                    meta = {
                        "title": f"Shodan match {ip}",
                        "content": str(m.get("data", ""))[:4000],
                        "url": None,
                        "source": "shodan",
                        "source_url": None,
                        "detected_at": evidence["seen"],
                        "entities": entities,
                        "trend_velocity": trend,
                        "classification": "Confidential",
                        "evidence_path": str(ev_path) if ev_path else None,
                        "geo_info": {"country": country, "city": None},
                    }
                    utils.log_signal(
                        source="shodan",
                        signal_type="triggered_content",
                        severity=risk,
                        trigger_id=trig.get("trigger_id", "unknown"),
                        context=f"IP {ip} matched pattern {pat}",
                        extra_data=meta,
                    )
                    logger.warning(f"ALERT {ip} | pattern={pat} | risk={risk} | gnoise={g_cls}")
                    cycle_hits += 1

        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt: stopping monitor_shodan")
            break
        except Exception as e:
            err_logger.error(f"shodan-cycle-error: {e}")

        logger.info(f"Cycle complete | hits={cycle_hits} | next in {interval}s")
        time.sleep(interval)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shodan/GreyNoise OSINT monitor")
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--max-results", type=int, default=100)
    parser.add_argument("--save-evidence", type=str, default="1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    demo_triggers = [
        {"pattern": "ransomware", "severity": "high", "trigger_id": "shodan_ransom", "context": "ransomware_keywords"},
        {"pattern": "port:3389", "severity": "medium", "trigger_id": "shodan_rdp", "context": "rdp_scans"},
    ]
    monitor_shodan(
        demo_triggers,
        interval=args.interval,
        max_results=args.max_results,
        save_evidence=(str(args.save_evidence).lower() in ("1", "true", "yes", "on")),
        debug=args.debug,
    )
