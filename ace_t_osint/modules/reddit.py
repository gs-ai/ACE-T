from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from ace_t_osint.utils import utils


REDDIT_BASE = "https://www.reddit.com"
DEFAULT_SUBREDDITS = [
    "osint", "cybersecurity", "netsec", "privacy", "hacking", "malware",
    "blueteamsec", "intel", "threatintel", "geopolitics", "worldnews",
    "Infosec", "Technology", "opsec", "DataHoarder", "sysadmin",
    "AskNetsec", "exploitdev", "security", "computersecurity", "networking"
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _logs_setup(debug: bool = False) -> Tuple[logging.Logger, logging.Logger]:
    logs_dir = _repo_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("reddit_monitor")
    err_logger = logging.getLogger("reddit_errors")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        err_logger.setLevel(logging.WARNING)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(logs_dir / "reddit_monitor.log")
        eh = logging.FileHandler(logs_dir / "reddit_errors.log")
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
    return _repo_root() / "state" / "reddit_state.json"


def _load_state() -> Dict[str, Any]:
    p = _state_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        return {"seen": {}, "volumes": {}, "sentiment": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"seen": {}, "volumes": {}, "sentiment": {}}
        data.setdefault("seen", {})
        data.setdefault("volumes", {})
        data.setdefault("sentiment", {})
        return data
    except Exception:
        return {"seen": {}, "volumes": {}, "sentiment": {}}


def _save_state(state: Dict[str, Any]) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _headers() -> Dict[str, str]:
    ua = random.choice(utils.STEALTH_UAS) if hasattr(utils, "STEALTH_UAS") else "Mozilla/5.0 (ACE-T OSINT)"
    return {"User-Agent": ua, "Accept": "application/json"}


def _extract_entities(text: str) -> Dict[str, Any]:
    if not text:
        return {"organizations": [], "keywords": [], "technologies": [], "countries": []}
    organizations: List[str] = []
    keywords: List[str] = []
    technologies: List[str] = []
    countries: List[str] = []

    org_patterns = [r"NSA", r"CIA", r"FBI", r"Interpol", r"Anonymous", r"Killnet", r"NATO", r"FSB", r"GRU"]
    tech_terms = ["AI", "ChatGPT", "PyTorch", "Docker", "Kubernetes", "AWS", "ESP32", "Malware", "Ransomware"]
    country_terms = [
        "USA", "Russia", "China", "Iran", "Ukraine", "Germany", "France", "UK", "India", "Brazil", "Japan"
    ]

    for org in org_patterns:
        if re.search(rf"\b{org}\b", text, re.IGNORECASE):
            organizations.append(org)
    for t in tech_terms:
        if re.search(rf"\b{re.escape(t)}\b", text, re.IGNORECASE):
            technologies.append(t)
    for c in country_terms:
        if re.search(rf"\b{re.escape(c)}\b", text, re.IGNORECASE):
            countries.append(c)

    for word in re.findall(r"\b\w{4,}\b", text):
        wl = word.lower()
        if wl not in {x.lower() for x in organizations}:
            keywords.append(wl)

    return {
        "organizations": sorted(set(organizations))[:50],
        "technologies": sorted(set(technologies))[:50],
        "countries": sorted(set(countries))[:50],
        "keywords": sorted(set(keywords))[:200],
    }


POSITIVE = ["good", "success", "safe", "positive", "win", "fixed", "resolved"]
NEGATIVE = ["bad", "fail", "danger", "negative", "alert", "threat", "breach", "leak"]


def _sentiment(text: str) -> str:
    tl = (text or "").lower()
    if any(w in tl for w in NEGATIVE):
        return "negative"
    if any(w in tl for w in POSITIVE):
        return "positive"
    return "neutral"


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _evidence_dirs() -> Tuple[Path, Path]:
    base = _repo_root() / "evidence"
    reddit_dir = base / "reddit"
    raw_dir = base / "raw"
    reddit_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    return reddit_dir, raw_dir


def _save_raw(sub: str, post_id: str, payload: Any) -> Path:
    _, raw_dir = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    p = raw_dir / f"reddit_{sub}_{post_id or 'batch'}_{ts}.json"
    try:
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        p.write_text(json.dumps({"error": "serialize"}), encoding="utf-8")
    return p


def _save_evidence(sub: str, post_id: str, evidence: Dict[str, Any], save: bool = True) -> Optional[Path]:
    reddit_dir, _ = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    p = reddit_dir / f"{ts}_{sub}_{post_id}.json"
    if not save:
        return None
    p.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    # Append to manifest
    sha = _sha256_path(p)
    manifest = reddit_dir / "manifest.jsonl"
    with open(manifest, "a", encoding="utf-8") as mf:
        mf.write(json.dumps({"path": str(p), "sha256": sha, "ts": ts}) + "\n")
    return p


def _cleanup_old(days: int = 7) -> None:
    reddit_dir, raw_dir = _evidence_dirs()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    for folder in (reddit_dir, raw_dir):
        for fp in folder.glob("*.json"):
            try:
                mtime = datetime.fromtimestamp(fp.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    fp.unlink(missing_ok=True)
            except Exception:
                pass


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


def _match(content: str, trig: Dict[str, Any]) -> bool:
    include: List[str] = []
    inc = trig.get("include")
    if isinstance(inc, list):
        include = [s for s in inc if isinstance(s, str)]
    elif isinstance(trig.get("pattern"), str):
        include = [str(trig.get("pattern"))]
    use_regex = bool(trig.get("regex"))
    tl = (content or "").lower()
    for pat in include:
        if not pat:
            continue
        if use_regex:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    return True
            except re.error:
                continue
        else:
            if pat.lower() in tl:
                return True
    return False


def _severity_for_keywords(base: str, text: str) -> str:
    base = (base or "medium").lower()
    lv = ["low", "medium", "high"]
    idx = lv.index(base) if base in lv else 1
    t = (text or "").lower()
    if any(k in t for k in ("breach", "leak", "ransomware", "0day", "zero-day")):
        idx = 2
    return lv[idx]


def _fetch_subreddit(sub: str, limit: int, logger: logging.Logger, use_tor: bool = False) -> Optional[Dict[str, Any]]:
    url = f"{REDDIT_BASE}/r/{sub}/new.json?limit={int(limit)}"
    proxies = {"http": utils.TOR_SOCKS, "https": utils.TOR_SOCKS} if use_tor else None
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=_headers(), timeout=20, proxies=proxies)
            if resp.status_code in (429, 503):
                sleep_for = min(60, (2 ** attempt) + random.uniform(0.2, 0.8))
                logger.info(f"rate/backoff {sub} {resp.status_code}; sleeping {sleep_for:.1f}s")
                time.sleep(sleep_for)
                continue
            if resp.status_code != 200:
                logger.info(f"non-200 {sub}: {resp.status_code}")
                # Attempt alternate sources or cache
                return _fetch_subreddit_alt(sub, limit, logger) or _read_cached_subreddit(sub, limit, logger)
            data = resp.json()
            if isinstance(data, dict):
                _write_cache(sub, data)
            return data
        except Exception as e:
            logger.info(f"fetch-error {sub}: {e}")
            time.sleep((2 ** attempt) + random.uniform(0.1, 0.3))
    # Final fallback
    return _fetch_subreddit_alt(sub, limit, logger) or _read_cached_subreddit(sub, limit, logger)


def _cache_dir() -> Path:
    d = _repo_root() / "data" / "reddit_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_path(sub: str) -> Path:
    return _cache_dir() / f"{sub}_new.json"


def _write_cache(sub: str, payload: Dict[str, Any]) -> None:
    try:
        _cache_path(sub).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _read_cached_subreddit(sub: str, limit: int, logger: logging.Logger) -> Optional[Dict[str, Any]]:
    p = _cache_path(sub)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        # Cap children length to limit
        if isinstance(data, dict):
            children = (data.get("data") or {}).get("children", [])
            if children:
                data["data"]["children"] = children[:limit]
        logger.info(f"using cached subreddit data for r/{sub}")
        return data
    except Exception:
        return None


def _pushshift_url(sub: str, size: int) -> str:
    # Pushshift-like endpoint; availability may vary over time
    return f"https://api.pushshift.io/reddit/search/submission/?subreddit={sub}&size={int(size)}&sort=desc"


def _fetch_subreddit_alt(sub: str, limit: int, logger: logging.Logger) -> Optional[Dict[str, Any]]:
    fallback = os.getenv("REDDIT_FALLBACK", "auto").lower()
    if fallback in ("none", "off", "0"):
        return None
    # Try Pushshift-like API if allowed or auto
    if fallback in ("pushshift", "auto"):
        try:
            r = requests.get(_pushshift_url(sub, limit), headers=_headers(), timeout=20)
            if r.status_code == 200:
                js = r.json()
                items = js.get("data") or []
                # Transform into Reddit-style children structure
                children = []
                for it in items[:limit]:
                    pid = it.get("id") or ""
                    title = it.get("title") or ""
                    body = it.get("selftext") or ""
                    author = it.get("author") or "u/unknown"
                    score = int(it.get("score", 0))
                    created_utc = it.get("created_utc")
                    permalink = it.get("permalink") or it.get("full_link") or f"/r/{sub}/comments/{pid}/_"
                    children.append({
                        "data": {
                            "id": pid,
                            "title": title,
                            "selftext": body,
                            "author": author,
                            "score": score,
                            "created_utc": created_utc,
                            "permalink": permalink,
                            "removed_by_category": it.get("removed_by_category"),
                        }
                    })
                out = {"data": {"children": children}}
                logger.info(f"pushshift-fallback used for r/{sub} ({len(children)} items)")
                _write_cache(sub, out)
                return out
        except Exception as e:
            logger.info(f"pushshift-fallback error r/{sub}: {e}")
    # As a last resort, attempt cache
    return _read_cached_subreddit(sub, limit, logger)


def monitor_reddit(triggers, interval: int = 180, max_posts: int = 50, subreddits_file: Optional[str] = None,
                   save_evidence: bool = True, debug: bool = False) -> None:
    print("[reddit] monitor_reddit started")
    logger, err_logger = _logs_setup(debug)
    # Load config from env if provided
    interval = int(os.getenv("POLL_INTERVAL", interval))
    max_posts = int(os.getenv("MAX_POSTS", max_posts))
    save_evidence = str(os.getenv("SAVE_EVIDENCE", "1")).lower() in ("1", "true", "yes", "on") if save_evidence is None else save_evidence
    use_tor = str(os.getenv("REDDIT_USE_TOR", "0")).lower() in ("1", "true", "yes", "on")

    # Load subreddit list
    subs: List[str] = []
    if subreddits_file and Path(subreddits_file).exists():
        try:
            text = Path(subreddits_file).read_text(encoding="utf-8")
            subs = [ln.strip().strip("/") for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        except Exception as e:
            logger.info(f"could-not-read subreddits file: {e}")
    if not subs:
        subs = DEFAULT_SUBREDDITS

    state = _load_state()
    norm_triggers = _normalize_triggers(triggers)

    def trend_for(sub: str, increment: int) -> Dict[str, Any]:
        vols = state.setdefault("volumes", {})
        prev = int(vols.get(sub, 0))
        cur = prev + int(increment)
        vols[sub] = cur
        _save_state(state)
        inc_pct = 0
        if prev:
            try:
                inc_pct = int(round(((cur - prev) / max(prev, 1)) * 100))
            except Exception:
                inc_pct = 0
        return {"increase_percent": inc_pct, "prev_volume": prev, "current_volume": cur}

    def record_sentiment(sub: str, post_id: str, value: str) -> Optional[str]:
        s = state.setdefault("sentiment", {}).setdefault(sub, {})
        prev = s.get(post_id)
        if value:
            s[post_id] = value
            _save_state(state)
        return prev

    while True:
        cycle_hits = 0
        try:
            logger.info(f"Cycle start | subs={len(subs)} | max_posts={max_posts}")
            for sub in subs:
                # jitter between subs
                time.sleep(random.uniform(2.0, 6.0))
                data = _fetch_subreddit(sub, max_posts, logger, use_tor=use_tor)
                if not data or not isinstance(data, dict):
                    continue
                children = (data.get("data") or {}).get("children", [])
                for child in children:
                    post = child.get("data") or {}
                    pid = post.get("id")
                    if not pid:
                        continue
                    title = post.get("title", "")
                    body = post.get("selftext", "") or ""
                    author = post.get("author", "u/unknown")
                    score = int(post.get("score", 0))
                    created_utc = post.get("created_utc")
                    permalink = post.get("permalink", "")
                    removed_by = post.get("removed_by_category")
                    url = f"https://reddit.com{permalink}" if permalink else f"https://reddit.com/{pid}"
                    sentiment = _sentiment(f"{title}\n{body}")

                    # Detect deletion/removal
                    deleted = bool(removed_by) or body.strip() in ("[deleted]", "[removed]")

                    # Normalize triggers and match
                    for trig in norm_triggers:
                        if _match(f"{title}\n{body}", trig):
                            sev = _severity_for_keywords(trig.get("severity", "medium"), f"{title} {body}")
                            entities = _extract_entities(f"{title}\n{body}")
                            trend = trend_for(sub, 1)
                            evidence = {
                                "id": str(uuid.uuid4()),
                                "source": "reddit",
                                "subreddit": sub,
                                "post_id": pid,
                                "title": title,
                                "author": author,
                                "score": score,
                                "created_utc": created_utc,
                                "url": url,
                                "sentiment": sentiment,
                                "entities": entities,
                                "trigger_pattern": trig.get("pattern") or (trig.get("include") or [""])[0],
                                "severity": sev,
                                "trend_velocity": trend,
                                "geo_info": {"country": "Unknown", "city": "Unknown"},
                                "tags": ["osint", "reddit", "cyber-intel"],
                                "classification": "Confidential",
                                "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, "datetime") else datetime.now(timezone.utc).isoformat(),
                            }
                            ev_path = _save_evidence(sub, pid, evidence, save=save_evidence)
                            _save_raw(sub, pid, post)
                            meta = {
                                "title": f"Reddit match: r/{sub} {pid}",
                                "content": (title + "\n\n" + body)[:4000],
                                "url": url,
                                "source": "reddit",
                                "source_url": url,
                                "detected_at": evidence["detected_at"],
                                "entities": entities,
                                "trend_velocity": trend,
                                "classification": "Confidential",
                                "evidence_path": str(ev_path) if ev_path else None,
                            }
                            utils.log_signal(
                                source=f"reddit/{sub}",
                                signal_type="triggered_content",
                                severity=sev,
                                trigger_id=trig.get("trigger_id", "unknown"),
                                context=f"Reddit post matched trigger {trig.get('pattern')}",
                                extra_data=meta,
                            )
                            logger.warning(f"ALERT r/{sub} {pid} | trigger={trig.get('trigger_id')}")
                            cycle_hits += 1

                    # Sentiment shift detection
                    prev_sent = record_sentiment(sub, pid, sentiment)
                    if prev_sent and prev_sent != sentiment:
                        utils.log_signal(
                            source=f"reddit/{sub}",
                            signal_type="sentiment_shift",
                            severity="medium",
                            trigger_id=pid,
                            context=f"Post {pid} sentiment changed from {prev_sent} to {sentiment}",
                            extra_data={"title": title, "source_url": url, "sentiment": sentiment},
                        )

                    # Deletion/removal alerts
                    if deleted:
                        trend = trend_for(sub, 1)
                        evidence = {
                            "id": str(uuid.uuid4()),
                            "source": "reddit",
                            "subreddit": sub,
                            "post_id": pid,
                            "title": title,
                            "author": author,
                            "score": score,
                            "created_utc": created_utc,
                            "url": url,
                            "sentiment": sentiment,
                            "entities": _extract_entities(f"{title}\n{body}"),
                            "trigger_pattern": "[deleted]",
                            "severity": "medium",
                            "trend_velocity": trend,
                            "geo_info": {"country": "Unknown", "city": "Unknown"},
                            "tags": ["osint", "reddit", "cyber-intel"],
                            "classification": "Confidential",
                            "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, "datetime") else datetime.now(timezone.utc).isoformat(),
                        }
                        ev_path = _save_evidence(sub, pid, evidence, save=save_evidence)
                        _save_raw(sub, pid, post)
                        utils.log_signal(
                            source=f"reddit/{sub}",
                            signal_type="triggered_content",
                            severity="medium",
                            trigger_id=f"deleted_{pid}",
                            context=f"Reddit post removed/deleted in r/{sub}",
                            extra_data={"title": title, "source_url": url, "evidence_path": str(ev_path) if ev_path else None},
                        )
                        logger.warning(f"ALERT r/{sub} {pid} | removed/deleted")
                        cycle_hits += 1

            _cleanup_old(days=int(os.getenv("EVIDENCE_RETENTION_DAYS", "7")))
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt: stopping monitor_reddit")
            break
        except Exception as e:
            err_logger.error(f"reddit-cycle-error: {e}")

        logger.info(f"Cycle complete | hits={cycle_hits} | next in {interval}s")
        time.sleep(interval)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reddit OSINT monitor")
    parser.add_argument("--interval", type=int, default=180)
    parser.add_argument("--max-posts", type=int, default=50)
    parser.add_argument("--subreddits-file", type=str, default=None)
    parser.add_argument("--save-evidence", type=str, default="1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    demo_triggers = [
        {"pattern": "breach", "severity": "high", "trigger_id": "reddit_breach", "context": "breach_keywords"},
        {"pattern": "leak", "severity": "medium", "trigger_id": "reddit_leak", "context": "leak_keywords"},
    ]
    monitor_reddit(
        demo_triggers,
        interval=args.interval,
        max_posts=args.max_posts,
        subreddits_file=args.subreddits_file,
        save_evidence=(str(args.save_evidence).lower() in ("1", "true", "yes", "on")),
        debug=args.debug,
    )
