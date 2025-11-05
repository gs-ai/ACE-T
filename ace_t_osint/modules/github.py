"""
GitHub OSINT Module
-------------------

Production-grade OSINT collector for public GitHub intelligence (repos, commits, code search, gists).

Capabilities:
- Query public GitHub REST endpoints without auth (optional token supported)
- Detect trigger matches and security leak heuristics across metadata and content
- Persist structured alerts and evidence JSON with raw API responses
- Maintain state (last seen IDs and per-trigger trend velocity)
- Structured logging to logs/github_monitor.log and logs/github_errors.log

Environment:
- GITHUB_TOKEN (optional)
- POLL_INTERVAL (default 180)
- MAX_RESULTS (default 50)
- SAVE_EVIDENCE (default 1)

CLI:
- --interval, --max-results, --debug, --simulate
"""
from __future__ import annotations

import difflib
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

import requests

from ace_t_osint.utils import utils


# ----------------------------
# Constants and Regex Heuristics
# ----------------------------

GITHUB_API = "https://api.github.com"
ENDPOINTS = {
    "gists": f"{GITHUB_API}/gists/public",
    "events": f"{GITHUB_API}/events",
    # Search endpoints (q must be appended), keep small per-cycle usage
    "search_code": f"{GITHUB_API}/search/code",
    "search_commits": f"{GITHUB_API}/search/commits",
}

RX_API_KEYS = re.compile(r"(?i)(api[_-]?key|token|secret|passwd|password)[\"'=: ]+([A-Za-z0-9_\-]{10,})")
RX_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----")
RX_INDICATORS = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
RX_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

TECH_TERMS = {"python", "docker", "aws", "gcp", "azure", "esp32", "arduino", "kubernetes", "terraform", "ansible"}


# ----------------------------
# Helpers and IO
# ----------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _logs_setup(debug: bool = False) -> Tuple[logging.Logger, logging.Logger]:
    logs_dir = _repo_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("github_monitor")
    err_logger = logging.getLogger("github_errors")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        err_logger.setLevel(logging.WARNING)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(logs_dir / "github_monitor.log")
        eh = logging.FileHandler(logs_dir / "github_errors.log")
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
    return _repo_root() / "state" / "github_state.json"


def _load_state() -> Dict[str, Any]:
    p = _state_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        return {"last_seen": {}, "trends": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"last_seen": {}, "trends": {}}
        # ensure keys
        data.setdefault("last_seen", {})
        data.setdefault("trends", {})
        return data
    except Exception:
        return {"last_seen": {}, "trends": {}}


def _save_state(state: Dict[str, Any]) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _evidence_dirs() -> Tuple[Path, Path]:
    base = _repo_root() / "evidence"
    parsed = base / "github"
    raw = base / "raw"
    parsed.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=True)
    return parsed, raw


def _now_iso() -> str:
    # Prefer utils.datetime if present for consistency with other modules
    return utils.datetime.utcnow().isoformat() if hasattr(utils, "datetime") else datetime.now(timezone.utc).isoformat()


def _github_headers(token: Optional[str], extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ACE-T/1.0 (+https://github.com/gs-ai/ACE-T)",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    if extra:
        h.update(extra)
    return h


def _backoff_sleep(attempt: int) -> None:
    time.sleep(min(30.0, (2 ** attempt)) + random.uniform(0.1, 0.5))


def fetch_github_data(url: str, token: Optional[str], logger: logging.Logger, attempts: int = 3, params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
    last_err = None
    for i in range(attempts):
        try:
            r = requests.get(url, headers=_github_headers(token), params=params, timeout=20)
            # Rate limiting awareness
            if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
                reset = r.headers.get("X-RateLimit-Reset")
                if reset:
                    try:
                        reset_ts = int(reset)
                        sleep_for = max(0, reset_ts - int(time.time()) + 1)
                        logger.info(f"GitHub rate-limit reached. Sleeping {sleep_for}s until reset.")
                        time.sleep(min(sleep_for, 60))  # cap sleep to avoid long blocks
                    except Exception:
                        _backoff_sleep(i)
                else:
                    _backoff_sleep(i)
                continue
            r.raise_for_status()
            return r
        except Exception as e:
            last_err = e
            logger.warning(f"fetch-error {url}: {e}")
            _backoff_sleep(i)
    logger.warning(f"Failed to GET {url}: {last_err}")
    return None


# ----------------------------
# Trigger & Entity Detection
# ----------------------------

def _normalize_triggers(triggers: Any) -> List[Dict[str, Any]]:
    try:
        return utils.normalize_triggers(triggers)
    except Exception:
        # Best-effort minimal normalization
        out = []
        if isinstance(triggers, list):
            for t in triggers:
                if isinstance(t, str):
                    out.append({"include": [t], "pattern": t, "severity": "medium", "trigger_id": t, "context": ""})
                elif isinstance(t, dict):
                    inc = []
                    if t.get("include") and isinstance(t.get("include"), list):
                        inc = t.get("include")
                    elif t.get("pattern"):
                        inc = [t["pattern"]]
                    out.append({
                        "include": inc,
                        "pattern": inc[0] if inc else None,
                        "severity": str(t.get("severity", "medium")),
                        "trigger_id": t.get("trigger_id", t.get("id", "unknown")),
                        "context": t.get("context", t.get("description", "")),
                        "regex": t.get("regex", False),
                        "fuzzy": t.get("fuzzy", False),
                    })
        return out


def _match_text(text: str, trig: Dict[str, Any]) -> bool:
    if not text:
        return False
    include: List[str] = []
    inc = trig.get("include")
    if isinstance(inc, list):
        include = [s for s in inc if isinstance(s, str)]
    elif isinstance(trig.get("pattern"), str):
        include = [str(trig.get("pattern"))]
    use_regex = bool(trig.get("regex"))
    use_fuzzy = bool(trig.get("fuzzy"))
    tl = text.lower()
    for pat in include:
        if not isinstance(pat, str) or not pat:
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
            if use_fuzzy:
                # Compare against tokens to capture obfuscations / typos
                for tok in set(re.findall(r"[A-Za-z0-9_\-]{4,}", text)):
                    if difflib.SequenceMatcher(None, pat.lower(), tok.lower()).ratio() >= 0.9:
                        return True
    return False


def detect_entities(text: str) -> Dict[str, Any]:
    if not text:
        return {"organizations": [], "technologies": [], "indicators": {}, "emails": [], "keywords": []}
    orgs: List[str] = []
    tech: List[str] = []
    emails = list(set(RX_EMAIL.findall(text)))
    indicators = list(set(RX_INDICATORS.findall(text)))
    # naive organizations: GitHub org paths or capitalized tokens that look like org names
    for m in re.finditer(r"\b([A-Z][A-Za-z0-9_-]{2,})\b", text):
        orgs.append(m.group(1))
    for t in TECH_TERMS:
        if re.search(rf"\b{re.escape(t)}\b", text, re.IGNORECASE):
            tech.append(t)
    kws = [w.lower() for w in re.findall(r"\b\w{4,}\b", text) if w.lower() not in TECH_TERMS]
    return {
        "organizations": sorted(set(orgs))[:50],
        "technologies": sorted(set(tech))[:50],
        "indicators": {"generic": sorted(set(indicators))[:100]},
        "emails": emails[:50],
        "keywords": sorted(set(kws))[:100],
    }


def leak_score(text: str) -> Tuple[int, List[str]]:
    score = 0
    hits: List[str] = []
    if RX_PRIVATE_KEY.search(text or ""):
        score += 5
        hits.append("private_key")
    for m in RX_API_KEYS.finditer(text or ""):
        score += 2
        hits.append("api_key")
    for m in RX_EMAIL.finditer(text or ""):
        score += 1
        hits.append("email")
    for m in RX_INDICATORS.finditer(text or ""):
        score += 1
        hits.append("indicator")
    return score, sorted(set(hits))


def severity_with_score(base: str, score: int) -> str:
    levels = ["low", "medium", "high"]
    b = base.lower() if base else "medium"
    idx = levels.index(b) if b in levels else 1
    if score >= 6:
        idx = 2
    elif score >= 3:
        idx = max(idx, 1)
    return levels[idx]


# ----------------------------
# Parsing of GitHub API payloads
# ----------------------------

def _gist_records(data: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for g in data or []:
        gid = g.get("id")
        desc = g.get("description") or ""
        owner = (g.get("owner") or {}).get("login") or "Anonymous"
        html_url = g.get("html_url")
        files = g.get("files") or {}
        filenames = list(files.keys())
        content_snippets: List[str] = []
        for f in files.values():
            # Public gist file content is often included for small files
            c = f.get("content")
            if c:
                content_snippets.append(str(c)[:2000])
        yield {
            "type": "gist",
            "id": gid,
            "owner": owner,
            "description": desc,
            "url": html_url,
            "filenames": filenames,
            "content": "\n".join(content_snippets)[:4000],
        }


def _event_records(data: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for e in data or []:
        et = e.get("type")
        if et != "PushEvent":
            continue
        repo = (e.get("repo") or {}).get("name")
        actor = (e.get("actor") or {}).get("login") or "Anonymous"
        payload = e.get("payload") or {}
        commits = payload.get("commits") or []
        for c in commits:
            msg = c.get("message") or ""
            url = c.get("url") or (e.get("repo") or {}).get("url")
            yield {
                "type": "commit",
                "id": c.get("sha"),
                "owner": actor,
                "repo": repo,
                "message": msg,
                "url": url,
                "content": msg,
            }


def _code_search_records(data: Dict[str, Any], limit: int = 50) -> Iterable[Dict[str, Any]]:
    items = (data or {}).get("items", [])
    for item in items[:limit]:
        repo = (item.get("repository") or {}).get("full_name")
        path = item.get("path")
        html_url = item.get("html_url")
        # text_matches requires media type. We may not have it unauth; rely on name/path
        content = " ".join(filter(None, [item.get("name"), path, repo]))
        yield {
            "type": "code",
            "id": item.get("sha") or uuid.uuid4().hex,
            "owner": repo.split("/")[0] if repo else "Unknown",
            "repo": repo,
            "file": path,
            "url": html_url,
            "content": content,
        }


def _commit_search_records(data: Dict[str, Any], limit: int = 50) -> Iterable[Dict[str, Any]]:
    items = (data or {}).get("items", [])
    for item in items[:limit]:
        commit = item.get("commit") or {}
        repo = (item.get("repository") or {}).get("full_name")
        author = (commit.get("author") or {}).get("name") or "Anonymous"
        message = commit.get("message") or ""
        html_url = item.get("html_url")
        yield {
            "type": "commit",
            "id": (item.get("sha") or uuid.uuid4().hex),
            "owner": repo.split("/")[0] if repo else "Unknown",
            "repo": repo,
            "message": message,
            "url": html_url,
            "content": message,
        }


# ----------------------------
# Evidence & Alerts
# ----------------------------

def _save_raw(category: str, data: Any) -> Path:
    parsed_dir, raw_dir = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = raw_dir / f"github_{category}_{ts}.json"
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        # Fallback to minimal write
        path.write_text(json.dumps({"error": "serialize"}), encoding="utf-8")
    return path


def _save_evidence(alert: Dict[str, Any], save: bool = True) -> Optional[Path]:
    parsed_dir, _ = _evidence_dirs()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tid = re.sub(r"[^A-Za-z0-9_-]", "_", str(alert.get("trigger_id", "unknown")))
    path = parsed_dir / f"{ts}_{tid}.json"
    if not save:
        return None
    path.write_text(json.dumps(alert, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _build_alert(rec: Dict[str, Any], trig: Dict[str, Any], trend: Dict[str, Any], leaks: Tuple[int, List[str]]) -> Dict[str, Any]:
    leak_val, leak_hits = leaks
    sev = severity_with_score(trig.get("severity", "medium"), leak_val)
    snippet = (rec.get("content") or rec.get("message") or rec.get("description") or "")[:800]
    author = rec.get("owner") or "Anonymous"
    repo = rec.get("repo") or ""
    file_name = rec.get("file") or (rec.get("filenames") or [None])[0]
    alert = {
        "id": str(uuid.uuid4()),
        "source": "github",
        "pattern": trig.get("pattern") or (trig.get("include") or [""])[0],
        "matched_repo": repo,
        "file": file_name,
        "commit_id": rec.get("id"),
        "author": author,
        "pushed_at": _now_iso(),
        "url": rec.get("url"),
        "source_type": rec.get("type"),
        "risk_vector": "public code exposure",
        "severity": sev,
        "detected_at": _now_iso(),
        "extracted_snippet": snippet,
        "entities": detect_entities(" ".join([snippet, repo or "", file_name or ""])),
        "trend_velocity": trend,
        "classification": "Confidential",
        "leak_hits": leak_hits,
        "trigger_id": trig.get("trigger_id", "unknown"),
    }
    return alert


# ----------------------------
# Main monitor logic
# ----------------------------

def monitor_github(triggers, interval: Optional[int] = None, max_results: Optional[int] = None, debug: bool = False, simulate: bool = False) -> None:
    print("[github] monitor_github started")
    logger, err_logger = _logs_setup(debug)
    interval = int(os.getenv("POLL_INTERVAL", interval or 180))
    max_results = int(os.getenv("MAX_RESULTS", max_results or 50))
    save_evidence = str(os.getenv("SAVE_EVIDENCE", "1")).lower() in ("1", "true", "yes", "on")
    token = os.getenv("GITHUB_TOKEN")

    state = _load_state()
    norm_triggers = _normalize_triggers(triggers)

    def update_trend(tid: str, new_hits: int) -> Dict[str, Any]:
        trends = state.setdefault("trends", {})
        prev = trends.get(tid, 0)
        now_val = int(prev) + int(new_hits)
        trends[tid] = now_val
        _save_state(state)
        inc = 0
        if prev and new_hits:
            try:
                inc = int(round(((now_val - prev) / max(prev, 1)) * 100))
            except Exception:
                inc = 0
        return {"new_hits": int(new_hits), "previous_hits": int(prev), "percent_increase": inc, "current_total": now_val}

    def already_seen(kind: str, rec_id: str) -> bool:
        if not rec_id:
            return False
        last = state.setdefault("last_seen", {}).setdefault(kind, [])
        if rec_id in last:
            return True
        last.append(rec_id)
        # cap memory
        if len(last) > 500:
            del last[:-500]
        _save_state(state)
        return False

    while True:
        cycle_hits = 0
        try:
            # SIMULATION MODE: load saved sample data
            sample_payload: Optional[Dict[str, Any]] = None
            if simulate:
                sample_path = _repo_root() / "tests" / "data" / "github_sample.json"
                if sample_path.exists():
                    try:
                        sample_payload = json.loads(sample_path.read_text(encoding="utf-8"))
                    except Exception as e:
                        err_logger.error(f"Failed reading simulation data: {e}")

            # 1) Public gists
            if sample_payload is not None:
                gists_data = sample_payload.get("gists", [])
            else:
                r = fetch_github_data(ENDPOINTS["gists"], token, logger, params={"per_page": max_results})
                gists_data = r.json() if r is not None else []
            _save_raw("gists", gists_data)
            for rec in _gist_records(gists_data):
                if not rec.get("id") or already_seen("gist", rec["id"]):
                    continue
                for trig in norm_triggers:
                    if _match_text(" ".join([rec.get("description", ""), " ".join(rec.get("filenames", [])), rec.get("content", "")]), trig):
                        score, hits = leak_score(" ".join([rec.get("description", ""), rec.get("content", "")]))
                        trend = update_trend(trig.get("trigger_id", "unknown"), 1)
                        alert = _build_alert(rec, trig, trend, (score, hits))
                        ev_path = _save_evidence(alert, save_evidence)
                        meta = {
                            "title": f"GitHub gist match: {rec.get('url')}",
                            "content": rec.get("content", "")[:4000],
                            "url": rec.get("url"),
                            "source": "github",
                            "source_url": rec.get("url"),
                            "detected_at": _now_iso(),
                            "entities": alert.get("entities"),
                            "trend_velocity": trend,
                            "classification": "Confidential",
                            "evidence_path": str(ev_path) if ev_path else None,
                        }
                        utils.log_signal(
                            source="github",
                            signal_type="triggered_content",
                            severity=alert["severity"],
                            trigger_id=alert["trigger_id"],
                            context=f"GitHub gist {rec.get('url')} matched trigger {trig.get('pattern')}",
                            extra_data=meta,
                        )
                        logger.warning(f"ALERT gist {rec.get('id')} | trigger={trig.get('trigger_id')}")
                        cycle_hits += 1

            # 2) Public events (push commit messages)
            if sample_payload is not None:
                events_data = sample_payload.get("events", [])
            else:
                r = fetch_github_data(ENDPOINTS["events"], token, logger, params={"per_page": max_results})
                events_data = r.json() if r is not None else []
            _save_raw("events", events_data)
            for rec in _event_records(events_data):
                if not rec.get("id") or already_seen("commit", rec["id"]):
                    continue
                for trig in norm_triggers:
                    if _match_text(" ".join([rec.get("message", ""), rec.get("repo", "")]), trig):
                        score, hits = leak_score(rec.get("message", ""))
                        trend = update_trend(trig.get("trigger_id", "unknown"), 1)
                        alert = _build_alert(rec, trig, trend, (score, hits))
                        ev_path = _save_evidence(alert, save_evidence)
                        meta = {
                            "title": f"GitHub commit match: {rec.get('repo')}@{rec.get('id')}",
                            "content": rec.get("message", "")[:4000],
                            "url": rec.get("url"),
                            "source": "github",
                            "source_url": rec.get("url"),
                            "detected_at": _now_iso(),
                            "entities": alert.get("entities"),
                            "trend_velocity": trend,
                            "classification": "Confidential",
                            "evidence_path": str(ev_path) if ev_path else None,
                        }
                        utils.log_signal(
                            source="github",
                            signal_type="triggered_content",
                            severity=alert["severity"],
                            trigger_id=alert["trigger_id"],
                            context=f"GitHub commit {rec.get('id')} matched trigger {trig.get('pattern')}",
                            extra_data=meta,
                        )
                        logger.warning(f"ALERT commit {rec.get('id')} | trigger={trig.get('trigger_id')}")
                        cycle_hits += 1

            # 3) Code search (pattern as query)
            if norm_triggers:
                # Only a few queries per cycle to avoid rate bloat
                for trig in norm_triggers[:3]:
                    q = trig.get("pattern") or (trig.get("include") or [""])[0]
                    if not q:
                        continue
                    params = {"q": q, "per_page": max_results}
                    if sample_payload is not None:
                        code_data = sample_payload.get("code_search", {"items": []})
                    else:
                        r = fetch_github_data(ENDPOINTS["search_code"], token, logger, params=params)
                        code_data = r.json() if r is not None else {"items": []}
                    _save_raw("code_search", code_data)
                    for rec in _code_search_records(code_data, limit=max_results):
                        if not rec.get("id") or already_seen("code", rec["id"]):
                            continue
                        # We already searched by trig pattern; we can treat as match
                        score, hits = leak_score(" ".join([rec.get("content", ""), rec.get("file", ""), rec.get("repo", "")]))
                        trend = update_trend(trig.get("trigger_id", "unknown"), 1)
                        alert = _build_alert(rec, trig, trend, (score, hits))
                        ev_path = _save_evidence(alert, save_evidence)
                        meta = {
                            "title": f"GitHub code search match: {rec.get('repo')}/{rec.get('file')}",
                            "content": rec.get("content", "")[:4000],
                            "url": rec.get("url"),
                            "source": "github",
                            "source_url": rec.get("url"),
                            "detected_at": _now_iso(),
                            "entities": alert.get("entities"),
                            "trend_velocity": trend,
                            "classification": "Confidential",
                            "evidence_path": str(ev_path) if ev_path else None,
                        }
                        utils.log_signal(
                            source="github",
                            signal_type="triggered_content",
                            severity=alert["severity"],
                            trigger_id=alert["trigger_id"],
                            context=f"GitHub code search result matched trigger {trig.get('pattern')}",
                            extra_data=meta,
                        )
                        logger.warning(f"ALERT code {rec.get('id')} | trigger={trig.get('trigger_id')}")
                        cycle_hits += 1

            # 4) Commit search (pattern as query)
            if norm_triggers:
                for trig in norm_triggers[:2]:  # extra small to preserve rate
                    q = trig.get("pattern") or (trig.get("include") or [""])[0]
                    if not q:
                        continue
                    params = {"q": q, "per_page": max_results}
                    headers_extra = {"Accept": "application/vnd.github.cloak-preview+json"}
                    if sample_payload is not None:
                        commit_data = sample_payload.get("commit_search", {"items": []})
                    else:
                        r = fetch_github_data(ENDPOINTS["search_commits"], token, logger, params=params)
                        commit_data = r.json() if r is not None else {"items": []}
                    _save_raw("commit_search", commit_data)
                    for rec in _commit_search_records(commit_data, limit=max_results):
                        if not rec.get("id") or already_seen("commit_search", rec["id"]):
                            continue
                        score, hits = leak_score(rec.get("message", ""))
                        trend = update_trend(trig.get("trigger_id", "unknown"), 1)
                        alert = _build_alert(rec, trig, trend, (score, hits))
                        ev_path = _save_evidence(alert, save_evidence)
                        meta = {
                            "title": f"GitHub commit search match: {rec.get('repo')}@{rec.get('id')}",
                            "content": rec.get("message", "")[:4000],
                            "url": rec.get("url"),
                            "source": "github",
                            "source_url": rec.get("url"),
                            "detected_at": _now_iso(),
                            "entities": alert.get("entities"),
                            "trend_velocity": trend,
                            "classification": "Confidential",
                            "evidence_path": str(ev_path) if ev_path else None,
                        }
                        utils.log_signal(
                            source="github",
                            signal_type="triggered_content",
                            severity=alert["severity"],
                            trigger_id=alert["trigger_id"],
                            context=f"GitHub commit search result matched trigger {trig.get('pattern')}",
                            extra_data=meta,
                        )
                        logger.warning(f"ALERT commit-search {rec.get('id')} | trigger={trig.get('trigger_id')}")
                        cycle_hits += 1

        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt: stopping monitor_github")
            break
        except Exception as e:
            err_logger.error(f"github-cycle-error: {e}")

        logger.info(f"Cycle complete | hits={cycle_hits} | next in {interval}s")
        time.sleep(interval)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GitHub OSINT monitor")
    parser.add_argument("--interval", type=int, default=180)
    parser.add_argument("--max-results", type=int, default=50)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    # Minimal demo trigger (search for 'api_key')
    demo_triggers = [
        {"pattern": "api_key", "severity": "medium", "trigger_id": "github_api_key", "context": "secret_keywords", "fuzzy": True}
    ]
    monitor_github(demo_triggers, interval=args.interval, max_results=args.max_results, debug=args.debug, simulate=args.simulate)
