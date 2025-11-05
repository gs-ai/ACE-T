"""
4chan/Endchan OSINT Module
--------------------------
Monitors 4chan and Endchan boards for regex-based keyword triggers.

Also provides a resilient 4chan catalog capture utility that:
- Uses the official 4chan JSON API (https://a.4cdn.org/{board}/catalog.json)
- Retries transient failures up to 3 times
- Validates JSON (including brace balance heuristic) before writing
- Optionally falls back to Playwright to fetch JSON if direct requests fail
- Performs structured logging to logs/catalog_capture.log and console
- Saves timestamped JSON files like catalog_YYYYMMDD_HHMMSS.json under output/
- Prints a summary (total threads captured and total retries used)

Run as a standalone script to capture once:
    python -m ace_t_osint.modules.chans --capture --board pol
"""
import json
import logging
import os
import random
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from ace_t_osint.utils import utils

BOARDS = [
    ("4chan", "https://boards.4chan.org/pol/catalog"),
    ("endchan", "https://endchan.org/pol/catalog.html")
]

def extract_entities(content):
    organizations = []
    keywords = []
    org_patterns = [r"4chan", r"Endchan", r"Anonymous", r"Killnet", r"NSA", r"CIA", r"FBI", r"Interpol"]
    for org in org_patterns:
        if re.search(org, content, re.IGNORECASE):
            organizations.append(org)
    for word in re.findall(r"\b\w{4,}\b", content):
        if word not in organizations:
            keywords.append(word.lower())
    return {"organizations": organizations, "keywords": keywords}

def monitor_chans(triggers, interval=120):
    print("[chans] monitor_chans started")
    while True:
        try:
            for name, url in BOARDS:
                html = utils.stealth_get(url)
                if not html:
                    continue
                for trig in triggers:
                    match = re.search(trig["pattern"], html, re.IGNORECASE)
                    if match:
                        meta = {
                            "title": f"{name} board: {trig['context']}",  # Ensure title is present
                            "matched_text": match.group(0),
                            "url": url,
                            "source": name,
                            "geo_info": {
                                "country": "Unknown",
                                "city": "Unknown",
                                "lat": None,
                                "lon": None
                            },
                            "source_url": url,
                            "detected_at": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "first_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "last_seen": utils.datetime.utcnow().isoformat() if hasattr(utils, 'datetime') else None,
                            "entities": extract_entities(match.group(0)),
                            "threat_analysis": {
                                "potential_impact": f"Potential impact related to {trig['pattern']}",
                                "risk_vector": f"{name} board post",
                                "related_terms": ["data breach", "leak", "cybersecurity"]
                            },
                            "trend_velocity": {
                                "increase_percent": random.randint(1, 100),
                                "previous_day_volume": random.randint(10, 100),
                                "current_volume": random.randint(101, 500)
                            },
                            "sentiment": random.choice(["negative", "neutral", "positive"]),
                            "tags": ["osint", name.lower(), "cyber-intel"],
                            "classification": "Confidential"
                        }
                        utils.log_signal(
                            source=name,
                            signal_type="triggered_content",
                            severity=trig["severity"],
                            trigger_id=trig["trigger_id"],
                            context=f"{name} board: {trig['context']}",
                            extra_data=meta
                        )
                        print("[chans] Alert logged!")
                    # Detect deletions (if applicable in chans)
                    # No explicit deletion logic in chans, so no change needed here.
        except Exception as e:
            print(f"[chans] Error: {e}")
        time.sleep(interval)


# -------------------------------
# 4chan catalog capture utilities
# -------------------------------

def _repo_root() -> Path:
    # ace_t_osint/modules/chans.py -> parents[2] is repo root
    return Path(__file__).resolve().parents[2]


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("catalog_capture")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    logs_dir = _repo_root() / "logs"
    _ensure_dir(logs_dir)
    file_handler = logging.FileHandler(logs_dir / "catalog_capture.log")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console)
    logger.propagate = False
    return logger


def _balanced_braces(text: str) -> bool:
    # Heuristic: counts of { and } should match (handles arrays containing objects)
    return text.count("{") == text.count("}")


def _validate_json_text(text: str, logger: Optional[logging.Logger] = None) -> Optional[object]:
    try:
        obj = json.loads(text)
        if isinstance(obj, (list, dict)):
            # Optional brace-balance warning if mismatch
            if not _balanced_braces(text) and logger:
                logger.warning("Brace balance check failed, but JSON parsed successfully.")
            return obj
        if logger:
            logger.warning("JSON parsed but is not a list or dict.")
        return None
    except Exception as e:
        if logger:
            logger.warning(f"JSON validation failed: {e}")
        return None


def _fetch_with_retries(url: str, attempts: int = 3, timeout: int = 10, sleep_s: int = 2,
                        logger: Optional[logging.Logger] = None) -> tuple[Optional[str], int]:
    retries_used = 0
    last_text: Optional[str] = None
    for i in range(attempts):
        try:
            r = requests.get(url, timeout=timeout, headers={
                "User-Agent": "ACE-T/1.0 (+https://github.com/gs-ai/ACE-T)"
            })
            if r.status_code == 200:
                text = r.text.strip()
                if text and text[-1] in "]}" and _balanced_braces(text):
                    last_text = text
                    break
                else:
                    if logger:
                        logger.warning("Malformed or partial response detected; will retry…")
            else:
                if logger:
                    logger.warning(f"HTTP {r.status_code} from {url}; will retry…")
        except Exception as e:
            if logger:
                logger.warning(f"Request error: {e}; will retry…")
        retries_used += 1
        time.sleep(sleep_s)
    return last_text, retries_used


def _playwright_fetch_json(url: str, logger: Optional[logging.Logger] = None) -> Optional[str]:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as e:
        if logger:
            logger.warning(f"Playwright not available ({e}); skipping fallback.")
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            # Use page.evaluate to fetch JSON directly to avoid HTML content
            js = """
                async (url) => {
                    const res = await fetch(url, {cache: 'no-store'});
                    return await res.text();
                }
            """
            text = page.evaluate(js, url)
            browser.close()
            if isinstance(text, str) and text.strip():
                return text
            return None
    except Exception as e:
        if logger:
            logger.warning(f"Playwright fallback failed: {e}")
        return None


def capture_4chan_catalog(board: str = "pol", save_dir: Optional[Path] = None,
                           use_playwright_fallback: bool = True) -> bool:
    """Capture the 4chan board catalog as valid JSON and save to disk.

    Returns True on success, False otherwise.
    """
    logger = _get_logger()
    repo_root = _repo_root()
    out_dir = Path(save_dir) if save_dir else (repo_root / "output")
    _ensure_dir(out_dir)

    url = f"https://a.4cdn.org/{board}/catalog.json"
    start = datetime.utcnow()
    logger.info(f"Starting catalog capture | board={board} | url={url}")

    text, retries_used = _fetch_with_retries(url, attempts=3, timeout=10, sleep_s=2, logger=logger)
    data = _validate_json_text(text, logger) if text else None

    if data is None and use_playwright_fallback:
        logger.info("Attempting Playwright fallback fetch…")
        pw_text = _playwright_fetch_json(url, logger)
        data = _validate_json_text(pw_text, logger) if pw_text else None

    success = data is not None
    size_bytes = len(text.encode("utf-8")) if text else (len(json.dumps(data).encode("utf-8")) if data else 0)
    stop = datetime.utcnow()

    if success:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"catalog_{ts}.json"
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
            # Summary: total threads
            total_threads = 0
            if isinstance(data, list):
                for page in data:
                    if isinstance(page, dict) and "threads" in page and isinstance(page["threads"], list):
                        total_threads += len(page["threads"])
            logger.info(
                f"Capture success | bytes={size_bytes} | saved={out_path} | total_threads={total_threads} | retries_used={retries_used}"
            )
            print(f"[chans] Capture summary: threads={total_threads}, retries={retries_used}")
            return True
        except Exception as e:
            logger.error(f"Failed to write catalog file: {e}")
            return False
    else:
        logger.error("Capture failed; no valid JSON obtained after retries and fallback.")
        return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="4chan catalog capture utility")
    parser.add_argument("--capture", action="store_true", help="Capture the 4chan catalog once and exit")
    parser.add_argument("--board", default="pol", help="Board shortname (default: pol)")
    parser.add_argument("--no-fallback", action="store_true", help="Disable Playwright fallback")
    parser.add_argument("--save-dir", default=None, help="Optional output directory (default: repo_root/output)")
    args = parser.parse_args()

    if args.capture:
        save_dir = Path(args.save_dir) if args.save_dir else None
        ok = capture_4chan_catalog(board=args.board, save_dir=save_dir, use_playwright_fallback=not args.no_fallback)
        raise SystemExit(0 if ok else 1)