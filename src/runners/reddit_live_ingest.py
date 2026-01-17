from __future__ import annotations

import hashlib
import json
import time
import random
import os
import re
import requests
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    import praw
    PRAW_AVAILABLE = True
except ImportError:
    PRAW_AVAILABLE = False
    praw = None

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

from adapters.reddit_adapter import adapt_reddit_items
from adapters.emit_graph import emit_graph
from db.alert_writer import write_alerts

# Configuration
CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config.yml"
SEEN_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "reddit_seen_posts.json"

# Reddit API configuration
REDDIT_CONFIG = None
REDDIT_INSTANCE = None

def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    global REDDIT_CONFIG
    if REDDIT_CONFIG is not None:
        return REDDIT_CONFIG

    REDDIT_CONFIG = {}
    if YAML_AVAILABLE and CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}
                REDDIT_CONFIG = config.get('reddit', {})
        except Exception as e:
            print(f"[reddit] Failed to load config: {e}")

    return REDDIT_CONFIG

def get_reddit_instance():
    """Get or create authenticated Reddit instance.

    Environment variables `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, and
    `REDDIT_USER_AGENT` are honored and take precedence over values in
    `config.yml`. This allows temporary, non-persistent credential use.
    """
    global REDDIT_INSTANCE
    if REDDIT_INSTANCE is not None:
        return REDDIT_INSTANCE

    if not PRAW_AVAILABLE:
        print("[reddit] PRAW not available, using fallback method")
        return None

    config = load_config()
    # Prefer environment variables for credentials so secrets are not committed
    client_id = os.getenv("REDDIT_CLIENT_ID") or config.get('client_id', '').strip()
    client_secret = os.getenv("REDDIT_CLIENT_SECRET") or config.get('client_secret', '').strip()
    user_agent = os.getenv("REDDIT_USER_AGENT") or config.get('user_agent', 'ACE-T:v2.0.0 (by /u/unknown)')

    if not client_id or not client_secret:
        print("[reddit] Reddit API credentials not configured in env or config.yml, using fallback method")
        print("[reddit] Set REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET env vars or update config.yml for authenticated access")
        return None

    try:
        REDDIT_INSTANCE = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent=user_agent
        )
        print("[reddit] Authenticated Reddit API initialized")
        return REDDIT_INSTANCE
    except Exception as e:
        print(f"[reddit] Failed to initialize Reddit API: {e}, using fallback method")
        return None

# Use a realistic User-Agent that identifies as a browser to avoid blocks
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

BASE = "https://www.reddit.com"
MAX_RETRIES = 3
BASE_DELAY = 2.0  # seconds between requests
MAX_BACKOFF = 30.0  # max exponential backoff
SEEN_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "reddit_seen_posts.json"
HTML_FALLBACK_STATE: Dict[str, Dict[str, float | int]] = {}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "y"}


def _fallback_settings() -> Dict[str, Any]:
    config = load_config()
    return {
        "base_delay": _env_float("ACE_T_REDDIT_FALLBACK_BASE_DELAY", float(config.get("fallback_base_delay", BASE_DELAY))),
        "max_retries": _env_int("ACE_T_REDDIT_FALLBACK_MAX_RETRIES", int(config.get("fallback_max_retries", MAX_RETRIES))),
        "html_enabled": _env_bool("ACE_T_REDDIT_FALLBACK_HTML_ENABLED", bool(config.get("fallback_html_enabled", True))),
        "html_cooldown": _env_float("ACE_T_REDDIT_FALLBACK_HTML_COOLDOWN", float(config.get("fallback_html_cooldown", 900.0))),
        "html_max_attempts": _env_int("ACE_T_REDDIT_FALLBACK_HTML_MAX_ATTEMPTS", int(config.get("fallback_html_max_attempts", 1))),
    }


def _should_try_html(subreddit: str, max_attempts: int, cooldown: float) -> bool:
    if max_attempts <= 0:
        return False
    key = str(subreddit or "").strip().lower()
    now = time.time()
    state = HTML_FALLBACK_STATE.get(key)
    if state:
        last = float(state.get("last", 0.0))
        count = int(state.get("count", 0))
        if cooldown > 0 and (now - last) < cooldown and count >= max_attempts:
            return False
        if cooldown > 0 and (now - last) >= cooldown:
            state["count"] = 0
    else:
        HTML_FALLBACK_STATE[key] = {"last": 0.0, "count": 0}
    return True


def _record_html_attempt(subreddit: str, success: bool) -> None:
    key = str(subreddit or "").strip().lower()
    state = HTML_FALLBACK_STATE.setdefault(key, {"last": 0.0, "count": 0})
    state["last"] = time.time()
    if success:
        state["count"] = 0
    else:
        state["count"] = int(state.get("count", 0)) + 1


def fetch_json_fallback(url: str, max_retries: int = MAX_RETRIES, base_delay: float = BASE_DELAY, retry_count: int = 0) -> Optional[Any]:
    """
    Fetch JSON from URL with exponential backoff retry logic.
    Returns None if all retries fail (403 blocks).
    """
    try:
        # Add jitter and delay to avoid thundering herd
        jitter = random.uniform(0.8, 1.4)
        if retry_count > 0:
            delay = min(base_delay * (2 ** retry_count) * jitter, MAX_BACKOFF)
            print(f"[reddit] retry {retry_count}, waiting {delay:.1f}s...")
        else:
            delay = base_delay * jitter
        time.sleep(delay)

        r = requests.get(url, headers=HEADERS, timeout=20)

        # Handle rate limiting specifically
        if r.status_code == 429:
            if retry_count < max_retries:
                print(f"[reddit] rate limited (429), retrying...")
                return fetch_json_fallback(url, max_retries, base_delay, retry_count + 1)
            else:
                print(f"[reddit] rate limit exceeded after {max_retries} retries")
                return None

        # Handle blocks (403)
        if r.status_code == 403:
            print(f"[reddit] blocked (403) - Reddit may be blocking automated access")
            print(f"[reddit] Consider using Reddit API with authentication or increasing delays")
            return None

        r.raise_for_status()
        return r.json()

    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, 'status_code', None)
        if retry_count < max_retries and status in [429, 500, 502, 503, 504]:
            print(f"[reddit] HTTP error {status}, retrying...")
            return fetch_json_fallback(url, max_retries, base_delay, retry_count + 1)
        print(f"[reddit] HTTP error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        if retry_count < max_retries:
            print(f"[reddit] request failed: {e}, retrying...")
            return fetch_json_fallback(url, max_retries, base_delay, retry_count + 1)
        print(f"[reddit] request failed after retries: {e}")
        return None


def fetch_posts_html(subreddit: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Fallback HTML scraping of old.reddit.com when JSON/API access is blocked.

    This is a best-effort fallback and may be fragile if Reddit HTML changes.
    """
    url = f"https://old.reddit.com/r/{subreddit}/new/"
    try:
        print(f"[reddit] attempting HTML fallback for r/{subreddit}")
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        html = r.text
        # Parse basic post metadata from the 'thing' elements
        pattern = re.compile(r'<div[^>]*class="thing"[^>]*data-fullname="(t3_[a-z0-9]+)"[^>]*data-author="([^"]*)"[^>]*data-timestamp="([0-9]+)"[^>]*data-url="([^"]*)"[^>]*data-title="([^"]*)"', re.I)
        posts: List[Dict[str, Any]] = []
        for m in pattern.finditer(html):
            fullname, author, ts, url_path, title = m.groups()
            post_id = fullname.split('_', 1)[1]
            try:
                created = int(ts)
                if created > 1_000_000_000_000:
                    created = int(created / 1000)
            except Exception:
                created = int(time.time())
            permalink = url_path if url_path.startswith('http') else f"https://old.reddit.com{url_path}"
            posts.append({
                'id': post_id,
                'title': title,
                'selftext': '',
                'author': author,
                'created_utc': created,
                'url': permalink,
                'permalink': url_path,
                'score': 0,
                'num_comments': 0,
                'subreddit': subreddit,
            })
            if len(posts) >= limit:
                break
        if posts:
            print(f"[reddit] Fetched {len(posts)} posts from r/{subreddit} (HTML fallback)")
        return posts
    except Exception as e:
        print(f"[reddit] HTML fallback failed for r/{subreddit}: {e}")
        return []


def fetch_posts(subreddit: str, limit: int = 25, sort: str = "new", time_filter: str = "day") -> List[Dict[str, Any]]:
    """Fetch posts using authenticated API if available, fallback to JSON API.

    sort: 'new' or 'top'
    time_filter: for 'top' only; values like 'day', 'week', 'month', 'year', 'all'
    """
    reddit = get_reddit_instance()

    # Use authenticated PRAW API if available
    if reddit is not None:
        try:
            subreddit_obj = reddit.subreddit(subreddit)
            posts = []
            if sort == "top":
                # PRAW: subreddit.top(time_filter=..., limit=...)
                for post in subreddit_obj.top(time_filter=time_filter, limit=limit):
                    posts.append({
                        'id': post.id,
                        'title': post.title,
                        'selftext': post.selftext,
                        'author': str(post.author) if post.author else '[deleted]',
                        'created_utc': post.created_utc,
                        'url': post.url,
                        'permalink': post.permalink,
                        'score': post.score,
                        'num_comments': post.num_comments,
                        'subreddit': subreddit
                    })
            else:
                for post in subreddit_obj.new(limit=limit):
                    posts.append({
                        'id': post.id,
                        'title': post.title,
                        'selftext': post.selftext,
                        'author': str(post.author) if post.author else '[deleted]',
                        'created_utc': post.created_utc,
                        'url': post.url,
                        'permalink': post.permalink,
                        'score': post.score,
                        'num_comments': post.num_comments,
                        'subreddit': subreddit
                    })
            print(f"[reddit] Fetched {len(posts)} posts from r/{subreddit} (authenticated, sort={sort}, time_filter={time_filter})")
            return posts
        except Exception as e:
            print(f"[reddit] PRAW failed for r/{subreddit}: {e}, falling back to JSON API")

    # Fallback to JSON API
    fallback = _fallback_settings()
    base_delay = fallback["base_delay"]
    max_retries = fallback["max_retries"]

    if sort == "top":
        url = f"{BASE}/r/{subreddit}/top.json?t={time_filter}&limit={limit}"
    else:
        url = f"{BASE}/r/{subreddit}/new.json?limit={limit}"

    data = fetch_json_fallback(url, max_retries, base_delay)
    if data is None:
        # Try HTML fallback if allowed and not throttled
        if not fallback["html_enabled"]:
            return []
        if not _should_try_html(subreddit, fallback["html_max_attempts"], fallback["html_cooldown"]):
            print(f"[reddit] HTML fallback throttled for r/{subreddit}")
            return []
        html_posts = fetch_posts_html(subreddit, limit)
        _record_html_attempt(subreddit, bool(html_posts))
        if html_posts:
            return html_posts
        return []

    try:
        # JSON structure similar for 'top' and 'new'
        return [c["data"] for c in data["data"]["children"]]
    except (KeyError, TypeError) as e:
        print(f"[reddit] Malformed response for r/{subreddit}: {e}")
        return []


def fetch_comments(subreddit: str, post_id: str) -> List[Dict[str, Any]]:
    """Fetch comments using authenticated API if available, fallback to JSON API."""
    reddit = get_reddit_instance()

    if reddit is not None:
        # Use authenticated PRAW API
        try:
            submission = reddit.submission(id=post_id)
            submission.comments.replace_more(limit=None)  # Load all comments
            comments = []

            def extract_comments(comment_list):
                for comment in comment_list:
                    if hasattr(comment, 'body') and comment.body:
                        comment_data = {
                            'id': comment.id,
                            'body': comment.body,
                            'author': str(comment.author) if comment.author else '[deleted]',
                            'created_utc': comment.created_utc,
                            'parent_id': comment.parent_id,
                            'link_id': comment.link_id,
                            'score': comment.score,
                            'replies': []
                        }
                        comments.append(comment_data)
                        if comment.replies:
                            extract_comments(comment.replies)

            extract_comments(submission.comments)
            print(f"[reddit] Fetched {len(comments)} comments for post {post_id} (authenticated)")
            return comments
        except Exception as e:
            print(f"[reddit] PRAW comments failed for {post_id}: {e}, falling back to JSON API")
            # Fall through to JSON API method

    # Fallback to JSON API method
    fallback = _fallback_settings()
    base_delay = fallback["base_delay"]

    url = f"{BASE}/r/{subreddit}/comments/{post_id}.json?limit=500"
    data = fetch_json_fallback(url, base_delay=base_delay)

    if data is None:
        return []

    comments = []

    def walk(children):
        for c in children:
            if c.get("kind") == "t1":
                d = c["data"]
                comments.append(d)
                if d.get("replies"):
                    walk(d["replies"]["data"]["children"])

    try:
        if len(data) > 1:
            walk(data[1]["data"]["children"])
    except (KeyError, TypeError, IndexError) as e:
        print(f"[reddit] Malformed comment response for {post_id}: {e}")
        return []

    return comments


def load_seen() -> set[str]:
    if SEEN_PATH.exists():
        try:
            return set(json.loads(SEEN_PATH.read_text()))
        except Exception:
            return set()
    return set()


def save_seen(ids: set[str]) -> None:
    SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEEN_PATH.write_text(json.dumps(sorted(ids)), encoding="utf-8")


def normalize_post(post: Dict[str, Any], subreddit: str) -> Dict[str, Any]:
    return {
        "id": post["id"],
        "post_id": post["id"],
        "title": post.get("title"),
        "body": post.get("selftext"),
        "author": post.get("author"),
        "created_utc": post.get("created_utc"),
        "url": post.get("url"),
        "permalink": BASE + post.get("permalink", ""),
        "source": "reddit",
        "subsource": subreddit.lower(),
        "post_url": BASE + post.get("permalink", ""),
        "score": post.get("score"),
        "num_comments": post.get("num_comments"),
    }


def normalize_comment(comment: Dict[str, Any], post_id: str, subreddit: str) -> Dict[str, Any]:
    comment_id = comment.get("id")
    permalink = comment.get("permalink")
    comment_url = permalink if isinstance(permalink, str) and permalink.startswith("http") else (BASE + permalink if permalink else None)
    post_url = f"{BASE}/r/{subreddit}/comments/{post_id}/"
    return {
        "id": f"{post_id}:{comment_id}",
        "comment_id": comment_id,
        "body": comment.get("body"),
        "author": comment.get("author"),
        "created_utc": comment.get("created_utc"),
        "parent_id": comment.get("parent_id"),
        "link_id": post_id,
        "source": "reddit",
        "subsource": subreddit.lower(),
        "post_url": post_url,
        "comment_url": comment_url,
    }


def get_existing_elements() -> tuple[list[dict], list[dict]]:
    graph_path = Path(__file__).resolve().parent.parent.parent / "data" / "graph_data.json"
    if not graph_path.exists():
        return [], []
    try:
        els = json.loads(graph_path.read_text())
        nodes = [e.get("data", {}) for e in els if not {"source", "target"} <= set((e.get("data") or {}).keys())]
        edges = [e.get("data", {}) for e in els if {"source", "target"} <= set((e.get("data") or {}).keys())]
        return nodes, edges
    except Exception:
        return [], []


def ingest_posts(subreddit: str = "Intelligence", limit: int | None = None, sort: str = "top", time_filter: str = "day") -> None:
    """Ingest posts for the subreddit.

    - limit: number of posts to fetch (if None, reads ACE_T_REDDIT_MAX_POSTS or defaults to 100)
    - sort: 'top' or 'new' (default 'top')
    - time_filter: timeframe for 'top' (e.g., 'day','week','month')
    """
    cfg_limit = None
    try:
        env_limit = os.getenv("ACE_T_REDDIT_MAX_POSTS") or os.getenv("REDDIT_MAX_POSTS")
        if env_limit:
            cfg_limit = int(env_limit)
    except Exception:
        cfg_limit = None
    if limit is None:
        limit = cfg_limit if cfg_limit and cfg_limit > 0 else 100

    print(f"[reddit] ingesting posts r/{subreddit} (limit={limit} sort={sort} time_filter={time_filter})")
    seen = load_seen()
    posts = fetch_posts(subreddit, limit=limit, sort=sort, time_filter=time_filter)

    # Handle blocked/failed requests
    if not posts:
        print(f"[reddit] no posts fetched for r/{subreddit} (may be blocked or no new content)")
        return

    retention_days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    cutoff = time.time() - (retention_days * 86400)
    new_posts = []
    for p in posts:
        pid = p.get("id")
        ts = float(p.get("created_utc") or time.time())
        if ts < cutoff:
            continue
        if pid and pid not in seen:
            new_posts.append(p)
    if not new_posts:
        print(f"[reddit] no new posts for r/{subreddit}")
        return

    items: List[Dict[str, Any]] = [normalize_post(p, subreddit) for p in new_posts]
    seen.update(p["id"] for p in new_posts)
    save_seen(seen)

    alert_rows = []
    for item in items:
        payload = {
            "title": item.get("title"),
            "content": item.get("body"),
            "url": item.get("post_url"),
            "post_url": item.get("post_url"),
            "reddit_id": item.get("id"),
            "post_id": item.get("post_id") or item.get("id"),
            "subreddit": item.get("subsource"),
            "author": item.get("author"),
            "score": item.get("score"),
            "num_comments": item.get("num_comments"),
        }
        alert_rows.append(
            {
                "content_hash": hashlib.sha256(f"reddit:{item.get('id')}".encode()).hexdigest(),
                "source_name": "reddit",
                "detected_at": item.get("created_utc"),
                "payload": payload,
            }
        )
    if alert_rows:
        try:
            write_alerts(alert_rows)
        except Exception as e:
            print(f"[reddit] db write failed: {e}")

    nodes, edges = adapt_reddit_items(items)
    if os.getenv("ACE_T_PIPELINE_MODE", "").strip().lower() not in {"1", "true", "yes"}:
        existing_nodes, existing_edges = get_existing_elements()
        emit_graph(existing_nodes + [n["data"] for n in nodes], existing_edges + [e["data"] for e in edges])
    print(f"[reddit] posts emitted nodes={len(nodes)} edges={len(edges)}")


def ingest_comments(subreddit: str = "Intelligence", limit_posts: int = None) -> None:
    """Ingest comments for the subreddit. limit_posts controls how many recent posts to fetch comments for.
    If limit_posts is None it reads ACE_T_REDDIT_COMMENT_POSTS or defaults to 10."""
    try:
        env_c = os.getenv("ACE_T_REDDIT_COMMENT_POSTS") or os.getenv("REDDIT_COMMENT_POSTS")
        cfg_limit = int(env_c) if env_c else None
    except Exception:
        cfg_limit = None
    limit_posts = limit_posts if (limit_posts is not None and limit_posts > 0) else (cfg_limit if cfg_limit else 10)

    print(f"[reddit] ingesting comments r/{subreddit} (limit_posts={limit_posts})")
    seen = load_seen()
    # Fetch recent posts (use default 'new' sort to find recent post IDs quickly)
    posts = fetch_posts(subreddit, limit=limit_posts * 2, sort="new")
    recent_posts = [p for p in posts if p.get("id") in seen][:limit_posts]
    if not recent_posts:
        print(f"[reddit] no recent posts for comments in r/{subreddit}")
        return

    items: List[Dict[str, Any]] = []
    for p in recent_posts:
        post_id = p["id"]
        try:
            comments = fetch_comments(subreddit, post_id)
            for c in comments:
                items.append(normalize_comment(c, post_id, subreddit))
        except Exception as e:
            print(f"[reddit] comments failed for {post_id}: {e}")
        time.sleep(1.0)

    if not items:
        print(f"[reddit] no new comments fetched r/{subreddit}")
        return

    retention_days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    cutoff = time.time() - (retention_days * 86400)
    items = [i for i in items if float(i.get("created_utc") or time.time()) >= cutoff]
    if not items:
        print(f"[reddit] no recent comments within retention r/{subreddit}")
        return

    alert_rows = []
    for item in items:
        payload = {
            "title": f"Comment on {item.get('link_id')}",
            "content": item.get("body"),
            "url": item.get("comment_url") or item.get("post_url"),
            "post_url": item.get("post_url"),
            "comment_url": item.get("comment_url"),
            "reddit_id": item.get("id"),
            "comment_id": item.get("comment_id"),
            "post_id": item.get("link_id"),
            "subreddit": item.get("subsource"),
            "author": item.get("author"),
            "parent_id": item.get("parent_id"),
            "link_id": item.get("link_id"),
        }
        alert_rows.append(
            {
                "content_hash": hashlib.sha256(f"reddit-comment:{item.get('id')}".encode()).hexdigest(),
                "source_name": "reddit",
                "detected_at": item.get("created_utc"),
                "payload": payload,
            }
        )
    if alert_rows:
        try:
            write_alerts(alert_rows)
        except Exception as e:
            print(f"[reddit] db write failed: {e}")

    nodes, edges = adapt_reddit_items(items)
    if os.getenv("ACE_T_PIPELINE_MODE", "").strip().lower() not in {"1", "true", "yes"}:
        existing_nodes, existing_edges = get_existing_elements()
        emit_graph(existing_nodes + [n["data"] for n in nodes], existing_edges + [e["data"] for e in edges])
    print(f"[reddit] comments emitted nodes={len(nodes)} edges={len(edges)}")


if __name__ == "__main__":
    ingest_posts()
