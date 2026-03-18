from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
import hashlib
import os
import time
import urllib.request
import urllib.error

@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes = b""
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    from_cache: bool = False

def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]

class Fetcher:
    """
    Minimal dependency fetcher:
    - polite user agent
    - per-host RPS externalized by caller (simple)
    - conditional GET using ETag/Last-Modified cached on disk
    """
    def __init__(self, cache_dir: str, user_agent: str, timeout_s: int = 20, max_bytes: int = 4_000_000):
        self.cache_dir = cache_dir
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        os.makedirs(cache_dir, exist_ok=True)

    def _meta_path(self, url: str) -> str:
        return os.path.join(self.cache_dir, f"{_hash_url(url)}.meta")

    def _body_path(self, url: str) -> str:
        return os.path.join(self.cache_dir, f"{_hash_url(url)}.body")

    def _load_meta(self, url: str) -> Dict[str, str]:
        p = self._meta_path(url)
        if not os.path.exists(p):
            return {}
        out = {}
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
        return out

    def _save_meta(self, url: str, etag: Optional[str], last_modified: Optional[str]) -> None:
        p = self._meta_path(url)
        with open(p, "w", encoding="utf-8") as f:
            if etag:
                f.write(f"ETag: {etag}\n")
            if last_modified:
                f.write(f"Last-Modified: {last_modified}\n")

    def get(self, url: str) -> FetchResult:
        meta = self._load_meta(url)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        }
        if meta.get("ETag"):
            headers["If-None-Match"] = meta["ETag"]
        if meta.get("Last-Modified"):
            headers["If-Modified-Since"] = meta["Last-Modified"]

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                status = getattr(resp, "status", 200)
                data = resp.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    data = data[:self.max_bytes]
                etag = resp.headers.get("ETag")
                lm = resp.headers.get("Last-Modified")
                self._save_meta(url, etag, lm)
                with open(self._body_path(url), "wb") as f:
                    f.write(data)
                return FetchResult(url=url, status=status, content=data, etag=etag, last_modified=lm, from_cache=False)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                bp = self._body_path(url)
                data = b""
                if os.path.exists(bp):
                    with open(bp, "rb") as f:
                        data = f.read(self.max_bytes)
                return FetchResult(url=url, status=304, content=data, etag=meta.get("ETag"), last_modified=meta.get("Last-Modified"), from_cache=True)
            return FetchResult(url=url, status=e.code, content=b"")
        except Exception:
            return FetchResult(url=url, status=0, content=b"")
