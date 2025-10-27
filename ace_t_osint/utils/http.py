import asyncio
import contextlib
import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

# Try to import aiohttp at runtime. The previous pattern using TYPE_CHECKING
# left `aiohttp` set to None during execution which disabled network fetching
# even when aiohttp was installed. Use a runtime try/except to detect
# availability instead.
try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover - runtime may not have aiohttp
    aiohttp = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class RetryPolicy:
    max_attempts: int
    base_delay_seconds: float
    max_delay_seconds: float


@dataclass
class FetchResult:
    url: str
    text: str
    bytes_in: int
    latency_ms: float
    from_cache: bool = False
    cached_at: float | None = None


class HttpCache:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock: asyncio.Lock | None = None
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("http-cache-load-error", extra={"path": str(self._path)})
            return
        if isinstance(data, dict):
            self._store = data

    def _lock_for_loop(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _persist(self) -> None:
        lock = self._lock_for_loop()
        async with lock:
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(self._store), encoding="utf-8")
            tmp_path.replace(self._path)

    async def update(self, url: str, *, etag: str | None, last_modified: str | None, body: str) -> None:
        self._store[url] = {
            "etag": etag,
            "last_modified": last_modified,
            "body": body,
            "cached_at": time.time(),
        }
        await self._persist()

    def get(self, url: str) -> Dict[str, Any] | None:
        return self._store.get(url)

    async def touch(self, url: str) -> None:
        if url in self._store:
            self._store[url]["cached_at"] = time.time()
            await self._persist()


class RateLimiter:
    def __init__(self, rate: float, concurrency: int) -> None:
        self._rate = max(rate, 0.1)
        self._semaphore = asyncio.Semaphore(concurrency)
        self._lock = asyncio.Lock()
        self._last_call: float = 0.0

    async def __aenter__(self) -> None:
        await self._semaphore.acquire()
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = max(0.0, (self._last_call + self._rate) - now)
            if wait:
                await asyncio.sleep(wait)
            self._last_call = asyncio.get_event_loop().time()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._semaphore.release()


class HttpClientFactory:
    def __init__(
        self,
        config: Dict,
        session_timeout: float = 30.0,
    ) -> None:
        self._config = config
        self._session_timeout = session_timeout
        self._session: Optional[Any] = None
        self._rate_limiters: Dict[str, RateLimiter] = {}
        self._network_enabled = aiohttp is not None
        cache_path = self._config.get("http_cache_path", "data/http_cache.json")
        self._cache = HttpCache(cache_path)

    def _get_rate_limiter(self, source: str) -> RateLimiter:
        interval = self._config.get("scrape_interval_seconds", {}).get(source)
        concurrency_cfg = self._config.get("concurrency", {})
        concurrency = concurrency_cfg.get(source, concurrency_cfg.get("default", 4))
        rate = max(interval / max(concurrency, 1), 1.0) if interval else 1.0
        key = f"{source}:{rate}:{concurrency}"
        if key not in self._rate_limiters:
            self._rate_limiters[key] = RateLimiter(rate, concurrency)
        return self._rate_limiters[key]

    def _build_headers(self) -> Dict[str, str]:
        user_agents = self._config.get("user_agents") or [
            "Mozilla/5.0 (compatible; ACE-T OSINT/1.0; +https://example.com)"
        ]
        # Use system time_ns() rather than relying on event loop providing time_ns
        # (some event loop implementations don't expose time_ns()).
        try:
            idx = time.time_ns() % len(user_agents)
        except AttributeError:
            idx = int(time.time() * 1e9) % len(user_agents)
        ua = user_agents[idx]
        return {"User-Agent": ua}

    async def _ensure_session(self) -> Any:
        if not self._network_enabled:
            raise RuntimeError("aiohttp is not available in this environment")
        if self._session and not self._session.closed:
            return self._session
        timeout = aiohttp.ClientTimeout(total=self._session_timeout)
        connector = aiohttp.TCPConnector(limit=64, ttl_dns_cache=300)
        kwargs = dict(timeout=timeout, connector=connector)
        proxy_cfg = self._config.get("tor_or_proxy", {})
        if proxy_cfg.get("enabled") and proxy_cfg.get("url"):
            kwargs["trust_env"] = True
        self._session = aiohttp.ClientSession(headers=self._build_headers(), **kwargs)
        return self._session

    async def close(self) -> None:
        if self._session and not getattr(self._session, "closed", True):
            await self._session.close()

    @contextlib.asynccontextmanager
    async def request(
        self,
        method: str,
        url: str,
        source: str,
        **kwargs,
    ) -> AsyncIterator[Any]:
        if not self._network_enabled:
            raise RuntimeError("Network fetching not available without aiohttp")
        policy_cfg = self._config.get("retry_policy", {})
        policy = RetryPolicy(
            max_attempts=policy_cfg.get("max_attempts", 3),
            base_delay_seconds=policy_cfg.get("base_delay_seconds", 1.0),
            max_delay_seconds=policy_cfg.get("max_delay_seconds", 30.0),
        )
        limiter = self._get_rate_limiter(source)
        attempt = 0
        session = await self._ensure_session()
        jitter_bounds = self._config.get("jitter_bounds", {"min_seconds": 0.1, "max_seconds": 0.5})
        proxy_cfg = self._config.get("tor_or_proxy", {})
        proxy = proxy_cfg.get("url") if proxy_cfg.get("enabled") else None

        while True:
            attempt += 1
            async with limiter:
                try:
                    resp = await session.request(method, url, proxy=proxy, **kwargs)
                    resp.raise_for_status()
                    yield resp
                    return
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("request-failed", extra={
                        "url": url,
                        "source": source,
                        "attempt": attempt,
                        "error": str(exc),
                    })
                    if attempt >= policy.max_attempts:
                        raise
                    backoff = min(policy.base_delay_seconds * (2 ** (attempt - 1)), policy.max_delay_seconds)
                    jitter = random.uniform(
                        jitter_bounds.get("min_seconds", 0.1), jitter_bounds.get("max_seconds", 0.5)
                    )
                    await asyncio.sleep(backoff + jitter)

    def _conditional_headers(self, url: str) -> Dict[str, str]:
        cached = self._cache.get(url)
        if not cached:
            return {}
        headers: Dict[str, str] = {}
        etag = cached.get("etag")
        last_modified = cached.get("last_modified")
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        return headers

    async def fetch_text(self, url: str, source: str, **kwargs) -> FetchResult:
        cached = self._cache.get(url)
        if not self._network_enabled:
            if cached:
                body = cached.get("body", "")
                size = len(body.encode("utf-8"))
                return FetchResult(
                    url=url,
                    text=body,
                    bytes_in=size,
                    latency_ms=0.0,
                    from_cache=True,
                    cached_at=cached.get("cached_at"),
                )
            raise RuntimeError("Network fetching not available without aiohttp")

        headers = kwargs.pop("headers", {})
        conditional = self._conditional_headers(url)
        merged_headers = {**headers, **conditional}
        start = asyncio.get_event_loop().time()
        async with self.request("GET", url, source, headers=merged_headers, **kwargs) as resp:
            latency_ms = (asyncio.get_event_loop().time() - start) * 1000
            if resp.status == 304 and cached:
                await self._cache.touch(url)
                body = cached.get("body", "")
                size = len(body.encode("utf-8"))
                return FetchResult(
                    url=url,
                    text=body,
                    bytes_in=size,
                    latency_ms=latency_ms,
                    from_cache=True,
                    cached_at=cached.get("cached_at"),
                )
            text = await resp.text(errors="ignore")
            etag = resp.headers.get("ETag")
            last_modified = resp.headers.get("Last-Modified")
            await self._cache.update(url, etag=etag, last_modified=last_modified, body=text)
            size = len(text.encode("utf-8"))
            return FetchResult(url=url, text=text, bytes_in=size, latency_ms=latency_ms)

    def network_available(self) -> bool:
        return self._network_enabled


__all__ = ["HttpClientFactory", "RetryPolicy", "RateLimiter", "FetchResult", "HttpCache"]
