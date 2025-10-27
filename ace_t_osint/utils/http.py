import asyncio
import contextlib
import logging
import random
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import aiohttp  # type: ignore
else:  # pragma: no cover
    aiohttp = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class RetryPolicy:
    max_attempts: int
    base_delay_seconds: float
    max_delay_seconds: float


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
        ua = user_agents[asyncio.get_event_loop().time_ns() % len(user_agents)]
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

    async def fetch_text(self, url: str, source: str, **kwargs) -> str:
        if not self._network_enabled:
            raise RuntimeError("Network fetching not available without aiohttp")
        async with self.request("GET", url, source, **kwargs) as resp:
            text = await resp.text(errors="ignore")
            return text

    def network_available(self) -> bool:
        return self._network_enabled


__all__ = ["HttpClientFactory", "RetryPolicy", "RateLimiter"]
