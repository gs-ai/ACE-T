import asyncio
import contextlib
import json
import logging
import os
import random
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Optional imports; the module fails closed when dependencies are missing.
try:  # pragma: no cover - import guarded at runtime
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

try:  # pragma: no cover - import guarded at runtime
    from aiohttp_socks import ProxyConnector  # type: ignore
except Exception:  # pragma: no cover
    ProxyConnector = None  # type: ignore

try:  # pragma: no cover - import guarded at runtime
    import socks  # type: ignore
except Exception:  # pragma: no cover
    socks = None  # type: ignore

logger = logging.getLogger(__name__)


class TorEnforcerError(RuntimeError):
    """Base error for Tor enforcement issues."""


class TorNotReadyError(TorEnforcerError):
    """Raised when Tor is not ready or fails verification."""


class TorBypassAttempt(TorEnforcerError):
    """Raised when code attempts to create a non-Tor socket."""


@dataclass
class TorTimingConfig:
    warmup_seconds: float = 8.0
    min_delay_seconds: float = 1.5
    max_delay_seconds: float = 30.0
    backoff_multiplier: float = 1.6
    rotation_cooldown_seconds: float = 20.0
    jitter_min_seconds: float = 0.3
    jitter_max_seconds: float = 1.0
    readiness_max_wait_seconds: float = 90.0
    reverify_interval_seconds: float = 45.0
    control_port_timeout_seconds: float = 3.0
    ip_check_timeout_seconds: float = 10.0
    rtt_weight: float = 1.35  # scale RTT into pacing delay


class TorEnforcer:
    """Fail-closed Tor enforcement with adaptive pacing and control-port verification."""

    def __init__(self) -> None:
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 9050
        self.control_port = 9051
        self.control_password = os.environ.get("TOR_CONTROL_PASSWORD")
        self.control_cookie_path = os.environ.get("TOR_CONTROL_COOKIE_PATH")
        self.ip_check_url = "https://check.torproject.org/api/ip"
        self.timing = TorTimingConfig()

        self._lock = asyncio.Lock()
        self._ready = False
        self._enabled = False  # Track if Tor is actually enabled
        self._last_ip: Optional[str] = None
        self._last_rtt: Optional[float] = None
        self._last_verify_ts: float = 0.0
        self._cooldown_until: float = 0.0
        self._current_delay: float = self.timing.min_delay_seconds
        self._patched_socket = False
        self._raw_socket_ctor = socket.socket
        self._raw_create_connection = socket.create_connection
        self._proxy_url = f"socks5h://{self.proxy_host}:{self.proxy_port}"
        self._newnym_ts: float = 0.0
        self._rotate_on_start = os.environ.get("ACE_T_TOR_ROTATE_ON_START", "0").lower() in ("1", "true", "yes", "on")

    # -- Public API -----------------------------------------------------
    def configure_from_config(self, cfg: Dict[str, Any] | None) -> None:
        base_cfg: Dict[str, Any] = {}
        if cfg is None:
            base_cfg = {}
        elif isinstance(cfg, dict):
            base_cfg = cfg
        elif hasattr(cfg, "to_dict"):
            try:
                base_cfg = cfg.to_dict()  # type: ignore[assignment]
            except Exception:
                base_cfg = {}
        
        # Check if Tor is enabled
        self._enabled = base_cfg.get("tor_or_proxy", {}).get("enabled", False) if isinstance(base_cfg, dict) else False
        
        tor_cfg = base_cfg.get("tor_enforcement", {}) if isinstance(base_cfg, dict) else {}
        self.proxy_host = tor_cfg.get("proxy_host", self.proxy_host)
        self.proxy_port = int(tor_cfg.get("proxy_port", self.proxy_port))
        self.control_port = int(tor_cfg.get("control_port", self.control_port))
        self.control_password = tor_cfg.get("control_password", self.control_password)
        self.control_cookie_path = tor_cfg.get("control_cookie_path", self.control_cookie_path)
        self.ip_check_url = tor_cfg.get("ip_check_url", self.ip_check_url)
        if "rotate_on_start" in tor_cfg:
            self._rotate_on_start = bool(tor_cfg.get("rotate_on_start"))
        timing_cfg = tor_cfg.get("timing", {}) or {}
        for field in self.timing.__dataclass_fields__:  # type: ignore[attr-defined]
            if field in timing_cfg:
                setattr(self.timing, field, float(timing_cfg[field]))
        self._proxy_url = f"socks5h://{self.proxy_host}:{self.proxy_port}"

    def install_socket_guard(self) -> None:
        """Force all sockets to be Tor-routed. Uses PySocks to wrap sockets."""
        if self._patched_socket:
            return
        if socks is None:
            raise TorEnforcerError("PySocks is required for Tor enforcement but is not installed.")

        socks.setdefaultproxy(
            socks.SOCKS5,
            self.proxy_host,
            self.proxy_port,
            rdns=True,
        )

        class _LockedSocksSocket(socks.socksocket):
            def set_proxy(self, proxy_type=None, addr=None, port=None, rdns=True, username=None, password=None):  # type: ignore[override]
                none_sentinel = getattr(socks, "PROXY_TYPE_NONE", object())
                if proxy_type is None or proxy_type == none_sentinel:
                    raise TorBypassAttempt("Direct sockets are forbidden while Tor enforcement is active")
                return super().set_proxy(proxy_type, addr, port, rdns=rdns, username=username, password=password)

        def _tor_socket(*args, **kwargs):  # type: ignore[override]
            family = args[0] if args else kwargs.get("family", socket.AF_INET)
            if family != socket.AF_INET:
                # Allow non-INET sockets (e.g., AF_UNIX) to function normally
                return self._raw_socket_ctor(*args, **kwargs)
            sock = _LockedSocksSocket(*args, **kwargs)
            # Prevent callers from clearing the proxy
            sock.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port, rdns=True)
            return sock

        def _tor_create_connection(address, timeout=None, source_address=None):  # type: ignore[override]
            if not isinstance(address, tuple) or len(address) < 2:
                raise TorBypassAttempt(f"Invalid address for Tor socket: {address}")
            host, port = address[0], int(address[1])
            # Allow direct loopback/control connections to keep local orchestration working.
            if host in ("127.0.0.1", "localhost") or self._is_control_endpoint(host, port):
                return self._raw_create_connection(address, timeout=timeout, source_address=source_address)
            sock = _tor_socket()
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(address)
            return sock

        socket.socket = _tor_socket  # type: ignore[assignment]
        socket.create_connection = _tor_create_connection  # type: ignore[assignment]
        self._patched_socket = True
        logger.info("tor-socket-guard-installed", extra={"proxy": self._proxy_url})

    async def gate_request(self, reason: str | None = None) -> None:
        """Verify Tor state before allowing an outbound request."""
        if not self._enabled:
            return  # No-op when Tor is disabled
        await self._wait_until_ready(reason=reason)
        await self._adaptive_delay()

    async def wait_for_readiness(self, reason: str | None = None) -> str:
        """Verify Tor without applying pacing delay (used for startup checks)."""
        await self._wait_until_ready(reason=reason)
        return self._last_ip or ""

    async def rotate_circuit(self) -> None:
        """Send NEWNYM and block until a new exit IP is verified."""
        async with self._lock:
            self._signal_newnym()
            self._newnym_ts = time.time()
            self._cooldown_until = self._newnym_ts + self.timing.rotation_cooldown_seconds
            self._ready = False
            logger.info("tor-circuit-rotation-requested", extra={"cooldown_seconds": self.timing.rotation_cooldown_seconds})
        await asyncio.sleep(self.timing.rotation_cooldown_seconds)
        await self._wait_until_ready(require_new_ip=True, reason="post-rotation")

    def build_connector(self, *, limit: int, ttl_dns_cache: int, keepalive_timeout: int):
        """Return (connector, per_request_proxy) tuple for aiohttp sessions."""
        connector = None
        request_proxy = None
        if ProxyConnector is not None:
            connector = ProxyConnector.from_url(
                self._proxy_url,
                rdns=True,
                limit=limit,
                ttl_dns_cache=ttl_dns_cache,
                keepalive_timeout=keepalive_timeout,
            )
        return connector, request_proxy

    def raw_socket(self) -> socket.socket:
        """Obtain an unwrapped socket for local-only operations (e.g., port probing)."""
        return self._raw_socket_ctor(socket.AF_INET, socket.SOCK_STREAM)

    @property
    def proxy_url(self) -> str:
        return self._proxy_url

    @property
    def last_exit_ip(self) -> Optional[str]:
        return self._last_ip

    @property
    def rotate_on_start(self) -> bool:
        return bool(self._rotate_on_start)

    # -- Internal helpers -----------------------------------------------
    def _is_control_endpoint(self, host: str, port: int) -> bool:
        return host in ("127.0.0.1", "localhost") and port == self.control_port

    async def _wait_until_ready(self, *, require_new_ip: bool = False, reason: str | None = None) -> None:
        deadline = time.time() + self.timing.readiness_max_wait_seconds
        delay = self.timing.warmup_seconds
        while True:
            try:
                async with self._lock:
                    if self._cooldown_until and time.time() < self._cooldown_until:
                        raise TorNotReadyError("Tor circuit cooling down after rotation")
                    self._check_control_port()
                    ip, rtt = await self._verify_exit_ip()
                    if require_new_ip and self._last_ip and ip == self._last_ip:
                        raise TorNotReadyError("Tor exit IP did not change after rotation")
                    self._last_ip = ip
                    self._last_rtt = rtt
                    self._last_verify_ts = time.time()
                    self._ready = True
                    self._current_delay = min(
                        self.timing.max_delay_seconds,
                        max(self.timing.min_delay_seconds, rtt * self.timing.rtt_weight),
                    )
                    return
            except TorNotReadyError as exc:
                if time.time() > deadline:
                    raise
                sleep_for = min(self.timing.max_delay_seconds, delay)
                jitter = random.uniform(self.timing.jitter_min_seconds, self.timing.jitter_max_seconds)
                logger.warning(
                    "tor-readiness-wait",
                    extra={
                        "reason": reason or "unspecified",
                        "sleep_seconds": round(sleep_for + jitter, 2),
                        "error": str(exc),
                    },
                )
                await asyncio.sleep(sleep_for + jitter)
                delay = min(self.timing.max_delay_seconds, delay * self.timing.backoff_multiplier)

    async def _adaptive_delay(self) -> None:
        delay = max(self.timing.min_delay_seconds, self._current_delay)
        jitter = random.uniform(self.timing.jitter_min_seconds, self.timing.jitter_max_seconds)
        await asyncio.sleep(delay + jitter)

    def _check_control_port(self) -> None:
        def _auth_token() -> str:
            # Prefer cookie-based auth if available
            if self.control_cookie_path and Path(self.control_cookie_path).exists():
                try:
                    data = Path(self.control_cookie_path).read_bytes()
                    return data.hex()
                except Exception:
                    pass
            default_cookie = Path("/var/run/tor/control.authcookie")
            if default_cookie.exists():
                try:
                    data = default_cookie.read_bytes()
                    return data.hex()
                except Exception:
                    pass
            if self.control_password:
                return f'"{self.control_password}"'
            return ""

        try:
            with self._raw_socket_ctor(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timing.control_port_timeout_seconds)
                sock.connect(("127.0.0.1", self.control_port))
                token = _auth_token()
                auth_cmd = f"AUTHENTICATE {token}\r\n" if token else "AUTHENTICATE\r\n"
                sock.sendall(auth_cmd.encode("utf-8"))
                auth_resp = sock.recv(128)
                if not auth_resp.startswith(b"250"):
                    raise TorNotReadyError("Tor control authentication failed")
                sock.sendall(b"GETINFO status/circuit-established\r\n")
                info_resp = sock.recv(256)
                if b"status/circuit-established=1" not in info_resp:
                    raise TorNotReadyError("Tor circuit not yet established")
        except TorNotReadyError:
            raise
        except Exception as exc:
            raise TorNotReadyError(f"Tor control port unavailable: {exc}") from exc

    def _signal_newnym(self) -> None:
        try:
            with self._raw_socket_ctor(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timing.control_port_timeout_seconds)
                sock.connect(("127.0.0.1", self.control_port))
                token = None
                if self.control_cookie_path and Path(self.control_cookie_path).exists():
                    try:
                        token = Path(self.control_cookie_path).read_bytes().hex()
                    except Exception:
                        token = None
                if token is None:
                    default_cookie = Path("/var/run/tor/control.authcookie")
                    if default_cookie.exists():
                        try:
                            token = default_cookie.read_bytes().hex()
                        except Exception:
                            token = None
                if token is None and self.control_password:
                    token = f'"{self.control_password}"'
                auth_cmd = f"AUTHENTICATE {token}\r\n" if token else "AUTHENTICATE\r\n"
                sock.sendall(auth_cmd.encode("utf-8"))
                if not sock.recv(128).startswith(b"250"):
                    raise TorNotReadyError("Tor control authentication failed")
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                resp = sock.recv(128)
                if not resp.startswith(b"250"):
                    raise TorNotReadyError("Tor NEWNYM signal failed")
        except Exception as exc:
            raise TorNotReadyError(f"Tor NEWNYM failed: {exc}") from exc

    async def _verify_exit_ip(self) -> Tuple[str, float]:
        if aiohttp is None:
            raise TorNotReadyError("aiohttp is required for Tor verification but is not installed")

        start = time.perf_counter()
        connector, per_request_proxy = self.build_connector(
            limit=8, ttl_dns_cache=300, keepalive_timeout=30
        )
        timeout = aiohttp.ClientTimeout(total=self.timing.ip_check_timeout_seconds)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(self.ip_check_url, proxy=per_request_proxy) as resp:
                    text = await resp.text()
                    latency = time.perf_counter() - start
                    if resp.status != 200:
                        raise TorNotReadyError(f"Tor IP check failed: HTTP {resp.status}")
                    data = json.loads(text)
                    ip = data.get("IP")
                    is_tor = data.get("IsTor") in (True, "True", "true", 1, "1")
                    if not ip or not is_tor:
                        raise TorNotReadyError("Exit IP is not confirmed as Tor-based")
                    return str(ip), latency
        except TorNotReadyError:
            raise
        except Exception as exc:
            raise TorNotReadyError(f"Tor IP verification failed: {exc}") from exc


_tor_enforcer: Optional[TorEnforcer] = None


def get_tor_enforcer() -> TorEnforcer:
    global _tor_enforcer
    if _tor_enforcer is None:
        _tor_enforcer = TorEnforcer()
    return _tor_enforcer


__all__ = [
    "TorEnforcer",
    "TorEnforcerError",
    "TorNotReadyError",
    "TorBypassAttempt",
    "get_tor_enforcer",
]
