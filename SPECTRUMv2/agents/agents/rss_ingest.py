from __future__ import annotations
import asyncio
import logging
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from ..base import Agent
from ..schemas import Event
from ..fetch import Fetcher

class RSSIngestAgent(Agent):
    name = "rss_ingest"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cache_dir = ".cache/agents/http"
        fetch_cfg = self.cfg.get("fetch", {})
        self.fetcher = Fetcher(
            cache_dir=cache_dir,
            user_agent=fetch_cfg.get("user_agent", "ACE-T-SPECTRUM/agents"),
            timeout_s=int(fetch_cfg.get("timeout_seconds", 20)),
            max_bytes=int(fetch_cfg.get("max_bytes", 4_000_000)),
        )

    async def start(self) -> None:
        feeds = self.cfg.get("inputs", {}).get("rss_feeds", [])
        loop_hz = float(self.cfg.get("runtime", {}).get("loop_hz", 2))
        sleep_s = max(1.0, 1.0 / loop_hz)

        while not self.bus.stopped():
            for f in feeds:
                if not f.get("enabled", True):
                    continue
                await self._poll_feed(f["name"], f["url"])
                await asyncio.sleep(0.2)
            await asyncio.sleep(sleep_s)

    async def _poll_feed(self, name: str, url: str) -> None:
        res = self.fetcher.get(url)
        if res.status not in (200, 304):
            return
        if not res.content:
            return

        try:
            root = ET.fromstring(res.content)
        except Exception:
            return

        # RSS/Atom tolerant extraction
        items = []
        # RSS
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            desc = (item.findtext("description") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            items.append({"title": title, "link": link, "summary": desc, "published": pub})

        # Atom
        ns = {"a": "http://www.w3.org/2005/Atom"}
        for entry in root.findall(".//a:entry", ns):
            title = (entry.findtext("a:title", default="", namespaces=ns) or "").strip()
            link_el = entry.find("a:link", ns)
            link = (link_el.get("href") if link_el is not None else "") or ""
            summary = (entry.findtext("a:summary", default="", namespaces=ns) or "").strip()
            updated = (entry.findtext("a:updated", default="", namespaces=ns) or "").strip()
            items.append({"title": title, "link": link, "summary": summary, "published": updated})

        emitted = 0
        for it in items:
            key = f"rss:{name}:{it.get('link') or it.get('title')}"
            if self.store.seen(key):
                continue
            self.store.mark_seen(key)
            ev = Event(
                type="raw.rss.item",
                source=name,
                payload={
                    "feed": name,
                    "url": url,
                    "item": it,
                    "fetched_status": res.status,
                    "fetched_from_cache": res.from_cache
                },
                tags=["rss","raw"]
            )
            await self.emit(ev)
            emitted += 1
        if emitted:
            self.log.info("RSS ingest: %s -> %d items", name, emitted)
