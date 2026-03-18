from __future__ import annotations
from typing import Dict, Any
from ..base import Agent
from ..schemas import Event

class NormalizeAgent(Agent):
    name = "normalize"

    async def handle(self, ev: Event) -> None:
        if ev.type == "raw.rss.item":
            item = ev.payload.get("item", {})
            norm = {
                "title": item.get("title",""),
                "url": item.get("link",""),
                "summary": item.get("summary",""),
                "published": item.get("published",""),
                "source": ev.source,
                "kind": "rss_item"
            }
            out = Event(
                type="norm.intel",
                source=ev.source,
                payload=norm,
                parent_id=ev.event_id,
                tags=["norm","intel"]
            )
            await self.emit(out)

        elif ev.type == "raw.file":
            text = ev.payload.get("content_text","")
            norm = {
                "title": ev.payload.get("filename",""),
                "url": f"file://{ev.payload.get('path','')}",
                "summary": text[:2000],
                "published": "",
                "source": ev.source,
                "kind": "local_file",
                "path": ev.payload.get("path","")
            }
            out = Event(
                type="norm.intel",
                source=ev.source,
                payload=norm,
                parent_id=ev.event_id,
                tags=["norm","intel"]
            )
            await self.emit(out)
