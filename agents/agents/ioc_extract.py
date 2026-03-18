from __future__ import annotations
from ..base import Agent
from ..schemas import Event
from ..utils.text import extract_iocs

class IOCExtractAgent(Agent):
    name = "ioc_extract"

    async def handle(self, ev: Event) -> None:
        if ev.type != "norm.intel":
            return
        text = "\n".join([
            ev.payload.get("title",""),
            ev.payload.get("summary",""),
            ev.payload.get("url",""),
        ])
        iocs = extract_iocs(text)
        if not iocs:
            return
        out = Event(
            type="ioc.extracted",
            source=ev.source,
            payload={
                "iocs": iocs,
                "intel": ev.payload
            },
            parent_id=ev.event_id,
            tags=["ioc"]
        )
        await self.emit(out)
