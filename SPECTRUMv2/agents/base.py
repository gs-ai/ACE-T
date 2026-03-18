from __future__ import annotations
from typing import Optional, Dict, Any
import asyncio
import logging
from .bus import EventBus
from .store import Store
from .schemas import Event

class Agent:
    """
    Base class:
      - start(): async background loops (producers)
      - handle(): event handlers (consumers)
    """
    name = "agent"

    def __init__(self, bus: EventBus, store: Store, cfg: Dict[str, Any], logger: Optional[logging.Logger]=None):
        self.bus = bus
        self.store = store
        self.cfg = cfg
        self.log = logger or logging.getLogger(self.name)

    async def start(self) -> None:
        return

    async def handle(self, ev: Event) -> None:
        return

    async def emit(self, ev: Event) -> None:
        ev.finalize()
        inserted = self.store.put_event(ev.to_dict())
        if inserted:
            await self.bus.publish(ev)
        else:
            # Dedupe: event already exists
            pass

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
