from __future__ import annotations
import asyncio
from typing import Dict, Callable, Awaitable, List, Optional
import logging
from .schemas import Event

Handler = Callable[[Event], Awaitable[None]]

class EventBus:
    def __init__(self, max_queue: int = 5000):
        self.q: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue)
        self.routes: Dict[str, List[Handler]] = {}
        self._stop = asyncio.Event()
        self.log = logging.getLogger("agents.bus")

    def subscribe(self, event_type_prefix: str, handler: Handler) -> None:
        self.routes.setdefault(event_type_prefix, []).append(handler)

    async def publish(self, ev: Event) -> None:
        await self.q.put(ev)

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    async def run(self, max_inflight: int = 200):
        inflight = set()

        async def _dispatch(ev: Event):
            matched = []
            for prefix, handlers in self.routes.items():
                if ev.type.startswith(prefix):
                    matched.extend(handlers)
            # No handler is acceptable: event may exist for archival or future routes
            for h in matched:
                try:
                    await h(ev)
                except Exception:
                    self.log.exception("Handler error", extra={"event_type": ev.type, "source": ev.source})

        while not self._stop.is_set():
            try:
                ev = await asyncio.wait_for(self.q.get(), timeout=0.25)
            except asyncio.TimeoutError:
                continue

            task = asyncio.create_task(_dispatch(ev))
            inflight.add(task)
            task.add_done_callback(lambda t: inflight.discard(t))

            while len(inflight) >= max_inflight:
                await asyncio.sleep(0.01)

        if inflight:
            await asyncio.gather(*inflight, return_exceptions=True)
