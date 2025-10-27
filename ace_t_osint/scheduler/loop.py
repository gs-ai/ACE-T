from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Awaitable, Callable, Dict, Iterable, List, Optional

from ..utils.time import format_ts, utcnow

logger = logging.getLogger(__name__)


class SchedulerLoop:
    def __init__(self, interval_map: Dict[str, int]) -> None:
        self.interval_map = interval_map
        self._tasks: List[asyncio.Task] = []
        self._running = False

    async def run_once(self, jobs: Dict[str, Callable[[], Awaitable[None]]]) -> None:
        await asyncio.gather(*(job() for job in jobs.values()))

    async def run_forever(self, jobs: Dict[str, Callable[[], Awaitable[None]]]) -> None:
        self._running = True
        metrics = defaultdict(int)
        while self._running:
            start = utcnow()
            await self.run_once(jobs)
            metrics["iterations"] += 1
            elapsed = (utcnow() - start).total_seconds()
            sleep_for = min(self.interval_map.values()) if self.interval_map else 60
            logger.info("scheduler-iteration", extra={
                "iterations": metrics["iterations"],
                "elapsed": elapsed,
            })
            await asyncio.sleep(sleep_for)

    def stop(self) -> None:
        self._running = False


__all__ = ["SchedulerLoop"]
