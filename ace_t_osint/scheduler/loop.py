from __future__ import annotations

import asyncio
import logging
import random
from typing import Awaitable, Callable, Dict, List

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
        offsets = self._initial_offsets(jobs)
        for name, job in jobs.items():
            interval = max(self.interval_map.get(name, 60), 1)
            task = asyncio.create_task(self._worker(name, job, interval, offsets.get(name, 0.0)))
            self._tasks.append(task)
        try:
            await asyncio.gather(*self._tasks)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()

    def _initial_offsets(self, jobs: Dict[str, Callable[[], Awaitable[None]]]) -> Dict[str, float]:
        count = max(len(jobs), 1)
        offsets: Dict[str, float] = {}
        for index, name in enumerate(jobs.keys()):
            interval = max(self.interval_map.get(name, 60), 1)
            spread = interval / count
            jitter = random.uniform(0, spread)
            offsets[name] = index * spread + jitter
        return offsets

    async def _worker(
        self,
        name: str,
        job: Callable[[], Awaitable[None]],
        interval: float,
        offset: float,
    ) -> None:
        await asyncio.sleep(offset)
        while self._running:
            started = utcnow()
            try:
                await job()
                elapsed = (utcnow() - started).total_seconds()
                logger.info(
                    "scheduler-cycle",
                    extra={
                        "source": name,
                        "started_at": format_ts(started),
                        "elapsed": elapsed,
                        "interval": interval,
                    },
                )
            except asyncio.CancelledError:  # pragma: no cover - cancellation path
                break
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(
                    "scheduler-error",
                    extra={"source": name, "error": str(exc)},
                )
            await asyncio.sleep(interval)


__all__ = ["SchedulerLoop"]
