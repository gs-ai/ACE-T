from __future__ import annotations

import json
import os
import random
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from modules.realtime_open_feeds import ingest_realtime_open_feeds
from runners.reddit_live_ingest import ingest_comments, ingest_posts
from runners.subreddit_targets import DEFAULT_SUBREDDITS

STATUS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "ingest_status.json"


@dataclass
class Task:
    name: str
    func: Callable[[], None]
    min_interval: float
    max_interval: float
    max_backoff: float = 900.0  # 15 minutes
    paused: bool = False
    last_run: Optional[float] = None
    next_run: float = field(default_factory=lambda: time.time())
    backoff: float = 0.0

    def schedule_next(self, success: bool) -> None:
        now = time.time()
        if success:
            self.backoff = 0.0
            interval = random.uniform(self.min_interval, self.max_interval)
            self.next_run = now + interval
        else:
            # Exponential backoff with cap
            self.backoff = self.backoff * 2 if self.backoff else self.min_interval
            self.backoff = min(self.backoff, self.max_backoff)
            jitter = random.uniform(0, self.backoff * 0.2)
            self.next_run = now + self.backoff + jitter


class Scheduler:
    def __init__(self, tasks: List[Task]) -> None:
        self.tasks = tasks
        self.running = True
        self.status_path = STATUS_PATH
        self.status = {"updated_at": "", "tasks": {}}
        self._init_status()

    def stop(self, *_: object) -> None:
        self.running = False

    def _iso(self, ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _init_status(self) -> None:
        current = self._load_status()
        tasks_status = current.get("tasks") if isinstance(current, dict) else {}
        if not isinstance(tasks_status, dict):
            tasks_status = {}
        for task in self.tasks:
            tasks_status.setdefault(task.name, {"status": "idle"})
        current["tasks"] = tasks_status
        self.status = current
        self._write_status()

    def _load_status(self) -> dict:
        if self.status_path.exists():
            try:
                return json.loads(self.status_path.read_text(encoding="utf-8"))
            except Exception:
                return {"updated_at": "", "tasks": {}}
        return {"updated_at": "", "tasks": {}}

    def _write_status(self) -> None:
        self.status["updated_at"] = self._iso(time.time())
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(json.dumps(self.status, indent=2), encoding="utf-8")

    def _mark_task(self, task: Task, **updates: object) -> None:
        entry = self.status.setdefault("tasks", {}).setdefault(task.name, {})
        entry.update(updates)
        self._write_status()

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        print("[scheduler] starting; Ctrl-C to stop")
        while self.running:
            now = time.time()
            due_tasks = [t for t in self.tasks if not t.paused and t.next_run <= now]
            if not due_tasks:
                sleep_for = min((t.next_run for t in self.tasks if not t.paused), default=1.0) - now
                time.sleep(max(0.5, sleep_for))
                continue

            for task in due_tasks:
                start = time.time()
                self._mark_task(
                    task,
                    status="running",
                    last_run=self._iso(start),
                    last_run_ts=start,
                )
                try:
                    print(f"[scheduler] running task {task.name}")
                    task.func()
                    task.last_run = time.time()
                    task.schedule_next(success=True)
                    self._mark_task(
                        task,
                        status="ok",
                        last_success=self._iso(task.last_run),
                        last_success_ts=task.last_run,
                        last_duration=round(task.last_run - start, 2),
                        last_error="",
                        next_run=self._iso(task.next_run),
                        next_run_ts=task.next_run,
                    )
                except Exception as e:
                    print(f"[scheduler] task {task.name} failed: {e!r}")
                    task.schedule_next(success=False)
                    fail_ts = time.time()
                    self._mark_task(
                        task,
                        status="error",
                        last_failure=self._iso(fail_ts),
                        last_failure_ts=fail_ts,
                        last_error=str(e),
                        next_run=self._iso(task.next_run),
                        next_run_ts=task.next_run,
                    )


def main() -> None:
    # Prefer explicit env var; otherwise fall back to the curated DEFAULT_SUBREDDITS
    def _subreddit_list() -> List[str]:
        raw = os.getenv("ACE_T_REDDIT_SUBREDDITS") or os.getenv("REDDIT_SUBREDDITS") or ""
        if raw:
            subs = [s.strip() for s in raw.split(",") if s.strip()]
        else:
            subs = DEFAULT_SUBREDDITS
        # de-dupe while preserving order
        seen = set()
        out = []
        for s in subs:
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
        return out

    subreddits = _subreddit_list()

    def _ingest_posts() -> None:
        # read limits and timeframe from env
        try:
            max_posts = int(os.getenv("ACE_T_REDDIT_MAX_POSTS") or os.getenv("REDDIT_MAX_POSTS") or 100)
        except Exception:
            max_posts = 100
        timeframe = os.getenv("ACE_T_REDDIT_TIMEFRAME") or os.getenv("REDDIT_TIMEFRAME") or "day"
        for sub in subreddits:
            ingest_posts(subreddit=sub, limit=max_posts, sort="top", time_filter=timeframe)

    def _ingest_comments() -> None:
        try:
            comment_posts = int(os.getenv("ACE_T_REDDIT_COMMENT_POSTS") or os.getenv("REDDIT_COMMENT_POSTS") or 10)
        except Exception:
            comment_posts = 10
        for sub in subreddits:
            ingest_comments(subreddit=sub, limit_posts=comment_posts)

    tasks = [
        Task(
            name="reddit:posts",
            func=_ingest_posts,
            min_interval=120.0,  # 2 minutes
            max_interval=300.0,  # 5 minutes
        ),
        Task(
            name="reddit:comments",
            func=_ingest_comments,
            min_interval=240.0,  # 4 minutes
            max_interval=540.0,  # 9 minutes
        ),
        Task(
            name="feeds:realtime_open",
            func=ingest_realtime_open_feeds,
            min_interval=600.0,  # 10 minutes
            max_interval=900.0,  # 15 minutes
        ),
    ]
    Scheduler(tasks).run()


if __name__ == "__main__":
    main()
