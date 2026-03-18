from __future__ import annotations
import asyncio
import os
import time
from typing import Dict, Any
from ..base import Agent
from ..schemas import Event

class FileWatchAgent(Agent):
    name = "file_watch"

    async def start(self) -> None:
        inputs = self.cfg.get("inputs", {}).get("local_files", [])
        loop_hz = float(self.cfg.get("runtime", {}).get("loop_hz", 2))
        sleep_s = max(1.0, 1.0 / loop_hz)

        while not self.bus.stopped():
            for spec in inputs:
                if not spec.get("enabled", True):
                    continue
                path = spec.get("path")
                if not path:
                    continue
                os.makedirs(path, exist_ok=True)
                await self._scan_dir(spec.get("name","local_files"), path)
            await asyncio.sleep(sleep_s)

    async def _scan_dir(self, name: str, path: str) -> None:
        try:
            emitted = 0
            for fn in os.listdir(path):
                fp = os.path.join(path, fn)
                if os.path.isdir(fp):
                    continue
                st = os.stat(fp)
                key = f"file:{fp}:{int(st.st_mtime)}:{st.st_size}"
                if self.store.seen(key):
                    continue
                self.store.mark_seen(key)
                # read bounded
                data = b""
                try:
                    with open(fp, "rb") as f:
                        data = f.read(2_000_000)
                except Exception:
                    continue
                ev = Event(
                    type="raw.file",
                    source=name,
                    payload={
                        "path": fp,
                        "filename": fn,
                        "mtime_utc": st.st_mtime,
                        "size": st.st_size,
                        "content_b64": None,
                        "content_text": data.decode("utf-8", errors="ignore")
                    },
                    tags=["file","raw"]
                )
                await self.emit(ev)
                emitted += 1
            if emitted:
                self.log.info("File ingest: %s -> %d files", name, emitted)
        except Exception:
            return
