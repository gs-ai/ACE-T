from __future__ import annotations
from typing import Dict, Any
import os
from ..base import Agent
from ..schemas import Event
from ..artifacts import atomic_write_json, now_iso_utc

def _load_json(path: str, default):
    try:
        import json
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        return default
    return default

class TimelineWriterAgent(Agent):
    name = "timeline_writer"

    async def handle(self, ev: Event) -> None:
        if ev.type not in ("norm.intel", "ioc.extracted", "enrich.llm"):
            return
        out_cfg = self.cfg.get("outputs", {})
        artifacts_dir = self.cfg.get("storage", {}).get("artifacts_dir", "data")
        timeline_path = out_cfg.get("timeline_json_path", os.path.join(artifacts_dir, "timeline.json"))

        tl = _load_json(timeline_path, default={"timestamp_utc": now_iso_utc(), "events": []})
        if not isinstance(tl, dict):
            tl = {"timestamp_utc": now_iso_utc(), "events": []}
        if "events" not in tl or not isinstance(tl.get("events"), list):
            tl["events"] = []
        tl["timestamp_utc"] = now_iso_utc()

        summary = ""
        if ev.type == "norm.intel":
            summary = (ev.payload.get("title","") or "")[:200]
        elif ev.type == "ioc.extracted":
            summary = "IOC extracted"
        elif ev.type == "enrich.llm":
            summary = "LLM enrichment"

        tl["events"].append({
            "ts_utc": ev.ts_utc,
            "iso_utc": now_iso_utc(),
            "type": ev.type,
            "source": ev.source,
            "summary": summary,
            "event_id": ev.event_id,
            "parent_id": ev.parent_id,
            "tags": ev.tags
        })
        if len(tl["events"]) > 10000:
            tl["events"] = tl["events"][-10000:]

        atomic_write_json(timeline_path, tl)
