from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def timeline_events(objects: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "event":
            continue
        events.append(
            {
                "id": obj.get("id"),
                "event_type": obj.get("event_type"),
                "time_start": obj.get("time_start"),
                "time_end": obj.get("time_end"),
                "participants": obj.get("participants") or [],
                "band": obj.get("band"),
                "confidence": obj.get("confidence"),
                "evidence": obj.get("evidence") or [],
                "metrics": obj.get("metrics") or {},
            }
        )
    return events


def write_timeline(path: Path, objects: Iterable[Dict[str, Any]]) -> None:
    payload = timeline_events(objects)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
