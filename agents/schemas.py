from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, List
import time
import hashlib
import json

def _now_utc() -> float:
    return time.time()

def stable_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

@dataclass
class Event:
    """
    The atomic unit of work in the agent swarm.

    type:        semantic routing key, e.g. "raw.rss.item", "norm.intel", "ioc.extracted"
    source:      source label
    ts_utc:      event timestamp in epoch seconds UTC
    payload:     structured content
    event_id:    deterministic hash for dedupe
    parent_id:   optional lineage pointer
    tags:        optional tags for filtering/risk lanes
    """
    type: str
    source: str
    payload: Dict[str, Any]
    ts_utc: float = field(default_factory=_now_utc)
    event_id: str = ""
    parent_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def finalize(self) -> "Event":
        if not self.event_id:
            self.event_id = stable_hash({
                "type": self.type,
                "source": self.source,
                "ts_bucket": int(self.ts_utc // 5),  # 5s bucket for stability
                "payload": self.payload
            })
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
