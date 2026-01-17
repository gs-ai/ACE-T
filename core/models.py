from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _iso(ts: Optional[str] = None) -> str:
    if ts:
        return ts
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BaseObject:
    id: str
    type: str
    created_at: str = field(default_factory=_iso)
    updated_at: Optional[str] = None
    band: Optional[str] = None
    confidence: Optional[float] = None
    labels: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "created_at": self.created_at,
        }
        if self.updated_at:
            payload["updated_at"] = self.updated_at
        if self.band:
            payload["band"] = self.band
        if self.confidence is not None:
            payload["confidence"] = float(self.confidence)
        if self.labels:
            payload["labels"] = list(self.labels)
        if self.tags:
            payload["tags"] = list(self.tags)
        if self.notes:
            payload["notes"] = self.notes
        return payload


@dataclass
class Artifact(BaseObject):
    uri: str = ""
    captured_at: str = field(default_factory=_iso)
    content_type: str = "text/plain"
    source: Dict[str, Any] = field(default_factory=dict)
    hashes: Optional[Dict[str, str]] = None
    size_bytes: Optional[int] = None
    local_path: Optional[str] = None
    mime_hint: Optional[str] = None

    def __post_init__(self) -> None:
        self.type = "artifact"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "type": "artifact",
                "uri": self.uri,
                "captured_at": self.captured_at,
                "content_type": self.content_type,
                "source": self.source,
            }
        )
        if self.hashes:
            payload["hashes"] = self.hashes
        if self.size_bytes is not None:
            payload["size_bytes"] = int(self.size_bytes)
        if self.local_path:
            payload["local_path"] = self.local_path
        if self.mime_hint:
            payload["mime_hint"] = self.mime_hint
        return payload


@dataclass
class Signal(BaseObject):
    signal_type: str = ""
    value: Any = None
    normalized: Any = None
    evidence: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        self.type = "signal"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "type": "signal",
                "signal_type": self.signal_type,
                "value": self.value,
            }
        )
        if self.normalized is not None:
            payload["normalized"] = self.normalized
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        return payload


@dataclass
class Entity(BaseObject):
    entity_type: str = ""
    name: str = ""
    aliases: Optional[List[str]] = None
    attributes: Optional[Dict[str, Any]] = None
    evidence: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        self.type = "entity"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "type": "entity",
                "entity_type": self.entity_type,
                "name": self.name,
            }
        )
        if self.aliases:
            payload["aliases"] = list(self.aliases)
        if self.attributes:
            payload["attributes"] = dict(self.attributes)
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        return payload


@dataclass
class Edge(BaseObject):
    from_id: str = ""
    to_id: str = ""
    edge_type: str = ""
    weight: float = 1.0
    direction: Optional[str] = None
    evidence: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        self.type = "edge"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "type": "edge",
                "from": self.from_id,
                "to": self.to_id,
                "edge_type": self.edge_type,
                "weight": float(self.weight),
            }
        )
        if self.direction:
            payload["direction"] = self.direction
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        return payload


@dataclass
class Event(BaseObject):
    event_type: str = ""
    time_start: str = field(default_factory=_iso)
    time_end: Optional[str] = None
    participants: Optional[List[str]] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    metrics: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        self.type = "event"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {
                "type": "event",
                "event_type": self.event_type,
                "time_start": self.time_start,
            }
        )
        if self.time_end:
            payload["time_end"] = self.time_end
        if self.participants:
            payload["participants"] = list(self.participants)
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        if self.metrics:
            payload["metrics"] = dict(self.metrics)
        return payload


@dataclass
class Claim(BaseObject):
    text: str = ""
    claim_type: Optional[str] = None
    about: Optional[List[str]] = None
    evidence: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        self.type = "claim"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update({"type": "claim", "text": self.text})
        if self.claim_type:
            payload["claim_type"] = self.claim_type
        if self.about:
            payload["about"] = list(self.about)
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        return payload


@dataclass
class Cluster(BaseObject):
    cluster_type: str = ""
    members: List[str] = field(default_factory=list)
    centroid: Optional[Dict[str, Any]] = None
    evidence: Optional[List[Dict[str, Any]]] = None

    def __post_init__(self) -> None:
        self.type = "cluster"

    def to_dict(self) -> Dict[str, Any]:
        payload = super().to_dict()
        payload.update(
            {"type": "cluster", "cluster_type": self.cluster_type, "members": list(self.members)}
        )
        if self.centroid:
            payload["centroid"] = dict(self.centroid)
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        return payload
