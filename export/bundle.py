from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_bundle(
    case_id: str,
    objects: Iterable[Dict[str, Any]],
    producer: str,
    run_id: str,
    version: str,
    toolchain: List[str] | None = None,
    case_name: str | None = None,
    tags: List[str] | None = None,
) -> Dict[str, Any]:
    bundle = {
        "version": version,
        "case": {
            "case_id": case_id,
            "created_at": _iso(),
        },
        "provenance": {
            "producer": producer,
            "produced_at": _iso(),
            "toolchain": toolchain or [],
            "run_id": run_id,
        },
        "objects": list(objects),
    }
    if case_name:
        bundle["case"]["name"] = case_name
    if tags:
        bundle["case"]["tags"] = list(tags)
    return bundle
