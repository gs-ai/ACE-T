from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from jsonschema import ValidationError


def _quarantine_path(stage_id: str) -> Path:
    root = Path(__file__).resolve().parents[1]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "data" / "quarantine" / f"{stage_id}_{ts}.json"


def validate_objects(
    objects: Iterable[Dict[str, Any]],
    validator,
    stage_id: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    valid: List[Dict[str, Any]] = []
    invalid: List[Dict[str, Any]] = []
    for obj in objects:
        try:
            validator.validate(obj)
            valid.append(obj)
        except ValidationError as exc:
            invalid.append({"object": obj, "error": str(exc)})
    if invalid:
        path = _quarantine_path(stage_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(invalid, indent=2), encoding="utf-8")
        print(f"[pipeline] quarantined {len(invalid)} invalid objects for {stage_id} at {path}")
    return valid, invalid
