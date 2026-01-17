from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Set


STATE_PATH = Path(__file__).resolve().parents[1] / "data" / "pipeline_state.json"


def load_state() -> Dict[str, Set[str]]:
    if STATE_PATH.exists():
        try:
            raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            return {
                "artifacts": set(raw.get("artifacts", [])),
                "signals": set(raw.get("signals", [])),
            }
        except Exception:
            return {"artifacts": set(), "signals": set()}
    return {"artifacts": set(), "signals": set()}


def save_state(artifacts: Set[str], signals: Set[str]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"artifacts": sorted(artifacts), "signals": sorted(signals)}
    STATE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
