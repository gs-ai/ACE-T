from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class JSONLWriter:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_now(self) -> Path:
        now = datetime.utcnow()
        path = self.base_dir / f"{now:%Y}" / f"{now:%m}" / f"{now:%d}"
        path.mkdir(parents=True, exist_ok=True)
        return path / "alerts.jsonl"

    def write_alert(self, alert: Dict) -> None:
        path = self._path_for_now()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert) + "\n")

    def ensure_today_file(self) -> Path:
        """Ensure the alerts.jsonl file for today exists and return its Path."""
        path = self._path_for_now()
        if not path.exists():
            path.write_text("", encoding="utf-8")
        return path


__all__ = ["JSONLWriter"]
