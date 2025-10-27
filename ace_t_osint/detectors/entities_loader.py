from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


class EntityLoader:
    def __init__(self, entities_dir: str | Path) -> None:
        self.entities_dir = Path(entities_dir)

    def load(self) -> Dict[str, List[str]]:
        entities: Dict[str, List[str]] = {}
        for path in sorted(self.entities_dir.glob("*.yml")) + sorted(self.entities_dir.glob("*.yaml")):
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle.read()) or {}
            for namespace, values in data.items():
                bucket = entities.setdefault(namespace, [])
                for value in self._flatten(values):
                    if value not in bucket:
                        bucket.append(value)
        return entities

    @staticmethod
    def _flatten(values: Any) -> List[str]:
        if isinstance(values, str):
            return [values]
        flattened: List[str] = []
        if isinstance(values, dict):
            for nested in values.values():
                flattened.extend(EntityLoader._flatten(nested))
        elif isinstance(values, list):
            for item in values:
                flattened.extend(EntityLoader._flatten(item))
        return [str(value) for value in flattened if value is not None]


__all__ = ["EntityLoader"]
