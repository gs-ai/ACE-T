from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Set


class SeenStore:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Set[str]] = {}

    def _path(self, source: str) -> Path:
        return self.base_dir / f"{source}_seen.json"

    def load(self, source: str) -> Set[str]:
        if source in self._cache:
            return self._cache[source]
        path = self._path(source)
        if not path.exists():
            self._cache[source] = set()
            return self._cache[source]
        with path.open("r", encoding="utf-8") as handle:
            self._cache[source] = set(json.load(handle))
        return self._cache[source]

    def add(self, source: str, fingerprint: str) -> None:
        seen = self.load(source)
        seen.add(fingerprint)
        path = self._path(source)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(sorted(seen), handle)


__all__ = ["SeenStore"]
