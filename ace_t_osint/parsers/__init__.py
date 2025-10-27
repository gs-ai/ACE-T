from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class ParsedItem:
    source: str
    url: str
    title: str
    content: str
    published_at: str | None = None


__all__ = ["ParsedItem"]
