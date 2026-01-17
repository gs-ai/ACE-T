from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable

from graph.builder import write_graph_data


def write_graph(_path: Path, objects: Iterable[Dict[str, Any]]) -> None:
    write_graph_data(objects)
