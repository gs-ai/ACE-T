from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_DEFAULT_LOOKUP = {
    "usa": {"country": "United States", "city": None, "lat": None, "lon": None},
    "europe": {"country": "Europe", "city": None, "lat": None, "lon": None},
}


def load_lookup(path: Optional[str]) -> Dict[str, Dict[str, Optional[str]]]:
    if not path:
        return _DEFAULT_LOOKUP
    path_obj = Path(path)
    if not path_obj.exists():
        logger.warning("geo-lookup-missing", extra={"path": str(path_obj)})
        return _DEFAULT_LOOKUP
    with path_obj.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def lookup_geo(text: str, lookup: Optional[Dict[str, Dict[str, Optional[str]]]] = None) -> Dict[str, Optional[str]]:
    lookup = lookup or _DEFAULT_LOOKUP
    text_lower = text.lower()
    for key, value in lookup.items():
        if key in text_lower:
            return value
    return {"country": None, "city": None, "lat": None, "lon": None}


__all__ = ["load_lookup", "lookup_geo"]
