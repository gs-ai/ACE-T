from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

# Default simple keyword lookup as a final fallback
_DEFAULT_LOOKUP = {
    "usa": {"country": "United States", "city": None, "lat": None, "lon": None},
    "europe": {"country": "Europe", "city": None, "lat": None, "lon": None},
}

# Ollama configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi4-mini")
OLLAMA_FALLBACK = [m for m in os.getenv("OLLAMA_FALLBACK", "deepcoder:1.5b,gemma2").split(",") if m]
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "30"))
OLLAMA_ENABLE = os.getenv("OLLAMA_ENABLE", "1").strip() not in ("0", "false", "False")


def load_lookup(path: Optional[str]) -> Dict[str, Dict[str, Optional[str]]]:
    if not path:
        return _DEFAULT_LOOKUP
    path_obj = Path(path)
    if not path_obj.exists():
        logger.warning("geo-lookup-missing", extra={"path": str(path_obj)})
        return _DEFAULT_LOOKUP
    with path_obj.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _try_parse_location_json(raw: object) -> Optional[dict]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raw = str(raw)
    cleaned = raw.strip().strip('`\n ')
    cleaned = re.sub(r'^json[:\s]*', '', cleaned, flags=re.IGNORECASE)
    try:
        return json.loads(cleaned)
    except Exception:
        pass
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def _ollama_query_location(text: str) -> Optional[dict]:
    """Query local Ollama to geocode text into a JSON location object.

    Returns a dict with keys such as address/city/state/country/latitude/longitude, or None.
    """
    if not OLLAMA_ENABLE:
        return None
    excerpt = text.strip()
    if len(excerpt) > 6000:
        excerpt = excerpt[:6000]
    prompt = (
        "You are a geolocation analyst. Read the following text and respond with a JSON object ONLY (no commentary) "
        "containing: 'location_name', 'address', 'city', 'state', 'postal_code', 'country', 'latitude', 'longitude', 'confidence'. "
        "If a field is unknown, set it to null. Text:\n" + excerpt
    )
    models_to_try = [OLLAMA_MODEL] + [m for m in OLLAMA_FALLBACK if m and m != OLLAMA_MODEL]
    payload_base = {"prompt": prompt, "stream": False}

    for model in models_to_try:
        payload = {"model": model, **payload_base}
        # HTTP first
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            resp.raise_for_status()
            data = None
            try:
                data = resp.json()
            except Exception:
                data = None
            candidate = None
            if isinstance(data, dict):
                candidate = data.get("response") or data.get("text") or data.get("output") or data
            elif isinstance(data, str):
                candidate = data
            if candidate is not None:
                parsed = _try_parse_location_json(candidate)
                if parsed:
                    return parsed
        except requests.Timeout:
            continue
        except Exception:
            # fall through to CLI for this model
            pass

        # CLI fallback
        try:
            proc = subprocess.run(["ollama", "generate", model, "--prompt", prompt, "--json"], capture_output=True, text=True, timeout=OLLAMA_TIMEOUT)
            if proc.returncode == 0 and proc.stdout:
                parsed = _try_parse_location_json(proc.stdout.strip())
                if parsed:
                    return parsed
            proc2 = subprocess.run(["ollama", "generate", model, "--prompt", prompt], capture_output=True, text=True, timeout=OLLAMA_TIMEOUT)
            if proc2.returncode == 0 and proc2.stdout:
                parsed = _try_parse_location_json(proc2.stdout.strip())
                if parsed:
                    return parsed
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
    return None


def lookup_geo(text: str, lookup: Optional[Dict[str, Dict[str, Optional[str]]]] = None) -> Dict[str, Optional[str]]:
    """Geolocate text using Ollama first; fall back to simple keyword lookup.

    Returns a dict with keys country, city, lat, lon (and possibly others if provided by model).
    """
    # Try Ollama-based extraction first
    try:
        result = _ollama_query_location(text)
    except Exception as e:
        logger.debug("ollama-geoparse-error", exc_info=e)
        result = None

    if isinstance(result, dict):
        # Normalize keys to expected shape
        lat = result.get("latitude") or result.get("lat")
        lon = result.get("longitude") or result.get("lon")
        city = result.get("city")
        country = result.get("country")
        out = {
            "country": country,
            "city": city,
            "lat": lat,
            "lon": lon,
        }
        # Include extras if present
        for k in ("state", "postal_code", "address", "location_name", "confidence"):
            if k in result:
                out[k] = result.get(k)
        return out

    # Fallback to keyword lookup
    lookup = lookup or _DEFAULT_LOOKUP
    text_lower = text.lower()
    for key, value in lookup.items():
        if key in text_lower:
            return value
    return {"country": None, "city": None, "lat": None, "lon": None}


__all__ = ["load_lookup", "lookup_geo"]
