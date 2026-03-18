from __future__ import annotations
import re
from typing import Dict, List

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I),
    "email": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "url": re.compile(r"\bhttps?://[^\s<>\]]+\b", re.I),
}

def extract_iocs(text: str) -> Dict[str, List[str]]:
    out = {}
    for k, rx in IOC_PATTERNS.items():
        hits = rx.findall(text or "")
        if hits:
            # de-dupe while keeping order
            seen = set()
            uniq = []
            for h in hits:
                if h not in seen:
                    seen.add(h)
                    uniq.append(h)
            out[k] = uniq
    return out
