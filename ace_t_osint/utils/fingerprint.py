from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc.lower()
    path = re.sub(r"/+$", "", parsed.path) or "/"
    query = "&".join(sorted(filter(None, parsed.query.split("&"))))
    normalized = urlunparse((scheme, netloc, path, "", query, ""))
    return normalized


__all__ = ["normalize_url"]
