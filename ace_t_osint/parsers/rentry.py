from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


TITLE_RE = re.compile(r"<h1[^>]*>(?P<title>.*?)</h1>", re.IGNORECASE | re.DOTALL)
CONTENT_RE = re.compile(r"<div[^>]*class=\"[^\"]*content[^\"]*\"[^>]*>(?P<body>.*?)</div>", re.IGNORECASE | re.DOTALL)


def parse_page(html: str, url: str) -> list[ParsedItem]:
    title_match = TITLE_RE.search(html)
    title = sanitize_html(title_match.group("title")) if title_match else "rentry"
    content_match = CONTENT_RE.search(html)
    if content_match:
        content_raw = content_match.group("body")
    else:
        content_raw = html
    content = sanitize_html(content_raw)
    return [ParsedItem(source="rentry", url=url, title=title, content=content)]


__all__ = ["parse_page"]
