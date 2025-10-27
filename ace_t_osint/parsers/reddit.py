from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


POST_RE = re.compile(
    r"<div[^>]*class=\"[^\"]*thing[^\"]*\"[^>]*>(?P<body>.*?)</div>", re.IGNORECASE | re.DOTALL
)
TITLE_RE = re.compile(r"<a[^>]*class=\"[^\"]*title[^\"]*\"[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>.*?)</a>", re.IGNORECASE | re.DOTALL)


def parse_listing(html: str, base_url: str = "https://old.reddit.com") -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in POST_RE.finditer(html):
        body = match.group("body")
        title_match = TITLE_RE.search(body)
        if not title_match:
            continue
        href = title_match.group("href")
        url = base_url + href if href.startswith("/") else href
        title = sanitize_html(title_match.group("title"))
        content = sanitize_html(body)
        items.append(ParsedItem(source="reddit", url=url or base_url, title=title, content=content))
    return items


__all__ = ["parse_listing"]
