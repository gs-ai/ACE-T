from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


ITEM_RE = re.compile(r"<div[^>]*class=\"[^\"]*timeline-item[^\"]*\"[^>]*>(?P<body>.*?)</div>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"<a[^>]*href=\"(?P<href>[^\"]+/status/[^\"]*)\"", re.IGNORECASE)
NAME_RE = re.compile(r"<a[^>]*class=\"[^\"]*fullname[^\"]*\"[^>]*>(?P<name>.*?)</a>", re.IGNORECASE | re.DOTALL)


def parse_timeline(html: str, base_url: str) -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in ITEM_RE.finditer(html):
        body = match.group("body")
        link = LINK_RE.search(body)
        href = link.group("href") if link else None
        url = base_url + href if href and href.startswith("/") else href or base_url
        name_match = NAME_RE.search(body)
        title_text = sanitize_html(name_match.group("name")) if name_match else "nitter"
        content = sanitize_html(body)
        items.append(ParsedItem(source="twitter", url=url, title=title_text, content=content))
    return items


__all__ = ["parse_timeline"]
