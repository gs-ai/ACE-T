from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


ROW_PATTERN = re.compile(
    r"<tr[^>]*>.*?<a[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>[^<]+)</a>.*?</tr>",
    re.IGNORECASE | re.DOTALL,
)


def parse_public(html: str, base_url: str = "https://ghostbin.com") -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in ROW_PATTERN.finditer(html):
        href = match.group("href")
        url = base_url + href if href.startswith("/") else href
        title = sanitize_html(match.group("title"))
        content = sanitize_html(match.group(0))
        items.append(ParsedItem(source="ghostbin", url=url, title=title, content=content))
    return items


__all__ = ["parse_public"]
