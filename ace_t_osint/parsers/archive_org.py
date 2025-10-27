from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


CAPTURE_RE = re.compile(
    r"<a[^>]*class=\"[^\"]*capture-list[^\"]*\"[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)


def parse_wayback(html: str, base_url: str) -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in CAPTURE_RE.finditer(html):
        href = match.group("href")
        title = sanitize_html(match.group("title"))
        url = base_url + href if href.startswith("/") else href
        context_match = match.group(0)
        content = sanitize_html(context_match)
        items.append(ParsedItem(source="archive_org", url=url, title=title, content=content))
    return items


__all__ = ["parse_wayback"]
