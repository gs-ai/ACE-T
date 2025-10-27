from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


ROW_PATTERN = re.compile(
    r"<tr>\s*<td[^>]*>\s*<a[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>[^<]+)</a>.*?</tr>",
    re.IGNORECASE | re.DOTALL,
)


def parse_archive(html: str, base_url: str = "https://pastebin.com") -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in ROW_PATTERN.finditer(html):
        href = match.group("href")
        title = sanitize_html(match.group("title"))
        url = base_url + href if href.startswith("/") else href
        snippet_match = match.group(0)
        content = sanitize_html(snippet_match)
        items.append(ParsedItem(source="pastebin", url=url, title=title, content=content))
    return items


__all__ = ["parse_archive"]
