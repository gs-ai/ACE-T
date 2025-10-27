from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


ROW_RE = re.compile(r"<tr>(?P<cells>.*?)</tr>", re.IGNORECASE | re.DOTALL)
CELL_RE = re.compile(r"<td[^>]*>(?P<cell>.*?)</td>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"<a[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>.*?)</a>", re.IGNORECASE | re.DOTALL)


def parse_results(html: str, base_url: str = "https://crt.sh") -> list[ParsedItem]:
    items: list[ParsedItem] = []
    rows = ROW_RE.findall(html)
    if not rows:
        return items
    for row_html in rows[1:]:
        cells = CELL_RE.findall(row_html)
        if not cells:
            continue
        link_match = LINK_RE.search(cells[0])
        href = link_match.group("href") if link_match else None
        url = base_url + href if href and href.startswith("/") else href or base_url
        title = sanitize_html(link_match.group("title")) if link_match else sanitize_html(cells[0])
        content = sanitize_html(" ".join(sanitize_html(cell) for cell in cells))
        items.append(ParsedItem(source="crtsh", url=url, title=title, content=content))
    return items


__all__ = ["parse_results"]
