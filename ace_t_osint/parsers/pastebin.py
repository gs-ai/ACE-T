from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


# Find <tr> blocks which contain archive rows. Pastebin markup may change and
# include nested tags, so pull each <tr> and then extract the first anchor
# inside it rather than relying on a single rigid regex.
TR_PATTERN = re.compile(r"<tr[^>]*>.*?</tr>", re.IGNORECASE | re.DOTALL)
ANCHOR_PATTERN = re.compile(r"<a[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<title>.*?)</a>", re.IGNORECASE | re.DOTALL)


def parse_archive(html: str, base_url: str = "https://pastebin.com") -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for tr in TR_PATTERN.findall(html):
        anchor = ANCHOR_PATTERN.search(tr)
        if not anchor:
            continue
        href = anchor.group("href")
        title = sanitize_html(anchor.group("title"))
        if title:
            title = title.strip()
        url = base_url + href if href.startswith("/") else href
        content = sanitize_html(tr)
        items.append(ParsedItem(source="pastebin", url=url, title=title, content=content))
    return items


__all__ = ["parse_archive"]
