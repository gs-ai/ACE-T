from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


THREAD_RE = re.compile(r"<div[^>]*class=\"[^\"]*thread[^\"]*\"[^>]*>(?P<body>.*?)</div>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"<a[^>]*class=\"[^\"]*(replylink|qlink)[^\"]*\"[^>]*href=\"(?P<href>[^\"]+)\"", re.IGNORECASE)


def parse_catalog(html: str, base_url: str) -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in THREAD_RE.finditer(html):
        body = match.group("body")
        link = LINK_RE.search(body)
        if not link:
            continue
        href = link.group("href")
        url = base_url + href if href.startswith("/") else href
        title_attr = re.search(r"data-subject=\"(?P<title>[^\"]+)\"", match.group(0))
        title = sanitize_html(title_attr.group("title")) if title_attr else sanitize_html(body)[:80]
        content = sanitize_html(body)
        items.append(ParsedItem(source="chans", url=url, title=title, content=content))
    return items


__all__ = ["parse_catalog"]
