from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


TITLE_RE = re.compile(r"<strong[^>]*itemprop=\"name\"[^>]*>\s*<a[^>]*>(?P<title>[^<]+)</a>", re.IGNORECASE)
FILE_RE = re.compile(
    r"<a[^>]*class=\"[^\"]*js-navigation-open[^\"]*Link--primary[^\"]*\"[^>]*href=\"(?P<href>[^\"]+)\"[^>]*>(?P<text>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)


def parse_repo(html: str, base_url: str) -> list[ParsedItem]:
    title_match = TITLE_RE.search(html)
    repo_name = sanitize_html(title_match.group("title")) if title_match else base_url
    items: list[ParsedItem] = []
    for match in FILE_RE.finditer(html):
        href = match.group("href")
        url = "https://github.com" + href if href.startswith("/") else href
        content = sanitize_html(match.group("text"))
        items.append(ParsedItem(source="github", url=url, title=repo_name, content=content))
    return items


__all__ = ["parse_repo"]
