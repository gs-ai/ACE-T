from __future__ import annotations

import re

from . import ParsedItem
from ..utils.html import sanitize_html


MESSAGE_RE = re.compile(
    r"<div[^>]*class=\"[^\"]*tgme_widget_message_wrap[^\"]*\"[^>]*>(?P<body>.*?)</div>",
    re.IGNORECASE | re.DOTALL,
)
LINK_RE = re.compile(r"<a[^>]*class=\"[^\"]*tgme_widget_message_date[^\"]*\"[^>]*href=\"(?P<href>[^\"]+)\"", re.IGNORECASE)
USER_RE = re.compile(r"<div[^>]*class=\"[^\"]*tgme_widget_message_user[^\"]*\"[^>]*>(?P<user>.*?)</div>", re.IGNORECASE | re.DOTALL)


def parse_channel(html: str, base_url: str) -> list[ParsedItem]:
    items: list[ParsedItem] = []
    for match in MESSAGE_RE.finditer(html):
        body = match.group("body")
        link = LINK_RE.search(body)
        url = link.group("href") if link else base_url
        user_match = USER_RE.search(body)
        title_text = sanitize_html(user_match.group("user")) if user_match else "telegram"
        content = sanitize_html(body)
        items.append(ParsedItem(source="telegram", url=url, title=title_text, content=content))
    return items


__all__ = ["parse_channel"]
