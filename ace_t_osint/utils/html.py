from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from typing import Iterable, List


SCRIPT_TAGS = {"script", "iframe", "style"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._texts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs):  # type: ignore[override]
        if tag.lower() in SCRIPT_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str):  # type: ignore[override]
        if tag.lower() in SCRIPT_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if self._skip_depth:
            return
        text = data.strip()
        if text:
            self._texts.append(text)

    def get_text(self) -> str:
        return " ".join(self._texts)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs):  # type: ignore[override]
        if tag.lower() == "a":
            for attr, value in attrs:
                if attr.lower() == "href" and value:
                    self.links.append(value)


def sanitize_html(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    return parser.get_text()


def extract_links(html: str) -> Iterable[str]:
    parser = _LinkExtractor()
    parser.feed(html)
    return parser.links


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", unescape(text)).strip()


__all__ = ["sanitize_html", "extract_links", "normalize_whitespace"]
