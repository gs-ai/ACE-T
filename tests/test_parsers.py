from pathlib import Path

from ace_t_osint.parsers import pastebin, reddit, github


def _load(name: str, source: str) -> str:
    return (Path("tests/fixtures") / source / name).read_text(encoding="utf-8")


def test_pastebin_parser_extracts_rows():
    html = _load("sample.html", "pastebin")
    items = pastebin.parse_archive(html)
    assert items
    assert items[0].title == "Leaked password list"


def test_reddit_parser_extracts_posts():
    html = _load("sample.html", "reddit")
    items = reddit.parse_listing(html)
    assert items
    assert "CVE" in items[0].content


def test_github_parser_extracts_files():
    html = _load("sample.html", "github")
    items = github.parse_repo(html, "https://github.com/example/repo")
    assert items
    assert items[0].title == "example/repo"
