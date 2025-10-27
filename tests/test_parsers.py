from pathlib import Path

from ace_t_osint.parsers import (
    archive_org,
    chans,
    crtsh,
    ghostbin,
    github,
    nitter,
    pastebin,
    reddit,
    rentry,
    telegram,
)


def _load(name: str, source: str) -> str:
    return (Path("ace_t_osint/fixtures") / source / name).read_text(encoding="utf-8")


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


def test_ghostbin_parser_extracts_bins():
    html = _load("sample.html", "ghostbin")
    items = ghostbin.parse_public(html)
    assert items
    assert items[0].url.endswith("ghost123")


def test_rentry_parser_returns_page():
    html = _load("sample.html", "rentry")
    items = rentry.parse_page(html, "https://rentry.org/sample")
    assert items
    assert items[0].title == "Rentry Threat Report"


def test_chans_parser_extracts_threads():
    html = _load("sample.html", "chans")
    items = chans.parse_catalog(html, "https://boards.4channel.org")
    assert items
    assert "Zero-Day" in items[0].title


def test_telegram_parser_extracts_messages():
    html = _load("sample.html", "telegram")
    items = telegram.parse_channel(html, "https://t.me/cyberalerts")
    assert items
    assert "cyber alerts channel" in items[0].content.lower()


def test_nitter_parser_extracts_tweets():
    html = _load("sample.html", "twitter")
    items = nitter.parse_timeline(html, "https://nitter.net")
    assert items
    assert items[0].url.endswith("123456789")


def test_archive_parser_extracts_captures():
    html = _load("sample.html", "archive_org")
    items = archive_org.parse_wayback(html, "https://web.archive.org")
    assert items
    assert "Example Domain" in items[0].title


def test_crtsh_parser_extracts_rows():
    html = _load("sample.html", "crtsh")
    items = crtsh.parse_results(html)
    assert items
    assert "example.com" in items[0].title
