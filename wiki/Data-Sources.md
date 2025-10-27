# Data Sources

ACE-T focuses on zero-API HTML collection. Each parser is built to consume cleaned HTML and emit `ParsedItem` instances with the fields expected by the detection pipeline.

| Source        | Parser module                         | Default interval (s) | Notes |
|---------------|----------------------------------------|----------------------|-------|
| Pastebin      | `ace_t_osint.parsers.pastebin`        | 300                  | Scrapes the public archive feed and user pages. |
| Ghostbin      | `ace_t_osint.parsers.ghostbin`        | 300                  | Parses the public listing page. |
| Rentry        | `ace_t_osint.parsers.rentry`          | 600                  | Fetches individual pages; URLs configured in `config.yml`. |
| Reddit        | `ace_t_osint.parsers.reddit`          | 600                  | Targets `old.reddit.com` HTML or RSS snapshots. |
| Chans         | `ace_t_osint.parsers.chans`           | 600                  | Processes catalog JSON embedded in board HTML. |
| Telegram      | `ace_t_osint.parsers.telegram`        | 600                  | Parses channel pages and paginated archives. |
| Twitter (Nitter) | `ace_t_osint.parsers.nitter`       | 600                  | Uses Nitter HTML mirrors only. |
| Archive.org   | `ace_t_osint.parsers.archive_org`     | 900                  | Tracks Wayback snapshots and availability changes. |
| GitHub        | `ace_t_osint.parsers.github`          | 900                  | Collects repository and gist HTML. |
| crt.sh        | `ace_t_osint.parsers.crtsh`           | 900                  | Scrapes certificate search results. |

## HTML fixtures

Every parser ships with an accompanying sample under `ace_t_osint/fixtures/<source>/sample.html`. These fixtures are referenced automatically when a network request fails or is disabled. You can override or extend the fixture search path by setting `fixture_dir` in `config.yml`.

## Adding new sources

1. Implement a parser that accepts sanitised HTML and yields `ParsedItem` objects. Reuse helpers from `ace_t_osint.utils.html` for stripping scripts, normalising whitespace, and extracting metadata.
2. Update `ace_t_osint/cli.py` to map the new source name to the parser callable in `parser_for_source`.
3. Extend `config.yml` with scrape interval, concurrency, and seed URLs.
4. Create a fixture sample under `ace_t_osint/fixtures/<source>/sample.html` and add unit tests in `tests/test_parsers.py` using the fixture to validate parsing behaviour.
5. Document the new source here and ensure triggers/entities cover the expected terminology.
