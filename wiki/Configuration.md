# Configuration

The sample configuration (`ace_t_osint/config.yml`) demonstrates the structure expected by the CLI. Settings are divided into global and per-source sections.

## Global keys

| Key | Description |
|-----|-------------|
| `logs_dir` | Directory where JSON-formatted logs are stored. The console also receives structured output. |
| `alert_output_dir` | Root directory for JSONL alert files (partitioned by year/month/day). |
| `checkpoint_dir` | Folder used to persist seen hashes per source for resume support. |
| `http_cache_path` | Location of the HTTP response cache (stores body, ETag, Last-Modified, timestamp). |
| `scrape_interval_seconds` | Mapping of source name → default crawl interval. |
| `concurrency` | Mapping of source name → maximum concurrent HTTP requests. |
| `user_agents` | List of user-agent strings rotated per request. |
| `retry_policy` | `max_attempts`, `base_delay_seconds`, and `max_delay_seconds` for network retries. |
| `jitter_bounds` | `min_seconds`/`max_seconds` used to spread out retries and scheduler offsets. |
| `robots_policy` | `respect`, `ignore`, or source-specific overrides. Currently advisory; customise in `utils.http`. |
| `tor_or_proxy` | Optional proxy configuration (`enabled`, `url`). Leave disabled for direct connections. |
| `fixture_dir` | Optional path for additional HTML fixtures searched before bundled samples. |
| `reload.interval_seconds` | Optional detector reload cadence when running in loop mode. |
| `sentiment_model_path` | Optional path to a local sentiment model. When missing, lexicon-based heuristics are used. |

## Per-source configuration

Each entry under `sources` accepts at minimum a `urls` list. Sources without URLs rely on embedded navigation (e.g., catalog pages). Example:

```yaml
sources:
  pastebin:
    urls:
      - "https://pastebin.com/archive"
      - "https://pastebin.com/u/someuser"
  telegram:
    urls:
      - "https://t.me/s/examplechannel"
```

You can also set additional keys that are consumed by parsers or detectors (e.g., `board_ids` for chans) by extending the parser implementation.

## Configuration workflow

1. Copy `ace_t_osint/config.yml` to a writable location if you prefer to keep project defaults untouched.
2. Export `ACE_T_CONFIG` environment variable pointing to the new file, or replace the bundled configuration.
3. Run `python -m ace_t_osint validate` to print the parsed configuration and confirm syntax.
4. Adjust intervals and concurrency cautiously; the scheduler already staggers first runs based on interval length to avoid bursts.

When running offline with fixtures, ensure `fixture_dir` points to a directory containing additional samples if needed.
