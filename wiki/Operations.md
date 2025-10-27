# Operations

This page explains how to run, monitor, and maintain the ACE-T OSINT crawler.

## Command-line interface

Use `python -m ace_t_osint` to access the CLI. Commands include:

| Command | Purpose |
|---------|---------|
| `python -m ace_t_osint run --sources all --once` | Execute a single pass across all configured sources.
| `python -m ace_t_osint run --sources pastebin,reddit --loop` | Continuously run selected sources using the scheduler. |
| `python -m ace_t_osint run --sources all --loop --reload-interval 300` | Loop with detector pack checks every 5 minutes. |
| `python -m ace_t_osint run --sources telegram --once --from-checkpoint` | Resume using saved seen hashes. |
| `python -m ace_t_osint run --sources archive_org --once --since 2025-01-01` | Seed historical data for sources that expose archives. |
| `python -m ace_t_osint validate` | Print the parsed configuration to stdout. |
| `python -m ace_t_osint reload` | Force trigger/entity pack reload without a full run. |
| `python -m ace_t_osint reindex` | Display SQLite index definitions. |
| `python -m ace_t_osint vacuum` | Compact the SQLite database. |

## Logging

`ace_t_osint.cli.setup_logging` installs JSON-format handlers for both the console and `logs/osint.log`. Every log entry contains a timestamp, level, logger, and contextual extras. Example entry:

```json
{"time": "2025-04-21T18:42:03Z", "level": "INFO", "logger": "ace_t_osint.cli", "message": "source-run", "source": "pastebin", "alerts": 2, "fetched": 1}
```

Per-source metrics emitted at the end of each run include:

- `fetched` – number of HTML pages processed
- `alerts` – alerts generated during the run
- `dedup` – content suppressed due to prior sightings
- `bytes_in` – total bytes collected
- `errors` – failed fetch attempts
- `cache_hits` – responses served from the HTTP cache
- `fixtures_used` – fixtures used instead of live HTTP
- `avg_latency_ms` – average latency of successful HTTP responses

The scheduler also logs `scheduler-cycle` events with elapsed run time and interval data.

## HTTP caching

The HTTP client stores responses and metadata in `data/http_cache.json`. When network access is unavailable, cached bodies are replayed and marked with `from_cache=true`. Conditional headers (`If-None-Match`, `If-Modified-Since`) are automatically attached to reduce bandwidth.

## Metrics persistence

`SQLiteWriter.record_run` writes the metrics block into the `runs` table alongside start/finish timestamps. Use `python -m ace_t_osint reindex` to inspect indices or query the database directly:

```sql
SELECT source_name, metrics FROM runs ORDER BY id DESC LIMIT 5;
```

## Scheduler behaviour

When multiple sources loop simultaneously, the scheduler assigns deterministic offsets proportional to the interval length and adds random jitter so the first iteration is not bursty. Offsets ensure polite crawling even immediately after startup.

## Reloading triggers and entities

The CLI’s `--reload-interval` option (or the config value under `reload.interval_seconds`) instructs the `DetectorManager` to check timestamps of trigger and entity files. Updates are picked up without restarting the process. Use the `reload` subcommand for an immediate refresh.
