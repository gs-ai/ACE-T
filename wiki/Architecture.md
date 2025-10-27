# Architecture

The ACE-T monitoring package (`ace_t_osint`) is designed for offline-friendly, asynchronous HTML collection. The runtime is composed of the layers below.

## High-level flow

1. **Scheduler loop** (`ace_t_osint.scheduler.loop.SchedulerLoop`) assigns offsets and recurring intervals so sources do not start simultaneously.
2. **HTTP acquisition** (`ace_t_osint.utils.http.HttpClientFactory`) uses `aiohttp` with per-source rate limiting, retry backoff, and conditional request headers. Responses and caching metadata are persisted for reuse when the crawler is offline.
3. **HTML sanitisation and parsing** – each parser in `ace_t_osint.parsers.<source>` strips scripts/iframes and yields `ParsedItem` objects with metadata from the source.
4. **Detection pipeline** (`ace_t_osint.detectors`) loads triggers, entity packs, and the sentiment lexicon. The `DetectorManager` in the CLI hot-reloads these packs when files change.
5. **Deduplication** (`ace_t_osint.utils.hashing` and `ace_t_osint.utils.fingerprint`) generates SHA-256 hashes and simhashes. Persistent checkpoints (`ace_t_osint.utils.checkpoint.SeenStore`) prevent reprocessing of already seen content.
6. **Alert emission** – results are serialised in the standard alert schema, sent to SQLite (`ace_t_osint.writers.sqlite_writer.SQLiteWriter`) and JSONL (`ace_t_osint.writers.jsonl_writer.JSONLWriter`), and metrics are appended to the runs table.

![Architecture diagram](https://raw.githubusercontent.com/gs-ai/ACE-T/main/TXTFILES/architecture-diagram.png)

## Package layout

```
ace_t_osint/
├── cli.py                # Entry point for run/validate/reindex/vacuum/reload commands
├── config.yml            # Sample configuration with per-source intervals and retry policy
├── fixtures/             # Offline HTML samples keyed by source
├── parsers/              # HTML parsing functions for each supported source
├── detectors/            # Rule engine, entity loader, sentiment heuristics
├── utils/                # HTTP client, hashing, simhash, geoparsing, checkpoints, etc.
├── writers/              # SQLite and JSONL writers
├── scheduler/loop.py     # Async scheduler with jittered start offsets
├── migrate.py            # SQLite schema initialiser
└── triggers/triggers.json# Regex/keyword rule definitions
```

Each component communicates with simple Python data structures, making the system easy to extend and test without network access.
