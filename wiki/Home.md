# ACE-T OSINT Framework Wiki

Welcome to the ACE-T project wiki. This documentation explains how the offline-friendly OSINT monitoring framework is organised, configured, and extended. The content is divided into dedicated pages:

- [[Architecture]] – runtime components and data flow
- [[Data-Sources]] – supported HTML-only data sources and parsing expectations
- [[Configuration]] – configuration file structure and tunables
- [[Operations]] – CLI usage, scheduler behaviour, logging, and metrics
- [[Alert-Schema]] – alert payload definition and storage layout
- [[Developers]] – guidance for extending parsers, detectors, and tests
- [[Troubleshooting]] – common issues and remediation steps

## Key capabilities

* **Async-first ingestion.** Every source is fetched with `aiohttp`, per-source rate limiting, jitter, retry backoff, and conditional HTTP headers so repeat crawls reuse cached content when possible. [[Architecture]] and [[Operations]] describe the flow in detail.
* **Deterministic deduplication.** Normalised content is hashed (SHA-256) and simhashed before alerts are emitted. Seen fingerprints persist to disk to survive restarts.
* **Rule-driven detections.** Triggers defined in `ace_t_osint/triggers/triggers.json` combine regex and keyword rules that are enriched with dictionary-based entity extraction and sentiment heuristics.
* **Structured persistence.** Alerts are written to SQLite (`data/osint.db`) and daily JSONL files (`data/alerts/YYYY/MM/DD/alerts.jsonl`). Runs and errors are also tracked for auditability.
* **Offline-ready fixtures.** Each source has a bundled HTML sample under `ace_t_osint/fixtures/<source>/sample.html` so tests and dry runs succeed without internet access.
* **Unified CLI.** `python -m ace_t_osint` exposes commands to run, validate, reindex, vacuum, and reload detectors without restarting the service.

## Quick start for operators

1. Install dependencies from `requirements.txt` (or the provided Conda environment).
2. Run the database migration via `python -m ace_t_osint.migrate`.
3. Launch a dry run with fixtures: `python -m ace_t_osint run --sources all --once`.
4. Inspect `logs/osint.log` or the console for JSON-formatted telemetry.

For detailed workflows refer to [[Operations]].
