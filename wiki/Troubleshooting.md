# Troubleshooting

This guide lists frequent issues and recommended remediation steps.

## CLI reports "binary files are not supported"

The custom YAML loader expects UTF-8 text. Ensure configuration or entity files are plain text. If editing on Windows, save files with UTF-8 encoding and without BOM. Run `python -m ace_t_osint validate` to pinpoint parse errors.

## No alerts generated

- Confirm triggers and entity packs contain terms relevant to your fixtures or live data.
- Inspect logs for `dedup` counts – high values indicate previously seen content; clear `data/checkpoints/<source>.json` to reset.
- Verify fixture files under `ace_t_osint/fixtures/<source>/sample.html` contain trigger terms.

## HTTP requests skipped

- When running without `aiohttp` (e.g., offline environments), the HTTP client falls back to cached responses. Populate `data/http_cache.json` by performing a connected run at least once.
- Check proxy settings under `tor_or_proxy` if requests fail unexpectedly.

## Scheduler appears idle

- In loop mode, initial offsets can delay the first run by up to `interval / source_count`. This is expected; inspect logs for `scheduler-cycle` events to confirm progress.
- If offsets are too long for testing, temporarily run with `--once` or reduce intervals in `config.yml`.

## Detector changes not applied

- Ensure the `reload.interval_seconds` value is set or pass `--reload-interval` to the `run` command.
- Use `python -m ace_t_osint reload` to force a reload.

## Database locked

- Long-running external queries can lock SQLite. Use WAL mode (enabled by default) and avoid leaving GUI tools connected during runs.
- If the lock persists, stop the crawler, close external tools, and rerun `python -m ace_t_osint vacuum`.

## Log file missing

- Confirm the `logs_dir` exists and is writable. The logging setup creates the directory automatically but may fail if permissions are restricted.
- Review console output; since logging also emits to stdout, you will still receive telemetry even if file writes fail.
