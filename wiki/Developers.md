# Developer Guide

This page summarises workflows for contributors extending the ACE-T monitoring stack.

## Environment setup

1. Create a Python 3.11 environment.
2. Install dependencies: `pip install -r requirements.txt`.
3. Run migrations: `python -m ace_t_osint.migrate`.
4. Execute the test suite: `pytest`.

## Repository structure highlights

- `ace_t_osint/parsers/` – HTML parsing logic. Tests live in `tests/test_parsers.py` with fixtures under `ace_t_osint/fixtures/`.
- `ace_t_osint/detectors/` – Rule engine (`rules_engine.py`), detector orchestration (`analyzer.py`), entity loader, and sentiment lexicon.
- `ace_t_osint/utils/` – HTTP client, hashing, fingerprinting, geoparsing, and checkpoint persistence.
- `ace_t_osint/writers/` – Output writers for SQLite and JSONL.
- `ace_t_osint/scheduler/loop.py` – Async scheduling utilities.
- `tests/` – Unit, property, and integration coverage.

## Coding guidelines

- Maintain asynchronous patterns when touching fetch logic. Use `asyncio`, `aiohttp`, and the shared `HttpClientFactory`.
- Avoid introducing APIs or authenticated endpoints; only HTML fetches are allowed.
- Keep new configuration keys documented in `config.yml` and the wiki.
- Extend entity packs by editing YAML files under `ace_t_osint/entities/` and add regression tests when expanding coverage.

## Adding detectors or rules

1. Update `ace_t_osint/triggers/triggers.json` with new patterns, tags, or classification values.
2. If additional context is needed, edit or create YAML entity packs.
3. Run `python -m ace_t_osint reload` or use `--reload-interval` to hot-reload during loop mode.
4. Validate matches with unit tests under `tests/test_rules_engine.py` or dedicated fixtures.

## Database migrations

`ace_t_osint/migrate.py` can be executed repeatedly; it creates missing tables (`alerts`, `seen`, `runs`, `errors`) and indexes. If schema changes are required, extend the migration script with idempotent SQL.

## Testing strategy

- **Parsers:** Add fixtures and assertions to `tests/test_parsers.py`. Focus on resilience to minor HTML changes.
- **Trigger engine:** Property tests in `tests/test_rules_engine.py` cover include/exclude logic. Extend with edge cases when adding DSL features.
- **Deduplication:** `tests/test_dedupe.py` validates hashing and simhash thresholds. Update as necessary.
- **Integration:** `tests/test_integration.py` runs the full pipeline against fixtures, checking alert schema conformity.

## Release checklist

- Ensure `pytest` passes.
- Run `python -m ace_t_osint validate` to confirm configuration integrity.
- Perform a fixture-based dry run (`python -m ace_t_osint run --sources all --once`).
- Update the wiki and README if new features alter operator workflows.
