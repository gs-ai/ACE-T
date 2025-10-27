# Alert Schema

Alerts produced by the framework conform to the JSON structure below. Each field is populated by the detection pipeline using parser metadata, trigger output, and enrichment utilities.

```json
{
  "geo_info": {"country": "...", "city": "...", "lat": null, "lon": null},
  "source_url": "https://...",
  "detected_at": "2025-04-21T18:42:03Z",
  "first_seen": "2025-04-21T18:42:03Z",
  "last_seen": "2025-04-21T18:42:03Z",
  "entities": {
    "orgs": ["..."],
    "persons": ["..."],
    "keywords": ["..."]
  },
  "threat_analysis": {
    "summary": "Matched text excerpt",
    "risk_vector": "keyword",
    "related_terms": ["..."],
  },
  "trend_velocity": {
    "pct_increase": 0.0,
    "prev_volume": 0,
    "curr_volume": 1
  },
  "sentiment": "neg|neu|pos",
  "tags": ["..."],
  "classification": "public|sensitive|credential|pii",
  "source_name": "pastebin|ghostbin|...",
  "content_hash": "<sha256>",
  "content_excerpt": "First 500 chars of cleaned content",
  "simhash": "<simhash value>"
}
```

## Field population

- `geo_info` – Derived from `ace_t_osint.utils.geoparse.lookup_geo`, which performs lexicon-based lookups.
- `entities` – Provided by `ace_t_osint.detectors.analyzer.Detector` using YAML entity packs in `ace_t_osint/entities/`.
- `threat_analysis.summary` – Populated with the matched trigger text; `risk_vector` reflects rule tags.
- `trend_velocity` – Computed using historical run metrics fetched from SQLite (previous alert counts).
- `sentiment` – Result of the lexicon/model pipeline in `ace_t_osint.utils.sentiment.SentimentAnalyzer`.
- `content_hash`/`simhash` – Generated in `ace_t_osint.utils.hashing` and `ace_t_osint.utils.fingerprint` after HTML sanitisation.

## Persistence

Alerts are written to:

1. **SQLite (`data/osint.db`)** – `alerts` table holds the JSON payload, keyed by `(content_hash, source_name)`. Duplicate detections update `last_seen` timestamps.
2. **JSONL (`data/alerts/YYYY/MM/DD/alerts.jsonl`)** – Append-only log for downstream processing or auditing.
3. **Seen store (`data/checkpoints/<source>.json`)** – Maintains seen hashes to prevent duplicates across runs.

Use `python -m ace_t_osint reindex` to inspect the database indexes and `python -m ace_t_osint vacuum` to reclaim space after large runs.
