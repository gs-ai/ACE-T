# ACE-T Clean Project — Current Status

## Snapshot
- 2D (Dash/Cytoscape) + 3D (Three.js) GUIs load together.
- Graph starts clean each run and replays the last 30 days from `db/osint.db` (feeds + Reddit alerts).
- Live updates continue via the scheduler (Reddit + realtime open feeds).
- Retention is enforced at 30 days across graph + DB (override with `ACE_T_RETENTION_DAYS`).
- Ingestion health is tracked in `data/ingest_status.json` and served at `/status` + `/health`.

## What It Does Now
- Ingests Reddit posts + comments and writes alerts to `db/osint.db`.
- Ingests realtime open feeds (IOC lists) and writes IOCs + alerts to `db/osint.db`.
- Emits graph nodes/edges into `data/graph_data.json` and exports `data/graph_3d.json`.
- Builds cross-source edges on exact indicator overlap plus domain/URL overlap.
- Preserves semantic edge metadata (e.g., `semantic_weight`, `cross_domain_flag`).
- 3D graph includes lightweight spring motion and pointer dragging (no UI changes).

## Active Sources
Reddit:
- r/InfoSecNews, r/pwnhub, r/OSINT, r/threatintel, r/Malware, r/ReverseEngineering
- r/computerforensics, r/phishing, r/blueteamsec, r/netsec, r/redteamsec
- r/sysadmin, r/cybersecurity, r/IncidentResponse

Realtime open feeds (configurable in `config.yml`):
- threatfox, urlhaus, feodotracker, sslbl, dshield_top, firehol_level1
- emerging_threats_compromised, tor_exit_nodes, stamparm_maltrail, cybercrime_tracker
- `blocklist_de` is present but disabled by default

## Graph Logic (High Level)
- Node mass is computed in `src/adapters/emit_graph.py` from degree, confidence, and recency.
- Confidence/recency inputs are augmented with:
  - `domain_convergence_score`
  - `cross_source_degree`
  - `signal_density`
- Edge weight is normalized to avg node mass, but semantic metadata is preserved.
- Domain overlap edges are added for cross-source signals sharing a root domain.

## Storage
- `db/osint.db`:
  - `alerts` table (Reddit + feed alerts)
  - `iocs` table (feed indicators)
- Graph:
  - `data/graph_data.json` (canonical elements)
  - `data/graph_3d.json` (3D export)

## How It Runs
- `./run_graph.sh` (requires conda `ace-t-env`)
  - clears graph files
  - replays last 30 days from DB (IOCs + Reddit alerts)
  - launches GUI
  - starts scheduler (continuous updates)

## Known Constraints
- HTML fallback for some subreddits may be blocked (403) by Reddit.
- HTML fallback is throttled per subreddit (cooldown + max attempts).
- Edge weights are still normalized for layout; semantic meaning is exposed via metadata.
- 3D motion is lightweight (springy) but not a full physics simulation.

## Recently Added
- DB-backed replay for Reddit alerts with replay caps (per-subsource + total).
- Fallback throttling for Reddit HTML scraping (cooldown + max attempts).
- Ingestion health/status endpoint (`/status`, `/health`) backed by scheduler state file.
- Cross-source matching expanded to domain/URL overlap.

## Enhancements to Consider Next
- Add a minimal status panel in the UI to surface `/status` at a glance.
- Add replay caps per feed/source to `config.yml` (currently env-only).
- Expand fuzzy matching to include hashing heuristics (e.g., URL normalization).
