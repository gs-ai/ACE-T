<p align="center">
  <img src="af4a3946-938f-4a9b-94e6-096c3bb949ed.png" alt="SPECTRUM ACE-T Header" style="width:100%; max-width:1200px; border-radius:8px; box-shadow:0 4px 8px rgba(0,0,0,0.1);">
</p>

# SPECTRUM ACE-T: Advanced Cyber-Enabled Threat Intelligence Platform

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" alt="Python 3.11">
  <img src="https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Mode-SPECTRUMv2-orange.svg" alt="Mode">
</p>

---

This is the active codebase. All runnable components live in `SPECTRUMv2`.

## UI Preview

Main graph workspace:

![SPECTRUM Graph Workspace](afoeihw8qp3947hf93q49fqo34qbfogy.png)

Clustered graph view:

![SPECTRUM Cluster View](alsjkdfoweuih9ah9erffhjgoiuh3423.png)

## Quick Start

```bash
cd SPECTRUMv2
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the 3D viewer:

```bash
bash run_graph_viewer.sh
```

Run tiered feed ingestion:

```bash
bash scripts/run_tiered_ingest.sh
```

Run the agents framework:

```bash
bash scripts/run_agents.sh
```

## Graph Data Sources

The graph combines multiple feed groups and source families:

### Primary incidents
- `ransomware.live` victim/event feed

### Infrastructure intel
- `abuse.ch threatfox`
- `abuse.ch urlhaus`
- `abuse.ch feodotracker`
- `c2intelfeeds` (verified + 30d)
- `montysecurity c2 tracker`
- `carbon black c2`

### Reputation context (enrichment)
- `blocklist_de`
- `ipsum` levels (3-8)

### Background knowledge (contextual overlays)
- `cisa_kev`
- optional `nvd_cve` (disabled by default)

Source toggles and URLs are configured in `config/ingest_sources.yaml`.
Source color keys for the UI legend are in `graph/data/sources.json`.

## Project Layout

- `graph/`: graph build + viewer server
- `src/`: feed and ingest runners/modules
- `agents/`: agent pipeline runtime
- `db/`: SQLite helpers + schema
- `config/`: ingest source config
- `outside_data/`: local API key/cached feed files
- `data/`: generated ingest outputs + feed cache
- `requirements.txt` / `requirements.lock.txt`: pinned dependencies

## Security and Privacy Notes

- Keep secrets in environment variables or ignored local files only.
- Do not commit API keys, local cache payloads, or private datasets.
- Scripts set `PYTHONPATH` for local package imports from this folder.
- `run_graph_viewer.sh` uses the active interpreter (`PYTHON_BIN` or current `python`).
- Generated graph artifacts are written to `graph/graph_3d.json` and `graph/graph_3d_render.json`.
