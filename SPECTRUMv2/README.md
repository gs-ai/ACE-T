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

This is the active codebase. All runnable components now live inside `SPECTRUMv2`.

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

## Project Layout

- `graph/`: graph build + viewer server
- `src/`: feed and ingest runners/modules
- `agents/`: agent pipeline runtime
- `db/`: SQLite helpers + schema
- `config/`: ingest source config
- `outside_data/`: local API key/cached feed files
- `requirements.txt` / `requirements.lock.txt`: pinned dependencies

## Notes

- Scripts set `PYTHONPATH` for local package imports from this folder.
- `run_graph_viewer.sh` uses the active interpreter (`PYTHON_BIN` or current `python`).
- Generated graph artifacts are written to `graph/graph_3d.json` and `graph/graph_3d_render.json`.
