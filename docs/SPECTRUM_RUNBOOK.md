# SPECTRUM Viewer Runbook (Replicable Launch)

This runbook captures the exact steps + environment settings required to rebuild and launch the ACE-T SPECTRUM 3D viewer in a repeatable way.

## One-Command Launch

```bash
bash scripts/run_graph_viewer.sh
```

What it does:
- Runs a **one-shot graph build** (no streaming)
- Starts the local viewer at `http://localhost:8000/ace_t_spectrum_3d.html`

Run this from the root of the contained bundle (e.g., `SPECTRUM 2`).

## Required Environment

- Python environment: `ace-t-env`
- API key file: `outside_data/ransomware_live_api_key.txt`

Optional env vars (only if needed):
- `RANSOMWARE_LIVE_API_KEY` (overrides file)
- `ACE_T_EXCLUDE_REDDIT=1` (default: on)
- `ACE_T_ENABLE_STREAMING=1` (disabled by default)

## Expected Output

- Graph files written to:
  - `GRAPH_COPY/graph_3d.json`
  - `GRAPH_COPY/graph_3d_render.json`
- Source defs written to:
  - `GRAPH_COPY/data/sources.json`

## Data Sources (Current)

Allowed sources are enforced by:
- `config/ingest_sources.yaml`

Currently graphed:
- `ransomware.live` (victim search results only)

## Stop the Server

```bash
# in the running terminal
Ctrl+C
```

If port 8000 is stuck:
```bash
lsof -ti :8000 | xargs kill -9
```

## Notes

- Streaming builder is **off by default**.
- The viewer polls `graph_3d_render.json` periodically for updates.
