# ACE-T SPECTRUM

ACE-T clean runtime focused on the reddit + realtime feed graph pipeline.

## Run

```bash
conda run -n ace-t-env bash run_graph.sh
```

This launches:
- The 2D Cytoscape GUI (Dash) on `http://127.0.0.1:8050`
- The 3D Three.js GUI on `http://127.0.0.1:8050/3d`
- The ingestion scheduler (reddit + realtime feeds)

## Timezone Configuration

ACE-T renders all node timestamps in a fixed timezone defined in `cyto_gui.py`.

To change it, edit the constant near the top of `cyto_gui.py`:

```python
TIMEZONE = "US/Central"
```

Examples: `UTC`, `US/Eastern`, `US/Central`, `US/Pacific`.

If an invalid timezone is supplied, the system timezone will be used automatically.
