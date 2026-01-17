# ACE-T SPECTRUM

ACE-T clean runtime focused on the reddit + realtime feed graph pipeline.

## Run

```bash
conda run -n ace-t-env bash run_graph.sh
```

This launches:
- The 3D Three.js GUI on `http://127.0.0.1:8050/three_view_3d.html`
- The ingestion scheduler (reddit + realtime feeds)

## Timezone Configuration

ACE-T renders all node timestamps in a fixed timezone defined in the 3D interface.

To change it, edit the timezone setting in the Three.js interface.

```python
TIMEZONE = "US/Central"
```

Examples: `UTC`, `US/Eastern`, `US/Central`, `US/Pacific`.

If an invalid timezone is supplied, the system timezone will be used automatically.
