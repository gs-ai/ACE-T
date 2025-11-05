# ACE-T Nodes Map: Node Connections

In ACE-T's Nodes Map (the Dash Cytoscape visualization), nodes represent alerts, triggers, and domains, and edges define connections between them. The connections are built dynamically as alerts are processed in the GUI (`alert_gui.py`). Here's how it's defined:

## Node Types

- **Alert Nodes**: Each processed alert becomes a node (colored by severity: high=red, medium=orange, mild=yellow, low=green). The node ID is a hash of timestamp, source, trigger ID, and URL to ensure uniqueness.
- **Trigger Nodes**: Group alerts by their trigger (e.g., "credential-leak-keywords"). These are shared across multiple alerts with the same trigger.
- **Domain Nodes**: Group alerts by the domain extracted from the alert's URL (e.g., "example.com"). These are shared across alerts from the same site.

## Edge Definitions (How Nodes Connect)

Edges are created in a **bipartite graph structure** to avoid excessive clutter (no direct alert-to-alert connections, which would create O(n²) edges). Each alert node connects to exactly two other node types:

1. **Alert → Trigger Edge**:
   - **Source**: Alert node.
   - **Target**: Trigger node (e.g., "t:credential-leak-keywords").
   - **Relationship**: "trigger" (indicates the alert was fired by this trigger).
   - **Why**: Groups alerts by what detected them, showing patterns like "multiple alerts from the same keyword trigger."

2. **Alert → Domain Edge**:
   - **Source**: Alert node.
   - **Target**: Domain node (e.g., "d:reddit.com").
   - **Relationship**: "domain" (indicates the alert originated from this domain).
   - **Why**: Groups alerts by source website, highlighting clusters like "many alerts from Reddit."

## Key Code Details

- In `_graph_add_alert` (lines 818–850 in `alert_gui.py`):
  - Alert nodes are added with enriched data (timestamp, source, etc.) for hover/click tooltips.
  - Trigger and domain nodes are created/updated only if they don't exist (using `setdefault`).
  - Edges are added with unique IDs (e.g., "e:alert_id->t:trigger:trigger").
- The graph data is saved to `output/gui_prefs/graph_data.json` as Cytoscape-compatible format (`{"nodes": [...], "edges": [...]}`).
- **No Other Connections**: Alerts aren't connected to each other directly, and triggers/domains aren't connected to each other. This keeps the graph clean and focused on relationships.

## Layout and Visualization

- The Dash server (`dash_cyto_server.py`) loads this data and applies layouts (preset for positions, cose for force-directed if enabled).
- Edges are styled with default Cytoscape arrows (source → target).
- If you want to add more connection types (e.g., alerts sharing the same source or timestamp), the code could be extended in `_graph_add_alert` to create additional edges.

This structure helps visualize alert clusters by trigger and source, making it easier to spot patterns in OSINT data. If your data shows unexpected connections (or lack thereof), it might be due to missing trigger/domain info in the alerts.
