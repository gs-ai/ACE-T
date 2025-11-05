"""
Dash Cytoscape server for ACE-T

Renders a live graph of alerts next to the Tkinter map. Elements are loaded
from a JSON file (nodes/edges) that the Tkinter GUI maintains.

Environment variables:
- ACE_T_GRAPH_DATA: absolute path to graph_data.json (default: output/gui_prefs/graph_data.json)
- DASH_PORT: port to serve on (default: 8060)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import webbrowser
import sys

import dash
from dash import dcc, html
import dash_cytoscape as cyto
from dash.dependencies import Input, Output

SEVERITY_COLORS = {
    "high": "#ff073a",     # Neon red
    "medium": "#ff9f1a",   # Neon orange (matches 🟧)
    "mild": "#f4ff52",     # Neon yellow
    "low": "#39ff14",      # Neon green
}

# Resolve data file path
# Project root is two levels up from this file (ACE-T/ace_t_osint/gui/..)
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GRAPH_PATH = REPO_ROOT / "output" / "gui_prefs" / "graph_data.json"
GRAPH_PATH = Path(os.environ.get("ACE_T_GRAPH_DATA", str(DEFAULT_GRAPH_PATH)))
PORT = int(os.environ.get("DASH_PORT", "8060"))

external_stylesheets = [
    {
        "href": "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap",
        "rel": "stylesheet",
    }
]

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
server = app.server

# Basic health endpoint for troubleshooting
@server.route("/health")
def _health():  # type: ignore
    try:
        elems = _load_elements()
        n_nodes = len([e for e in elems if isinstance(e, dict) and e.get("data", {}).get("source") is None and e.get("data", {}).get("target") is None])
        n_edges = len([e for e in elems if isinstance(e, dict) and e.get("data", {}).get("source") is not None and e.get("data", {}).get("target") is not None])
        return {
            "ok": True,
            "graph_path": str(GRAPH_PATH),
            "exists": GRAPH_PATH.exists(),
            "nodes": n_nodes,
            "edges": n_edges,
        }
    except Exception:
        return {"ok": False}

stylesheet = [
    {"selector": "node", "style": {
        # Always show labels, offset to the right of nodes for readability
        "content": "data(label)",
        "font-size": "7px",
        "font-family": "JetBrains Mono, monospace",
        "color": "#00f5ff",
        "text-opacity": 0.85,
        "text-wrap": "wrap",
        "text-max-width": "160px",
        "text-outline-color": "#001014",
        "text-outline-width": 1,
        "text-halign": "right",
        "text-valign": "center",
        "text-margin-x": 6,
        "background-color": "#6c6c6c",
        "border-width": 1,
        "border-color": "#1f2a2e",
        "width": 4,
        "height": 4,
        "min-zoomed-font-size": 4,
    }},
    # Trigger and domain helper nodes get distinct shapes/colors
    {"selector": '[type = "trigger"]', "style": {
        "shape": "round-rectangle",
        "background-color": "#004b4f",
        "border-color": "#00f5ff",
        "border-width": 1,
        "width": 6,
        "height": 5,
        "font-size": "6px",
        "text-margin-x": 4,
    }},
    {"selector": '[type = "domain"]', "style": {
        "shape": "diamond",
        "background-color": "#313131",
        "border-color": "#6c6c6c",
        "border-width": 1,
        "width": 6,
        "height": 6,
        "font-size": "6px",
        "text-margin-x": 4,
    }},
    {"selector": "node:hover", "style": {
        # Keep node size stable; only increase label visibility
        "text-opacity": 1.0,
        "z-index": 9999,
        "text-background-color": "#000000",
        "text-background-opacity": 0.4,
        "text-background-shape": "roundrectangle",
        "text-background-padding": 1,
    }},
    {"selector": "node:selected", "style": {
        # Emphasize selection without changing node dimensions
        "text-opacity": 1.0,
        "border-width": 2,
        "border-color": "#00f5ff",
        "text-background-color": "#000000",
        "text-background-opacity": 0.55,
        "text-background-shape": "roundrectangle",
        "text-background-padding": 1,
    }},
    {"selector": "edge", "style": {
        "width": 0.7,
        "line-color": "#2a2a2a",
        "target-arrow-color": "#2a2a2a",
        "curve-style": "bezier",
        "opacity": 0.6,
    }},
] + [
    {"selector": '[relationship = "trigger"]', "style": {
        "line-color": "#00f5ff",
        "target-arrow-color": "#00f5ff",
        "width": 0.9,
    }},
    {"selector": '[relationship = "domain"]', "style": {
        "line-color": "#3a3a3a",
        "target-arrow-color": "#3a3a3a",
        "line-style": "dashed",
        "width": 0.8,
    }},
] + [
    {"selector": f'[severity = "{sev}"]', "style": {"background-color": color}}
    for sev, color in SEVERITY_COLORS.items()
]

def _load_elements():
    try:
        if not GRAPH_PATH.exists():
            return []
        data = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        # Cytoscape expects a flat list of element dicts
        return list(nodes) + list(edges)
    except Exception:
        return []


app.layout = html.Div(
    style={"backgroundColor": "#000000", "height": "100vh", "padding": "0", "margin": "0"},
    children=[
        # Stores
        dcc.Store(id="force_store", data={"enabled": False}),
        dcc.Store(id="viewport_store", data={}),
        dcc.Store(id="elements_meta", data={"count": 0}),
    dcc.Store(id="did_autofit", data=False),
        dcc.Location(id="url", refresh=False),
        html.Div(
            id="legend",
            style={
                "position": "absolute",
                "top": "6px",
                "left": "8px",
                "zIndex": 10000,
                "backgroundColor": "rgba(0, 0, 0, 0.45)",
                "padding": "6px 8px",
                "border": "1px solid #003b46",
                "borderRadius": "4px",
                "color": "#cceff2",
                "fontFamily": "JetBrains Mono, monospace",
                "fontSize": "10px",
            },
            children=[
                html.Div("Nodes Map — drag to arrange; positions persist. Refreshes every 4s.") ,
                html.Div([
                    html.Span("High", style={"color": SEVERITY_COLORS["high"], "marginRight": "10px"}),
                    html.Span("Medium", style={"color": SEVERITY_COLORS["medium"], "marginRight": "10px"}),
                    html.Span("Mild", style={"color": SEVERITY_COLORS["mild"], "marginRight": "10px"}),
                    html.Span("Low", style={"color": SEVERITY_COLORS["low"], "marginRight": "10px"}),
                ]),
                html.Div(
                    [
                        html.Button(
                            id="toggle_force",
                            children="Force: Off",
                            style={
                                "backgroundColor": "#000000",  # dark button body
                                "color": "#00f5ff",            # neon cyan text
                                "border": "1px solid #003b46", # dark teal outline
                                "borderRadius": "4px",
                                "padding": "4px 8px",
                                "fontFamily": "JetBrains Mono, monospace",
                                "fontSize": "10px",
                                "cursor": "pointer",
                                "marginTop": "6px",
                            },
                            n_clicks=0,
                        ),
                        html.Button(
                            id="fit_graph",
                            children="Fit",
                            title="Fit to all nodes",
                            style={
                                "backgroundColor": "#000000",
                                "color": "#00f5ff",
                                "border": "1px solid #003b46",
                                "borderRadius": "4px",
                                "padding": "4px 8px",
                                "fontFamily": "JetBrains Mono, monospace",
                                "fontSize": "10px",
                                "cursor": "pointer",
                                "marginTop": "6px",
                                "marginLeft": "8px",
                            },
                            n_clicks=0,
                        ),
                    ]
                ),
            ]
        ),
        html.Div(
            id="graph-container",
            style={"height": "100%", "width": "100%", "position": "absolute", "top": 0, "left": 0},
            children=[
                html.Div(
                    id="empty-overlay",
                    style={
                        "position": "absolute",
                        "top": "50%",
                        "left": "50%",
                        "transform": "translate(-50%, -50%)",
                        "padding": "6px 10px",
                        "border": "1px dashed #003b46",
                        "borderRadius": "4px",
                        "color": "#6fe8f5",
                        "backgroundColor": "rgba(0,0,0,0.5)",
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "11px",
                        "zIndex": 20000,
                        "display": "none",
                    },
                    children="No graph elements yet… waiting for alerts",
                ),
                # Hover details card (appears when mousing over a node)
                html.Div(
                    id="hover_card",
                    style={
                        "position": "absolute",
                        "top": "74px",
                        "left": "12px",
                        "zIndex": 15000,
                        "backgroundColor": "rgba(0, 0, 0, 0.75)",
                        "padding": "6px 8px",
                        "border": "1px solid #003b46",
                        "borderRadius": "4px",
                        "color": "#cceff2",
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "10px",
                        "maxWidth": "360px",
                        "display": "none",
                    },
                    children=[],
                ),
                # Selected node details (sticky until next click)
                html.Div(
                    id="selected_card",
                    style={
                        "position": "absolute",
                        "top": "170px",
                        "left": "12px",
                        "zIndex": 14000,
                        "backgroundColor": "rgba(0, 0, 0, 0.75)",
                        "padding": "6px 8px",
                        "border": "1px solid #003b46",
                        "borderRadius": "4px",
                        "color": "#cceff2",
                        "fontFamily": "JetBrains Mono, monospace",
                        "fontSize": "10px",
                        "maxWidth": "420px",
                        "display": "none",
                    },
                    children=[],
                ),
                cyto.Cytoscape(
                    id="cytoscape",
                    elements=_load_elements(),
                    # Use preset layout to respect saved/user positions; prevent auto-fit on updates
                    layout={"name": "preset", "fit": False, "padding": 10},
                    stylesheet=stylesheet,
                    style={"width": "100%", "height": "100%", "backgroundColor": "#000000"},
                    minZoom=0.2,
                    maxZoom=4,
                    userPanningEnabled=True,
                    userZoomingEnabled=True,
                    boxSelectionEnabled=False,
                    autoungrabify=False,
                ),
                dcc.Interval(id="interval", interval=4000, n_intervals=0),
            ],
        )
    ],
)
 
@app.callback(
    [Output("cytoscape", "elements"), Output("cytoscape", "zoom"), Output("cytoscape", "pan"), Output("elements_meta", "data")],
    [Input("interval", "n_intervals")],
    [dash.State("cytoscape", "elements"), dash.State("viewport_store", "data")]
)
def refresh_elements(_, prev_elems, viewport):
    # Load new elements and preserve user-dragged positions when possible
    new = _load_elements()
    try:
        n_nodes = len([e for e in new if isinstance(e, dict) and (e.get("data", {}).get("source") is None and e.get("data", {}).get("target") is None)])
        n_edges = len([e for e in new if isinstance(e, dict) and (e.get("data", {}).get("source") is not None and e.get("data", {}).get("target") is not None)])
        meta = {"count": int(n_nodes + n_edges), "nodes": int(n_nodes), "edges": int(n_edges)}
    except Exception:
        meta = {"count": 0}
    try:
        pos_map = {}
        if isinstance(prev_elems, list):
            for el in prev_elems:
                if isinstance(el, dict):
                    data = el.get("data") or {}
                    eid = data.get("id")
                    pos = el.get("position")
                    if eid and pos:
                        pos_map[eid] = pos
        # Build maps: neighbors and type
        neighbors = {}
        types = {}
        for el in new:
            if isinstance(el, dict):
                d = el.get("data") or {}
                nid = d.get("id")
                ntype = d.get("type")
                if nid and ntype:
                    types[nid] = ntype
        for el in new:
            data = el.get("data") or {}
            src = data.get("source")
            tgt = data.get("target")
            if src and tgt:
                neighbors.setdefault(src, []).append(tgt)
                neighbors.setdefault(tgt, []).append(src)
        # First, assign stable positions to new anchor nodes (triggers/domains)
        for el in new:
            data = el.get("data") or {}
            eid = data.get("id")
            if not eid or eid in pos_map:
                continue
            ntype = types.get(eid)
            if ntype in ("trigger", "domain"):
                h = abs(hash(eid))
                angle = (h % 360) * 3.14159 / 180.0
                # Place triggers/domains on wider rings so they act as magnets
                radius = 900 if ntype == "trigger" else 700
                x = radius * float(__import__('math').cos(angle))
                y = radius * float(__import__('math').sin(angle))
                el["position"] = {"x": x, "y": y}
                pos_map[eid] = el["position"]

        # Then, place remaining new nodes near their anchors (magnet-like)
        for el in new:
            data = el.get("data") or {}
            eid = data.get("id")
            if not eid:
                continue
            if eid in pos_map:
                el["position"] = pos_map[eid]
            else:
                # Try to place near trigger/domain anchors if available
                neigh_ids = neighbors.get(eid, [])
                trig_pts = []
                dom_pts = []
                for nid in neigh_ids:
                    if nid in pos_map:
                        if types.get(nid) == "trigger":
                            trig_pts.append(pos_map[nid])
                        elif types.get(nid) == "domain":
                            dom_pts.append(pos_map[nid])
                def _avg(pts):
                    if not pts:
                        return None
                    return {
                        "x": sum(p.get("x", 0) for p in pts) / len(pts),
                        "y": sum(p.get("y", 0) for p in pts) / len(pts),
                    }
                p_trig = _avg(trig_pts)
                p_dom = _avg(dom_pts)
                if p_trig or p_dom:
                    # Weighted pull toward triggers/domains (magnets)
                    wx = wy = 0.0
                    wsum = 0.0
                    if p_trig:
                        wx += 0.6 * p_trig["x"]; wy += 0.6 * p_trig["y"]; wsum += 0.6
                    if p_dom:
                        wx += 0.4 * p_dom["x"]; wy += 0.4 * p_dom["y"]; wsum += 0.4
                    ax = wx / max(wsum, 1e-6)
                    ay = wy / max(wsum, 1e-6)
                    j = (hash(eid) % 25) - 12  # small jitter to avoid overlap
                    el["position"] = {"x": ax + j, "y": ay + j}
                else:
                    # Fallback deterministic radial placement
                    h = abs(hash(eid))
                    angle = (h % 360) * 3.14159 / 180.0
                    radius = 400 + (h % 120)
                    x = radius * float(__import__('math').cos(angle))
                    y = radius * float(__import__('math').sin(angle))
                    el["position"] = {"x": x, "y": y}
    except Exception:
        pass
    # Preserve current viewport (zoom/pan) so updates don’t reset the view
    z = dash.no_update
    p = dash.no_update
    try:
        if isinstance(viewport, dict):
            if viewport.get("zoom") is not None:
                z = viewport.get("zoom")
            if viewport.get("pan") is not None:
                p = viewport.get("pan")
    except Exception:
        pass
    # Log a tiny heartbeat to stdout on first intervals for visibility
    try:
        if _ == 0:
            print(f"[dash-cyto] Loaded {meta.get('nodes', 0)} nodes / {meta.get('edges', 0)} edges from {GRAPH_PATH}")
    except Exception:
        pass
    return new, z, p, meta


# Toggle empty overlay visibility depending on element count
@app.callback(
    Output("empty-overlay", "style"),
    [Input("elements_meta", "data")],
)
def show_empty_overlay(meta):
    base = {
        "position": "absolute",
        "top": "50%",
        "left": "50%",
        "transform": "translate(-50%, -50%)",
        "padding": "6px 10px",
        "border": "1px dashed #003b46",
        "borderRadius": "4px",
        "color": "#6fe8f5",
        "backgroundColor": "rgba(0,0,0,0.5)",
        "fontFamily": "JetBrains Mono, monospace",
        "fontSize": "11px",
        "zIndex": 20000,
    }
    try:
        cnt = int((meta or {}).get("count", 0))
        if cnt > 0:
            base["display"] = "none"
        else:
            base["display"] = "block"
    except Exception:
        base["display"] = "none"
    return base


# Persist viewport on user interactions (zoom/pan)
@app.callback(
    Output("viewport_store", "data"),
    [Input("cytoscape", "zoom"), Input("cytoscape", "pan")],
    [dash.State("viewport_store", "data")]
)
def persist_viewport(zoom, pan, store):
    try:
        store = store or {}
        if zoom is not None:
            store["zoom"] = zoom
        if isinstance(pan, dict):
            store["pan"] = pan
        return store
    except Exception:
        return store or {}


# Unified force state controller: initializes from URL and toggles on button click
@app.callback(
    Output("force_store", "data"),
    [Input("url", "href"), Input("toggle_force", "n_clicks")],
    [dash.State("force_store", "data")]
)
def control_force_state(href, n_clicks, store):
    store = store or {"enabled": False}
    try:
        ctx = dash.callback_context
        if ctx and ctx.triggered:
            prop = ctx.triggered[0].get("prop_id", "")
            # URL changed: initialize from query (?force=1|0)
            if prop.startswith("url."):
                if href:
                    from urllib.parse import urlparse, parse_qs
                    q = parse_qs(urlparse(href).query or "")
                    if "force" in q:
                        val = (q.get("force", ["0"])[0] or "0").lower()
                        store["enabled"] = val in ("1", "true", "yes", "on")
            # Button clicked: toggle
            elif prop.startswith("toggle_force.") and n_clicks:
                store["enabled"] = not bool(store.get("enabled"))
    except Exception:
        pass
    return store


# Keep button label in sync with force state
@app.callback(
    Output("toggle_force", "children"),
    [Input("force_store", "data")]
)
def reflect_force_label(store):
    try:
        enabled = bool((store or {}).get("enabled"))
        return "Force: On" if enabled else "Force: Off"
    except Exception:
        return "Force: Off"


# Apply layout based on events, avoiding re-running layouts on every interval
@app.callback(
    [Output("cytoscape", "layout"), Output("did_autofit", "data")],
    [Input("force_store", "data"), Input("interval", "n_intervals"), Input("fit_graph", "n_clicks"), Input("elements_meta", "data")],
    [dash.State("did_autofit", "data"), dash.State("cytoscape", "elements")]
)
def apply_layout(force_data, n_intervals, fit_clicks, meta, did_autofit, elements):
    # Determine if any positions exist in current elements
    has_pos = False
    try:
        if isinstance(elements, list):
            for el in elements:
                if isinstance(el, dict) and el.get("position"):
                    has_pos = True
                    break
    except Exception:
        has_pos = False

    # Common layout presets
    cose_fit = {
        "name": "cose",
        "fit": True,
        "animate": False,
        "randomize": False,
        "padding": 10,
        "componentSpacing": 80,
        "nodeRepulsion": 8000,
        "idealEdgeLength": 120,
        "edgeElasticity": 0.2,
        "nestingFactor": 1.1,
        "gravity": 1.0,
        "numIter": 500,
        "initialTemp": 200,
        "coolingFactor": 0.95,
        "minTemp": 1.0,
    }
    preset_fit = {"name": "preset", "fit": True, "padding": 10}
    preset_keep = {"name": "preset", "fit": False, "padding": 10}

    # Figure out what triggered this callback
    try:
        ctx = dash.callback_context
        prop = ctx.triggered[0].get("prop_id", "") if ctx and ctx.triggered else ""
    except Exception:
        prop = ""

    enabled = bool((force_data or {}).get("enabled"))
    did = bool(did_autofit)

    # 1) Explicit Fit button: fit once (preset if we have positions, else cose)
    if prop.startswith("fit_graph.n_clicks"):
        return (preset_fit if has_pos else cose_fit), True

    # 2) Force state changed (URL init or toggle): if turning on, run cose with fit once; if off, keep preset
    if prop.startswith("force_store.data"):
        if enabled:
            return cose_fit, True
        else:
            return preset_keep, did

    # 3) First time elements arrive: one-time fit (prefer preset if positions exist)
    if prop.startswith("elements_meta.data"):
        try:
            cnt = int((meta or {}).get("count", 0))
        except Exception:
            cnt = 0
        if cnt > 0 and not did:
            return (preset_fit if has_pos else cose_fit), True

    # 4) Interval ticks: do not re-run layout repeatedly to avoid moving graph off-screen
    if prop.startswith("interval.n_intervals"):
        return dash.no_update, did

    # Default: don't change layout
    return dash.no_update, did


# Hover tooltip: show details when mousing over a node
@app.callback(
    [Output("hover_card", "children"), Output("hover_card", "style")],
    [Input("cytoscape", "mouseoverNodeData"), Input("cytoscape", "mouseoutNodeData")]
)
def show_hover_details(over_data, out_data):
    base_style = {
        "position": "absolute",
        "top": "74px",
        "left": "12px",
        "zIndex": 15000,
        "backgroundColor": "rgba(0, 0, 0, 0.75)",
        "padding": "6px 8px",
        "border": "1px solid #003b46",
        "borderRadius": "4px",
        "color": "#cceff2",
        "fontFamily": "JetBrains Mono, monospace",
        "fontSize": "10px",
        "maxWidth": "360px",
    }
    try:
        # Hide on mouseout
        if isinstance(out_data, dict) and not isinstance(over_data, dict):
            s = dict(base_style)
            s["display"] = "none"
            return [], s
        if not isinstance(over_data, dict):
            # hide
            s = dict(base_style)
            s["display"] = "none"
            return [], s
        data = over_data
        typ = data.get("type")
        label = data.get("label") or data.get("id")
        sev = data.get("severity")
        url = data.get("url")
        ts = data.get("timestamp")
        src = data.get("source")
        sig = data.get("signal_type")
        trig = data.get("trigger_id")
        region = data.get("region")
        ctx = data.get("context")
        rows = []
        rows.append(html.Div([html.B("Label:"), f" {label}"]))
        rows.append(html.Div([html.B("Type:"), f" {typ or 'node'}"]))
        if sev:
            rows.append(html.Div([html.B("Severity:"), f" {sev}"]))
        if ts:
            rows.append(html.Div([html.B("Time:"), f" {ts}"]))
        if src:
            rows.append(html.Div([html.B("Source:"), f" {src}"]))
        if sig:
            rows.append(html.Div([html.B("Signal:"), f" {sig}"]))
        if trig:
            rows.append(html.Div([html.B("Trigger:"), f" {trig}"]))
        if region:
            rows.append(html.Div([html.B("Region:"), f" {region}"]))
        if ctx:
            rows.append(html.Div([html.B("Context:"), f" {ctx}"], style={"whiteSpace": "pre-wrap"}))
        if url:
            rows.append(html.Div([html.B("URL:"), html.Span(f" {url}", style={"color": "#00f5ff"})]))
        s = dict(base_style)
        s["display"] = "block"
        try:
            print(f"[dash-cyto] hover node: id={data.get('id')} label={label}")
        except Exception:
            pass
        return rows, s
    except Exception:
        s = dict(base_style)
        s["display"] = "none"
        return [], s


# On click: show selected details and open URL in Firefox (if present)
@app.callback(
    [Output("selected_card", "children"), Output("selected_card", "style")],
    [Input("cytoscape", "tapNodeData")],
    [dash.State("selected_card", "style")]
)
def on_node_click(data, style):
    try:
        base_style = style or {
            "position": "absolute",
            "top": "170px",
            "left": "12px",
            "zIndex": 14000,
            "backgroundColor": "rgba(0, 0, 0, 0.75)",
            "padding": "6px 8px",
            "border": "1px solid #003b46",
            "borderRadius": "4px",
            "color": "#cceff2",
            "fontFamily": "JetBrains Mono, monospace",
            "fontSize": "10px",
            "maxWidth": "420px",
            "display": "none",
        }
        if not isinstance(data, dict):
            s = dict(base_style)
            s["display"] = "none"
            return [], s
        typ = data.get("type")
        label = data.get("label") or data.get("id")
        sev = data.get("severity")
        url = data.get("url")
        ts = data.get("timestamp")
        src = data.get("source")
        sig = data.get("signal_type")
        trig = data.get("trigger_id")
        region = data.get("region")
        ctx = data.get("context")
        # Build selected card
        children = [
            html.Div([html.B("Selected Node")], style={"color": "#6fe8f5", "marginBottom": "4px"}),
            html.Div([html.B("Label:"), f" {label}"]),
            html.Div([html.B("Type:"), f" {typ or 'node'}"]),
        ]
        if sev:
            children.append(html.Div([html.B("Severity:"), f" {sev}"]))
        if ts:
            children.append(html.Div([html.B("Time:"), f" {ts}"]))
        if src:
            children.append(html.Div([html.B("Source:"), f" {src}"]))
        if sig:
            children.append(html.Div([html.B("Signal:"), f" {sig}"]))
        if trig:
            children.append(html.Div([html.B("Trigger:"), f" {trig}"]))
        if region:
            children.append(html.Div([html.B("Region:"), f" {region}"]))
        if ctx:
            children.append(html.Div([html.B("Context:"), f" {ctx}"], style={"whiteSpace": "pre-wrap"}))
        if url:
            children.append(html.Div([html.B("URL:"), html.Span(f" {url}", style={"color": "#00f5ff"})]))
        print(f"[dash-cyto] tap node: id={data.get('id')} label={label} url={'yes' if url else 'no'}")
        # Fire-and-forget: open URL in Firefox if available; fallback to default browser
        try:
            if isinstance(url, str) and url.lower().startswith(("http://", "https://")):
                if sys.platform == "darwin":  # macOS
                    subprocess.Popen(["open", "-a", "Firefox", url])
                elif sys.platform.startswith("linux"):
                    subprocess.Popen(["xdg-open", url])
                elif sys.platform.startswith("win"):
                    # Windows: try default browser
                    webbrowser.open(url)
                else:
                    webbrowser.open(url)
        except Exception:
            pass
        # Ensure the card is visible by setting its display via client-side style (can't output style from same callback without extra Output)
        # We rely on CSS to show once it has children; a tiny JS could toggle, but we keep it simple here.
        s = dict(base_style)
        s["display"] = "block"
        return children, s
    except Exception:
        return [], (style or {"display": "none"})


def main():
    # Ensure data file exists
    try:
        GRAPH_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not GRAPH_PATH.exists():
            GRAPH_PATH.write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
    except Exception:
        pass
    # Dash >=2.17 prefers app.run over deprecated app.run_server
    app.run(host="127.0.0.1", port=PORT, debug=False)


if __name__ == "__main__":
    main()
