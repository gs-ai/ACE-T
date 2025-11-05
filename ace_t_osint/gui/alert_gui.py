import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, Tuple, List, Optional, cast
import csv
import os
import platform
import sys
import json
import threading
from datetime import datetime
import hashlib
import re
from urllib.parse import urlparse
import webbrowser
from pathlib import Path
import socket
import urllib.request

import requests
import subprocess
import time

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None

from tkintermapview import TkinterMapView

# Optional embedded webview to display Dash (Cytoscape) inside Tkinter
try:
    from tkinterweb import HtmlFrame  # type: ignore
    HAS_TKHTML = True
except Exception:
    HtmlFrame = None  # type: ignore
    HAS_TKHTML = False

# Optional per-cell grid support
try:
    from tksheet import Sheet  # type: ignore
    HAS_TKSHEET = True
except Exception:
    Sheet = None  # type: ignore
    HAS_TKSHEET = False

SEVERITY_COLORS = {
    "high": "#ff073a",      # Neon red
    "medium": "#ff9f1a",    # Neon orange (matches 🟧)
    "mild": "#f4ff52",      # Neon yellow
    "low": "#39ff14",       # Neon green
}

# Colored emoji badges to indicate severity inside a Treeview cell (works without per-cell styling)
SEVERITY_ICONS = {
    "low": "🟩",
    "mild": "🟨",
    "medium": "🟧",
    "high": "🟥",
}

# Neon styling for map highlights and UI accents
NEON_CYAN = "#00f5ff"
NEON_GLOW = "#00d8e6"

BASE_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(BASE_PATH, "output", "logs.csv")
OUTPUT_JSON_DIR = os.path.join(BASE_PATH, "output", "incidents")
SNAPSHOT_BASE_DIR = os.path.join(BASE_PATH, "output", "url_snapshots")
GUI_PREFS_DIR = os.path.join(BASE_PATH, "output", "gui_prefs")
COL_WIDTHS_FILE = os.path.join(GUI_PREFS_DIR, "column_widths.json")
GRAPH_DATA_FILE = os.path.join(GUI_PREFS_DIR, "graph_data.json")
CYTO_PORT = int(os.getenv("DASH_PORT", "8060"))
CYTO_LOG_FILE = os.path.join(GUI_PREFS_DIR, "cyto_server.log")
SETTINGS_FILE = os.path.join(GUI_PREFS_DIR, "settings.json")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
# Pin the default model to phi4-mini:latest for every call; allow an explicit env override if set.
DEFAULT_OLLAMA_MODEL = "phi4-mini:latest"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
# No fallback by default; can be provided via OLLAMA_FALLBACK env (comma-separated)
_fallback_env = os.getenv("OLLAMA_FALLBACK", "")
OLLAMA_FALLBACK = [m.strip() for m in _fallback_env.split(",") if m.strip()]
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "30"))

FONT_FAMILY = "JetBrains Mono"
def get_font(size, weight="normal"):
    try:
        return (FONT_FAMILY, size, weight)
    except Exception:
        return ("Consolas", size, weight)

COLUMNS = [
    ("Timestamp", 140),
    ("Source", 70),
    ("Signal Type", 110),
    ("Severity", 70),
    ("Trigger ID", 100),
    ("Context", 220),
    ("Region", 80),
    ("Trend", 120),
    ("Sentiment", 80),
    ("URL", 200)
]

def _col_index(name: str) -> int:
    for i, (n, _) in enumerate(COLUMNS):
        if n == name:
            return i
    return -1

class AlertGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ACE-T OSINT Alerts")
        self.configure(bg="#000000")
        self.attributes('-fullscreen', True)  # Open in full screen
        self.resizable(True, True)
        if platform.system() == "Darwin":
            self.attributes('-alpha', 0.97)
        self.config(highlightbackground="#222", highlightcolor="#222", highlightthickness=1)
        self['bd'] = 0

        # Header
        header = tk.Label(self, text="ACE-T OSINT ALERTS", font=get_font(18, "bold"), fg=NEON_CYAN, bg="#000000", pady=8)
        header.pack(fill='x', padx=8, pady=(8, 0))

    # Top bar: severity legend (right) + actions (left)
        topbar = tk.Frame(self, bg="#000000")
        # Actions (left)
        actions = tk.Frame(topbar, bg="#000000")
        actions.pack(side='left', padx=8, pady=(0, 4))
        # Initialize Cytoscape server state for on-demand launching
        self.cyto_port = CYTO_PORT
        self.cyto_url = f"http://127.0.0.1:{self.cyto_port}/"
        self.cyto_proc = None
        # placeholders for optional embedded status/webview (not used in on-demand flow)
        self.cyto_status = None
        self.cyto_web = None
        tk.Button(
            actions,
            text="Open Nodes Map",
            command=self._open_nodes_map,
            bg="#000000",  # dark button body
            fg=NEON_CYAN,   # neon cyan lettering
            activebackground="#000000",
            activeforeground=NEON_CYAN,
            relief='raised',
            bd=1,
            highlightbackground="#001f26",  # dark outline accent
            highlightcolor="#001f26",
            highlightthickness=1
        ).pack(side='left', padx=6)
        # Auto-open toggle
        default_auto = self._get_auto_open_default()
        self.auto_open_nodes_var = tk.BooleanVar(value=default_auto)
        tk.Checkbutton(
            actions,
            text="Auto-open Nodes Map",
            variable=self.auto_open_nodes_var,
            command=self._on_toggle_auto_open,
            bg="#000000",
            fg=NEON_CYAN,  # neon cyan label
            selectcolor="#FFFFFF",  # white indicator for contrast
            activebackground="#000000",
            activeforeground=NEON_CYAN,
            highlightthickness=0
        ).pack(side='left', padx=10)

        # Force/Gravity default toggle (applies when opening the map)
        default_force = self._get_force_default()
        self.force_layout_var = tk.BooleanVar(value=default_force)
        tk.Checkbutton(
            actions,
            text="Gravity (force)",
            variable=self.force_layout_var,
            command=self._on_toggle_force_default,
            bg="#000000",
            fg=NEON_CYAN,
            selectcolor="#FFFFFF",
            activebackground="#000000",
            activeforeground=NEON_CYAN,
            highlightthickness=0
        ).pack(side='left', padx=10)

        # Keyboard shortcuts
        try:
            # Toggle gravity default: Cmd+Shift+F (macOS) / Control+Shift+F (others also map to Command on some setups)
            self.bind_all("<Command-Shift-f>", lambda e: self._kb_toggle_force_default())
            self.bind_all("<Control-Shift-f>", lambda e: self._kb_toggle_force_default())
            # Open Nodes Map: Cmd+M / Ctrl+M
            self.bind_all("<Command-m>", lambda e: self._open_nodes_map())
            self.bind_all("<Control-m>", lambda e: self._open_nodes_map())
        except Exception:
            pass

        # Severity legend (right). Show left-to-right: High, Medium, Mild, Low
        legend = tk.Frame(topbar, bg="#000000")
        for sev in ["high", "medium", "mild", "low"]:
            color = SEVERITY_COLORS.get(sev, NEON_CYAN)
            lbl = tk.Label(legend, text=sev.capitalize(), bg="#001f26", fg=color, font=get_font(9, "bold"), width=9, relief='flat', bd=0, padx=2, pady=2)
            lbl.pack(side='left', padx=2, pady=2)
        legend.pack(side='right', padx=8, pady=(0, 4))
        topbar.pack(fill='x')

        # Main content frame (top half: table, bottom half: map)
        self.content_frame = tk.Frame(self, bg="#000000")
        self.content_frame.pack(fill='both', expand=True)

        # Table for alerts (top half)
        self.table_frame = tk.Frame(self.content_frame, bg="#000000")
        self.table_frame.pack(fill='both', expand=True, side='top')
        # Force Treeview (no grid) for a simple, stable table view.
        self.using_sheet: bool = False
        self.table: Any
        if self.using_sheet and Sheet is not None:
            # Build tksheet grid for per-cell coloring of Severity column
            self.table = Sheet(self.table_frame, headers=[c[0] for c in COLUMNS], theme="dark")  # type: ignore
            try:
                self.table.set_options(
                    # Seamless jet black look
                    table_bg="#000000",
                    table_fg=NEON_CYAN,
                    header_bg="#000000",
                    header_fg=NEON_CYAN,
                    index_bg="#000000",
                    index_fg="#000000",  # hide index numerals by matching bg
                    top_left_bg="#000000",
                    top_left_fg="#000000",
                    # Hide grid lines (if supported)
                    table_grid_fg="#000000",
                    header_grid_fg="#000000",
                    outline_thickness=0,
                    header_outline_thickness=0,
                    show_vertical_grid=False,
                    show_horizontal_grid=False,
                    show_row_index=False,
                    show_top_left=False,
                )
            except Exception:
                pass
            try:
                self.table.enable_bindings((
                    "single_select",
                    "row_select",
                    "column_width_resize",
                    "arrowkeys",
                    "drag_select",
                    "right_click_popup_menu",
                ))
            except Exception:
                pass
            self.table.pack(expand=True, fill='both', padx=16, pady=6)
            # Bindings for selection and double-click
            try:
                if hasattr(self.table, "extra_bindings"):
                    self.table.extra_bindings({
                        "cell_select": self.on_sheet_select,
                        "double_click": self.on_sheet_double_click,
                        "column_width_resize": lambda e: self._save_column_widths_debounced(),
                    })
            except Exception:
                pass
            # Also hide any residual lines by matching highlight/selection to background
            try:
                self.table.set_options(
                    table_selected_cells_bg="#000000",
                    table_selected_cells_border_fg="#000000",
                    header_border_fg="#000000",
                    header_selected_cells_bg="#000000",
                )
            except Exception:
                pass
        else:
            self.using_sheet = False
            style = ttk.Style(self)
            style.theme_use('clam')
            # Global neon cyan on black for all table text by default
            style.configure("Treeview", background="#000000", fieldbackground="#000000", foreground=NEON_CYAN, font=get_font(10), rowheight=24, borderwidth=0, highlightthickness=0)
            style.configure("Treeview.Heading", background="#000000", foreground=NEON_CYAN, font=get_font(10, "bold"), borderwidth=0)
            style.map('Treeview', background=[('selected', '#003b46')])
            self.table = ttk.Treeview(self.table_frame, columns=[c[0] for c in COLUMNS], show='headings', selectmode='browse')
            for col, width in COLUMNS:
                self.table.heading(col, text=col)
                # Per-column alignment: center Severity, right-align Trend, left-align others
                anchor = 'center' if col == 'Severity' else ('e' if col == 'Trend' else 'w')
                self.table.column(col, width=max(60, min(220, width)), anchor=anchor, stretch=False)
            self.table.pack(expand=True, fill='both', padx=16, pady=6)
            # Open URL preview on double-click on URL column
            self.table.bind('<Double-1>', self.on_table_double_click)
            # Periodically save widths to capture user resizes (Treeview has no resize event)
            self.after(4000, self._periodic_save_widths)

        # Bottom panel: Map full width (nodes graph opens in browser via button)
        self.bottom_frame = tk.Frame(self.content_frame, bg="#000000")
        self.bottom_frame.pack(fill='both', expand=True, side='bottom')
        try:
            self.bottom_frame.columnconfigure(0, weight=1)
            self.bottom_frame.rowconfigure(0, weight=1)
        except Exception:
            pass

        # Map widget (full width)
        self.map_frame = tk.Frame(self.bottom_frame, bg="#000000")
        try:
            self.map_frame.grid(row=0, column=0, sticky='nsew')
        except Exception:
            self.map_frame.pack(fill='both', expand=True)
        self.map_widget = TkinterMapView(self.map_frame, width=600, height=400, corner_radius=0)
        self.map_widget.set_tile_server("https://a.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png")
        try:
            self.map_widget.configure(bg="#000000")
        except Exception:
            pass
        self.map_widget.pack(fill="both", expand=True, padx=8, pady=8)
        self.map_widget.set_position(20, 0)  # Center on world
        self.map_widget.set_zoom(2)  # Zoomed out to show all countries

        self.map_markers = []  # Store references to markers
        self.marker_alerts = {}  # (lat, lon) -> [alert details]

        # Map legend
        self.map_legend = tk.Frame(self.map_frame, bg="#001f26", bd=1, relief='ridge')
        tk.Label(self.map_legend, text="Map Legend", bg="#001f26", fg=NEON_CYAN, font=get_font(10, "bold")).pack(anchor='w', padx=8, pady=(4,0))
        for sev, color in SEVERITY_COLORS.items():
            tk.Label(self.map_legend, text=sev.capitalize(), bg="#001f26", fg=color, font=get_font(9, "bold"), width=12, anchor='w').pack(anchor='w', padx=8)
        self.map_legend.place(relx=0.01, rely=0.75, anchor='w')

        # (Graph embed removed) — launch on demand via the top "Open Nodes Map" button

        # Keep mapping of table items to marker locations for interactive highlighting
        self.table_item_to_key: Dict[Any, Tuple[float, float]] = {}
        self.row_to_key: Dict[int, Tuple[float, float]] = {}
        self.blink_jobs: Dict[Tuple[float, float], Any] = {}  # key -> after job id
        self.blink_markers: Dict[Tuple[float, float], Any] = {}  # key -> glow marker
        self.dynamic_markers: Dict[Any, Any] = {}
        self.pending_location_requests: set[Any] = set()

        self.popup = None  # For temporary alert popup

        footer = tk.Label(self, text="ACE-T Intelligence Platform | Alerts auto-refresh | Severity: Neon colors indicate risk level", font=get_font(8), fg="#4dffff", bg="#000000", pady=4)
        footer.pack(fill='x', side='bottom', padx=8, pady=(0, 6))

        self.last_line = 0
        # Auto-open nodes map on startup if enabled
        if self.auto_open_nodes_var.get():
            try:
                self.after(1200, self._open_nodes_map)
            except Exception:
                pass
        # Bind table selection to show blinking marker (Treeview only)
        if not self.using_sheet:
            self.table.bind('<<TreeviewSelect>>', self.on_table_select)
        self.after(1000, self.check_log)
        os.makedirs(OUTPUT_JSON_DIR, exist_ok=True)
        os.makedirs(SNAPSHOT_BASE_DIR, exist_ok=True)
        os.makedirs(GUI_PREFS_DIR, exist_ok=True)
        # load additional URLs to consider when resolving locations
        self.additional_urls = self._load_additional_urls()

        # Apply saved column widths (if any)
        try:
            self._apply_saved_widths()
        except Exception:
            pass
        # Save widths on close as a last resort
        try:
            self.protocol("WM_DELETE_WINDOW", self._on_close)
        except Exception:
            pass

        # --- Graph model (for Cytoscape) ---
        self.graph_nodes: Dict[str, Dict[str, str]] = {}
        self.graph_edges: Dict[str, Dict[str, str]] = {}
        self.by_trigger: Dict[str, List[str]] = {}
        self.by_domain: Dict[str, List[str]] = {}
        self._graph_write_job: Optional[str] = None

    # ---------- Column auto-fit helpers ----------
    def _text_px(self, s: str) -> int:
        try:
            return max(6, int(len(s) * 8))  # rough mono font width estimate
        except Exception:
            return 80

    def _autofit_sheet_columns(self, values):
        if not (self.using_sheet and Sheet is not None):
            return
        # Try common tksheet APIs for setting width
        set_col_width = getattr(self.table, 'set_column_width', None)
        col_width = getattr(self.table, 'column_width', None)
        for idx, (col, _) in enumerate(COLUMNS):
            content = str(values[idx]) if idx < len(values) else ''
            need = self._text_px(max([content, col], key=len)) + 24
            need = max(60, min(460, need))
            try:
                if callable(set_col_width):
                    set_col_width(idx, need)
                elif callable(col_width):
                    col_width(idx, width=need)
            except Exception:
                continue

    def _autofit_tree_columns(self, values):
        if self.using_sheet:
            return
        for idx, (col, _) in enumerate(COLUMNS):
            content = str(values[idx]) if idx < len(values) else ''
            need = self._text_px(max([content, col], key=len)) + 24
            need = max(60, min(460, need))
            try:
                self.table.column(col, width=need, stretch=False)
            except Exception:
                pass

    # ---------- tksheet helpers ----------
    def _sheet_safe_append(self, values):
        """Append a row to tksheet regardless of API differences across versions."""
        if not (self.using_sheet and Sheet is not None):
            return False
        # Try common insertion methods
        try:
            ins = getattr(self.table, 'insert_row', None)
            if callable(ins):
                ins(values, idx="end")
                return True
        except Exception:
            pass
        try:
            ins_rows = getattr(self.table, 'insert_rows', None)
            if callable(ins_rows):
                ins_rows([values], idx="end")
                return True
        except Exception:
            pass
        # Fallback: mutate the whole data matrix
        try:
            get_data = getattr(self.table, 'get_sheet_data', None)
            set_data = getattr(self.table, 'set_sheet_data', None)
            if callable(get_data) and callable(set_data):
                raw = get_data() or []
                if isinstance(raw, list):
                    d = raw
                else:
                    d = []
                d.append(values)
                set_data(d)
                return True
        except Exception:
            pass
        return False

    # ---------- Width persistence ----------
    def _collect_current_widths(self) -> dict:
        widths = {}
        try:
            if self.using_sheet and Sheet is not None:
                get_w = getattr(self.table, 'get_column_width', None)
                for idx, (col, _) in enumerate(COLUMNS):
                    w = None
                    if callable(get_w):
                        try:
                            val = get_w(idx)
                            w = int(val) if isinstance(val, (int, float, str)) else None
                        except Exception:
                            w = None
                    if w is None:
                        # Fallback: try "column_width" getter style
                        cw = getattr(self.table, 'column_width', None)
                        if callable(cw):
                            try:
                                val2 = cw(idx)
                                w = int(val2) if isinstance(val2, (int, float, str)) else None
                            except Exception:
                                w = None
                    if w is not None:
                        widths[COLUMNS[idx][0]] = int(w)
            else:
                for col, _ in COLUMNS:
                    try:
                        w = int(self.table.column(col).get('width', 0))
                        if w:
                            widths[col] = w
                    except Exception:
                        continue
        except Exception:
            return widths
        return widths

    def _apply_saved_widths(self):
        try:
            if not os.path.exists(COL_WIDTHS_FILE):
                return
            with open(COL_WIDTHS_FILE, 'r', encoding='utf-8') as fh:
                widths = json.load(fh)
        except Exception:
            return
        # Apply
        for idx, (col, _) in enumerate(COLUMNS):
            w = int(widths.get(col, 0)) if isinstance(widths, dict) else 0
            if not w:
                continue
            try:
                if self.using_sheet and Sheet is not None:
                    set_col_width = getattr(self.table, 'set_column_width', None)
                    col_width = getattr(self.table, 'column_width', None)
                    if callable(set_col_width):
                        set_col_width(idx, w)
                    elif callable(col_width):
                        col_width(idx, width=w)
                else:
                    self.table.column(col, width=w, stretch=False)
            except Exception:
                continue

    def _save_column_widths(self):
        widths = self._collect_current_widths()
        if not widths:
            return
        try:
            with open(COL_WIDTHS_FILE, 'w', encoding='utf-8') as fh:
                json.dump(widths, fh, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _save_column_widths_debounced(self):
        try:
            if hasattr(self, '_save_job') and self._save_job:
                self.after_cancel(self._save_job)
        except Exception:
            pass
        try:
            self._save_job = self.after(800, self._save_column_widths)
        except Exception:
            self._save_column_widths()

    def _periodic_save_widths(self):
        try:
            self._save_column_widths()
        finally:
            # Re-schedule
            try:
                self.after(4000, self._periodic_save_widths)
            except Exception:
                pass

    def _on_close(self):
        try:
            self._save_column_widths()
        finally:
            try:
                self.destroy()
            except Exception:
                pass
            # Intentionally do NOT terminate the Cytoscape server so the graph can remain open
            # Users can keep interacting with nodes even after the main GUI exits.

    # ---------- Dash Cytoscape helpers ----------
    def _ensure_graph_store(self):
        try:
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            if not os.path.exists(GRAPH_DATA_FILE):
                with open(GRAPH_DATA_FILE, 'w', encoding='utf-8') as fh:
                    json.dump({"nodes": [], "edges": []}, fh)
            # ensure settings file exists
            if not os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
                    json.dump({}, fh)
        except Exception:
            pass

    def _get_auto_open_default(self) -> bool:
        # precedence: settings.json -> env var -> False
        try:
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                    data = json.load(fh) or {}
                    v = data.get('auto_open_nodes_map')
                    if isinstance(v, bool):
                        return v
        except Exception:
            pass
        env_v = os.getenv('ACE_T_AUTO_OPEN_NODES_MAP', os.getenv('AUTO_OPEN_NODES_MAP', '0'))
        if isinstance(env_v, str):
            return env_v.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(env_v)

    def _save_auto_open_setting(self, enabled: bool):
        try:
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            data = {}
            if os.path.exists(SETTINGS_FILE):
                try:
                    with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                        raw = json.load(fh)
                        if isinstance(raw, dict):
                            data = raw
                except Exception:
                    data = {}
            data['auto_open_nodes_map'] = bool(enabled)
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _on_toggle_auto_open(self):
        val = False
        try:
            val = bool(self.auto_open_nodes_var.get())
        except Exception:
            val = False
        self._save_auto_open_setting(val)
        if val:
            # if enabling at runtime, also open now
            try:
                self._open_nodes_map()
            except Exception:
                pass

    def _get_force_default(self) -> bool:
        # precedence: settings.json -> env var -> False
        try:
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                    data = json.load(fh) or {}
                    v = data.get('force_layout_default')
                    if isinstance(v, bool):
                        return v
        except Exception:
            pass
        env_v = os.getenv('ACE_T_FORCE_LAYOUT_DEFAULT', os.getenv('FORCE_LAYOUT_DEFAULT', '0'))
        if isinstance(env_v, str):
            return env_v.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(env_v)

    def _save_force_setting(self, enabled: bool):
        try:
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            data = {}
            if os.path.exists(SETTINGS_FILE):
                try:
                    with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                        raw = json.load(fh)
                        if isinstance(raw, dict):
                            data = raw
                except Exception:
                    data = {}
            data['force_layout_default'] = bool(enabled)
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _on_toggle_force_default(self):
        try:
            val = bool(self.force_layout_var.get())
        except Exception:
            val = False
        self._save_force_setting(val)

    def _kb_toggle_force_default(self):
        try:
            cur = bool(self.force_layout_var.get())
            self.force_layout_var.set(not cur)
            self._save_force_setting(not cur)
        except Exception:
            pass

    def _is_port_free(self, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except Exception:
            return False

    def _pick_free_port(self, start: int = 8060, tries: int = 10) -> int:
        for p in range(start, start + tries):
            if self._is_port_free(p):
                return p
        return start

    def _start_cyto_server(self):
        try:
            env = os.environ.copy()
            env["ACE_T_GRAPH_DATA"] = GRAPH_DATA_FILE
            # Pick a free port if default is taken
            self.cyto_port = self._pick_free_port(CYTO_PORT, tries=10)
            self.cyto_url = f"http://127.0.0.1:{self.cyto_port}/"
            env["DASH_PORT"] = str(self.cyto_port)
            os.makedirs(GUI_PREFS_DIR, exist_ok=True)
            log_fh = open(CYTO_LOG_FILE, "a", encoding="utf-8")
            self.cyto_proc = subprocess.Popen(
                [sys.executable, "-m", "ace_t_osint.gui.dash_cyto_server"],
                cwd=BASE_PATH,
                env=env,
                stdout=log_fh,
                stderr=log_fh,
                start_new_session=True,
            )
        except Exception:
            self.cyto_proc = None

    def _open_nodes_map(self):
        """Start the Cytoscape server if needed and open it in the default browser."""
        def worker():
            try:
                self._ensure_graph_store()
            except Exception:
                pass
            # Start server if not already up
            if not self._is_cyto_up():
                try:
                    self._start_cyto_server()
                except Exception:
                    pass
                # Wait briefly for the server to become ready
                for _ in range(20):  # up to ~10s
                    if self._is_cyto_up():
                        break
                    time.sleep(0.5)
            try:
                # Append force/gravity preference as a query param
                try:
                    force_on = bool(self.force_layout_var.get())
                except Exception:
                    force_on = False
                launch_url = self.cyto_url
                if force_on:
                    launch_url = f"{launch_url}?force=1"
                else:
                    launch_url = f"{launch_url}?force=0"
                webbrowser.open(launch_url)
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def _restart_and_probe_cyto(self):
        try:
            status = getattr(self, 'cyto_status', None)
            if status is not None:
                status.set("Restarting…")
            proc = getattr(self, 'cyto_proc', None)
            if proc is not None:
                proc.terminate()
        except Exception:
            pass
        try:
            self._start_cyto_server()
        except Exception:
            pass
        self._schedule_cyto_probe(retries=10)

    def _is_cyto_up(self) -> bool:
        try:
            with urllib.request.urlopen(self.cyto_url, timeout=1) as r:
                return r.status == 200 or True
        except Exception:
            return False

    def _schedule_cyto_probe(self, retries: int = 20):
        web = getattr(self, 'cyto_web', None)
        if not (HAS_TKHTML and web is not None):
            return
        if self._is_cyto_up():
            try:
                web = getattr(self, 'cyto_web', None)
                if web is not None:
                    # Respect force preference when embedding as well
                    try:
                        force_on = bool(self.force_layout_var.get())
                    except Exception:
                        force_on = False
                    launch_url = self.cyto_url + ("?force=1" if force_on else "?force=0")
                    web.load_website(launch_url)
                status = getattr(self, 'cyto_status', None)
                if status is not None:
                    status.set(f"Connected: {self.cyto_url}")
            except Exception:
                pass
            return
        if retries <= 0:
            status = getattr(self, 'cyto_status', None)
            if status is not None:
                status.set("Renderer not available here — opening in browser…")
            # Fallback: open the live graph in the system browser so the user sees it immediately
            try:
                try:
                    force_on = bool(self.force_layout_var.get())
                except Exception:
                    force_on = False
                launch_url = self.cyto_url + ("?force=1" if force_on else "?force=0")
                webbrowser.open(launch_url)
            except Exception:
                pass
            return
        try:
            self.after(1000, lambda: self._schedule_cyto_probe(retries=retries-1))
        except Exception:
            pass

    def _domain_from_url(self, url: str) -> str:
        try:
            return (urlparse(url).netloc or '').lower()
        except Exception:
            return ''

    def _alert_id(self, ts: str, source: str, trigger_id: str, url: str) -> str:
        key = url or f"{ts}|{source}|{trigger_id}"
        try:
            return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]
        except Exception:
            return key[:16]

    def _graph_add_alert(self, ts: str, source: str, signal_type: str, severity_key: str, trigger_id: str, context: str, url: str, region: str):
        nid = self._alert_id(ts, source, trigger_id, url)
        label = (context or trigger_id or source or 'alert')
        if len(label) > 43:
            label = label[:42] + '…'
        # Alert node (colored by severity)
        # Include richer details so the Dash graph can show hover/click info and open URLs
        self.graph_nodes[nid] = {
            "id": nid,
            "label": label,
            "severity": (severity_key or 'medium'),
            "type": "alert",
            # Details for hover/click
            "timestamp": ts,
            "source": source,
            "signal_type": signal_type,
            "trigger_id": trigger_id,
            "context": context,
            "region": region,
            "url": (url or ""),
        }

        # Trigger node and edge (bipartite model to reduce O(n^2) clutter)
        trig_label = (trigger_id or '').strip() or 'unknown-trigger'
        tnode_id = f"t:{trig_label}"
        self.graph_nodes.setdefault(tnode_id, {"id": tnode_id, "label": trig_label, "type": "trigger"})
        teid = f"e:{nid}->{tnode_id}:trigger"
        self.graph_edges[teid] = {"id": teid, "source": nid, "target": tnode_id, "relationship": "trigger"}

        # Domain node and edge
        domain = self._domain_from_url(url) or 'unknown-domain'
        dnode_id = f"d:{domain}"
        self.graph_nodes.setdefault(dnode_id, {"id": dnode_id, "label": domain, "type": "domain"})
        deid = f"e:{nid}->{dnode_id}:domain"
        self.graph_edges[deid] = {"id": deid, "source": nid, "target": dnode_id, "relationship": "domain"}

        self._schedule_graph_write()

    def _schedule_graph_write(self):
        try:
            if self._graph_write_job:
                self.after_cancel(self._graph_write_job)
        except Exception:
            pass
        try:
            self._graph_write_job = self.after(800, self._write_graph_file)
        except Exception:
            self._write_graph_file()

    def _write_graph_file(self):
        data = {
            "nodes": [{"data": v} for v in self.graph_nodes.values()],
            "edges": [{"data": v} for v in self.graph_edges.values()],
        }
        try:
            with open(GRAPH_DATA_FILE, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False)
        except Exception:
            pass

    def parse_extra(self, extra):
        try:
            data = json.loads(extra.replace("'", '"'))
            region = data.get('region', '')
            trend = data.get('trend', '')
            sentiment = data.get('sentiment', '')
            url = data.get('source_url', '')
            return region, trend, sentiment, url
        except Exception:
            return '', '', '', ''

    def display_alert(self, row):
        # Skip header rows or rows with column names in the data
        if row and (row[0].strip().lower() == "timestamp" or row == [c[0] for c in COLUMNS]):
            return
        ts, source, signal_type, severity, trigger_id, context = row[:6]
        extra = row[6] if len(row) > 6 else ''
        region, trend, sentiment, url = self.parse_extra(extra)
        # Default empty fields so cells aren't blank
        region = region or 'Unknown'
        trend = trend or ''
        sentiment = sentiment or ''
        url = url or ''
        # Show a colored emoji badge for severity (Treeview-compatible)
        sev_key = (severity or '').strip().lower()
        sev_badge = SEVERITY_ICONS.get(sev_key, '⬛')
        sev_text = f"{sev_badge} {(severity or '').upper()}".strip()
        values = [ts, source, signal_type, sev_text, trigger_id, context, region, trend, sentiment, url]
        if self.using_sheet and Sheet is not None:
            # Insert row into tksheet using robust helper
            appended = False
            try:
                appended = self._sheet_safe_append(values)
            except Exception:
                appended = False
            r_index = 0
            try:
                total = self.table.get_total_rows()  # type: ignore[attr-defined]
                r_index = int(cast(int, total)) - 1
            except Exception:
                # Fallback: try to derive from data length
                try:
                    data = self.table.get_sheet_data()  # type: ignore[attr-defined]
                    if isinstance(data, list):
                        r_index = len(cast(List[List[Any]], data)) - 1
                    else:
                        r_index = 0
                except Exception:
                    r_index = 0
            # Color only the Severity cell for this row
            try:
                sev_idx = _col_index("Severity")
                sev_color = SEVERITY_COLORS.get(severity.lower(), "#e0e0e0")
                self.table.highlight_cells(row=r_index, column=sev_idx, fg=sev_color, bg="#000000", canvas="table")  # type: ignore[attr-defined]
            except Exception:
                pass
            # Auto-fit columns to content width
            try:
                self._autofit_sheet_columns(values)
            except Exception:
                pass
            item_id = r_index
        else:
            # Insert row into Treeview
            tag = f"row_{severity.lower()}"
            item_id = self.table.insert('', 'end', values=values, tags=(tag,))
            # Keep row text neon cyan on black
            self.table.tag_configure(tag, foreground=NEON_CYAN)
            # Auto-fit Treeview columns
            try:
                self._autofit_tree_columns(values)
            except Exception:
                pass

            # If Region is unknown and URL is present, auto-run geolocation in background
            try:
                if (not region or region == 'Unknown') and url and item_id not in self.pending_location_requests and item_id not in self.dynamic_markers:
                    self.pending_location_requests.add(item_id)
                    threading.Thread(target=self._process_row_location, args=(item_id, values, url), daemon=True).start()
            except Exception:
                pass
            # Auto-fit Treeview columns
            try:
                self._autofit_tree_columns(values)
            except Exception:
                pass

        # Only plot if geolocation data is present and has city/country/state/zip/coords
        try:
            data = json.loads(extra.replace("'", '"'))
            lat = data.get('lat') or data.get('latitude')
            lon = data.get('lon') or data.get('longitude')
            city = data.get('city', '')
            country = data.get('country', '')
            state = data.get('state', '')
            zipcode = data.get('zip') or data.get('zipcode', '')
            # Only plot if at least one of city, state, country, zip, and both lat/lon are present
            if lat and lon and (city or state or country or zipcode):
                color = SEVERITY_COLORS.get(severity.lower(), "#e0e0e0")
                label = f"{city}, {country}" if city else (state or country or zipcode)
                details = f"Time: {ts}\nSource: {source}\nType: {signal_type}\nSeverity: {severity}\nTrigger: {trigger_id}\nContext: {context}\nRegion: {region}\nCity: {city}\nState: {state}\nCountry: {country}\nZip: {zipcode}\nTrend: {trend}\nSentiment: {sentiment}\nURL: {url}"
                key = (float(lat), float(lon))
                if key not in self.marker_alerts:
                    self.marker_alerts[key] = []
                self.marker_alerts[key].append(details)
                # Use a small, unique, classy marker (circle with border)
                marker = self.map_widget.set_marker(float(lat), float(lon), text='', marker_color_circle=color, marker_color_outside="#232526", marker_size=6, marker_outline_width=2)
                # remember the table item -> key mapping so that clicking a row will highlight the marker
                if self.using_sheet and Sheet is not None:
                    self.row_to_key[item_id] = key
                else:
                    self.table_item_to_key[item_id] = key
                # Note: TkinterMapView markers may not expose bindable canvas reliably across versions.
                # Tooltip bindings removed to avoid runtime/type issues.
                self.map_markers.append(marker)
        except Exception:
            pass

        # Update graph model (Cytoscape) with this alert and write debounced JSON
        try:
            self._graph_add_alert(ts, source, signal_type, sev_key, trigger_id, context, url, region)
        except Exception:
            pass

        # Enhanced alerting: pop to front and play sound on high severity
        if severity.lower() == "high":
            self.lift()
            self.attributes('-topmost', True)
            self.after(1000, lambda: self.attributes('-topmost', False))
            if platform.system() == "Darwin":
                print("\a", end="", flush=True)
            elif platform.system() == "Windows":
                try:
                    # Fallback to terminal bell on Windows to avoid winsound type issues
                    print("\a", end="", flush=True)
                except Exception:
                    pass
            else:
                try:
                    sys.stdout.write("\a")
                    sys.stdout.flush()
                except Exception:
                    pass

    def show_marker_popup(self, event, key):
        if self.popup:
            self.popup.destroy()
        x = self.winfo_pointerx() - self.winfo_rootx()
        y = self.winfo_pointery() - self.winfo_rooty()
        self.popup = tk.Toplevel(self)
        self.popup.wm_overrideredirect(True)
        self.popup.configure(bg="#232526")
        self.popup.geometry(f"+{x+20}+{y+20}")
        alerts = self.marker_alerts.get(key, [])
        for alert in alerts:
            tk.Label(self.popup, text=alert, bg="#232526", fg=NEON_CYAN, font=get_font(9), justify='left', anchor='w').pack(anchor='w', padx=8, pady=2)

    def hide_marker_popup(self):
        if self.popup:
            self.popup.destroy()
            self.popup = None

    def check_log(self):
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                reader = list(csv.reader(f))
                for i, row in enumerate(reader[1:], 1):
                    if i > self.last_line:
                        self.display_alert(row)
                self.last_line = len(reader) - 1
        self.after(2000, self.check_log)

    def on_table_select(self, event):
        sel = self.table.selection()
        if not sel:
            return
        item = sel[0]
        values = self.table.item(item).get('values', [])
        url = values[-1] if values else ''
        if url and item not in self.pending_location_requests and item not in self.dynamic_markers:
            self.pending_location_requests.add(item)
            threading.Thread(target=self._process_row_location, args=(item, values, url), daemon=True).start()

        key = self.table_item_to_key.get(item)
        if not key:
            return
        # Center map on the selected alert and start blinking marker
        lat, lon = key
        try:
            self.map_widget.set_position(lat, lon)
            self.map_widget.set_zoom(8)
        except Exception:
            pass
        # Blink with severity color
        try:
            sev = (values[3] or '').lower()
            sev_color = SEVERITY_COLORS.get(sev, NEON_CYAN)
        except Exception:
            sev_color = NEON_CYAN
        self._start_blink(key, color=sev_color)

    # tksheet selection binding (only when using the Sheet widget)
    def on_sheet_select(self, event: Any):
        try:
            r = event.get("row") if isinstance(event, dict) else None
        except Exception:
            r = None
        if r is None or r < 0:
            return
        try:
            values = [self.table.get_cell_data(r, c) for c in range(len(COLUMNS))]  # type: ignore[attr-defined]
        except Exception:
            values = []
        url = values[-1] if values else ''
        if url and r not in self.pending_location_requests and r not in self.dynamic_markers:
            self.pending_location_requests.add(r)
            threading.Thread(target=self._process_row_location, args=(r, values, url), daemon=True).start()

        key = self.row_to_key.get(int(r))
        if not key:
            return
        lat, lon = key
        try:
            self.map_widget.set_position(lat, lon)
            self.map_widget.set_zoom(8)
        except Exception:
            pass
        # Blink with severity color derived from the row
        try:
            sev = (values[3] or '').lower()
            sev_color = SEVERITY_COLORS.get(sev, NEON_CYAN)
        except Exception:
            sev_color = NEON_CYAN
        self._start_blink(key, color=sev_color)

    def on_sheet_double_click(self, event: Any):
        try:
            r = event.get("row") if isinstance(event, dict) else None
            c = event.get("column") if isinstance(event, dict) else None
        except Exception:
            r = c = None
        if r is None or c is None:
            return
        if int(c) != _col_index("URL"):
            return
        try:
            values = [self.table.get_cell_data(r, i) for i in range(len(COLUMNS))]  # type: ignore[attr-defined]
        except Exception:
            values = []
        url = values[-1] if values else ''
        if not url:
            return
        threading.Thread(target=self._open_url_window_worker, args=(values, url), daemon=True).start()

    def on_table_double_click(self, event):
        try:
            region = self.table.identify('region', event.x, event.y)
            if not region:
                return
            # region like 'cell' or 'heading'
            if not region.startswith('cell'):
                return
            row_id = self.table.identify_row(event.y)
            col_id = self.table.identify_column(event.x)  # like '#10'
            if not row_id or not col_id:
                return
            # Map column index to name
            try:
                col_index = int(col_id.replace('#', '')) - 1
            except Exception:
                return
            if col_index < 0 or col_index >= len(COLUMNS):
                return
            col_name = COLUMNS[col_index][0]
            if col_name != 'URL':
                return
            values = self.table.item(row_id).get('values', [])
            url = values[-1] if values else ''
            if not url:
                return
            # Open URL directly in the default browser; no in-app preview window
            try:
                webbrowser.open(url)
            except Exception:
                pass
        except Exception:
            pass

    def _process_row_location(self, item_id, values, url):
        try:
            content = self._fetch_url_content(url)
            if not content:
                return
            # Also fetch additional context from configured URLs to help the model
            try:
                extra_content = self._fetch_additional_contents(url)
            except Exception:
                extra_content = ''
            combined = content
            if extra_content:
                combined = content + "\n\n" + extra_content
            location_data, raw_response = self._query_ollama_for_location(combined)
            if not location_data:
                return
            self._save_incident_json(url, values, content, location_data, raw_response)
            lat = location_data.get('latitude') or location_data.get('lat')
            lon = location_data.get('longitude') or location_data.get('lon')
            if lat is None or lon is None:
                return

            try:
                lat_f = float(lat)
                lon_f = float(lon)
            except (TypeError, ValueError):
                return

            location_text = location_data.get('location_name') or location_data.get('city') or location_data.get('country')
            self.after(0, lambda: self._handle_location_result(item_id, values, url, lat_f, lon_f, location_text, location_data))
        finally:
            self.pending_location_requests.discard(item_id)

    def _handle_location_result(self, item_id, values, url, lat, lon, location_text, location_data):
        key = (lat, lon)
        details = self._build_marker_details(values, location_text, url, location_data)
        if key not in self.marker_alerts:
            self.marker_alerts[key] = []
        self.marker_alerts[key].append(details)

        existing_marker = self.dynamic_markers.get(item_id)
        if existing_marker:
            try:
                existing_marker.delete()
            except Exception:
                pass

        # Color dynamic marker by severity and keep it very small
        try:
            sev = (values[3] or '').lower()
            sev_color = SEVERITY_COLORS.get(sev, NEON_CYAN)
        except Exception:
            sev_color = NEON_CYAN
        marker = self.map_widget.set_marker(lat, lon, text='', marker_color_circle=sev_color, marker_color_outside="#001f26", marker_size=6, marker_outline_width=2)
        self.dynamic_markers[item_id] = marker
        self.table_item_to_key[item_id] = key

        # Tooltip bindings removed to avoid runtime/type issues across environments

        if location_text:
            # Prefer a precise address if available, otherwise fall back to name/city
            addr = location_data.get('address') if isinstance(location_data, dict) else None
            city = location_data.get('city') if isinstance(location_data, dict) else None
            state = location_data.get('state') if isinstance(location_data, dict) else None
            country = location_data.get('country') if isinstance(location_data, dict) else None
            parts = []
            if addr:
                parts.append(addr)
            if city:
                parts.append(city)
            elif location_text and location_text not in (addr or ''):
                parts.append(location_text)
            if state:
                parts.append(state)
            if country:
                parts.append(country)
            region_display = ", ".join([p for p in parts if p]) if parts else location_text
            try:
                if self.using_sheet and Sheet is not None:
                    # Update Region cell in tksheet
                    self.table.set_cell_data(item_id, _col_index("Region"), region_display)  # type: ignore[attr-defined]
                else:
                    self.table.set(item_id, "Region", region_display)
            except Exception:
                pass

        try:
            self.map_widget.set_position(lat, lon)
            self.map_widget.set_zoom(8)
        except Exception:
            pass

        self._start_blink(key, color=sev_color)

    def _build_marker_details(self, values, location_text, url, location_data):
        try:
            ts, source, signal_type, severity, trigger_id, context = values[:6]
        except Exception:
            ts = source = signal_type = severity = trigger_id = context = ''
        location_meta = location_text or location_data.get('region') or location_data.get('country') or 'Unknown location'
        return (
            f"Time: {ts}\nSource: {source}\nType: {signal_type}\nSeverity: {severity}\n"
            f"Trigger: {trigger_id}\nLocation: {location_meta}\nURL: {url}"
        )

    def _start_blink(self, key, color=NEON_CYAN, blink_count=8, interval=400):
        """Create a temporary glowing marker that blinks for a short while at key (lat, lon)."""
        # cancel existing blink for this key
        if key in self.blink_jobs:
            try:
                self.after_cancel(self.blink_jobs.pop(key))
            except Exception:
                pass
        # ensure there's only one glow marker per key at a time
        if key in self.blink_markers and self.blink_markers[key]:
            try:
                self.blink_markers[key].delete()
            except Exception:
                pass
            self.blink_markers.pop(key, None)

        def do_blink(count):
            if count <= 0:
                # cleanup
                if key in self.blink_markers and self.blink_markers[key]:
                    try:
                        self.blink_markers[key].delete()
                    except Exception:
                        pass
                    self.blink_markers.pop(key, None)
                return
            # toggle glow marker on/off
            if key in self.blink_markers and self.blink_markers[key]:
                try:
                    self.blink_markers[key].delete()
                except Exception:
                    pass
                self.blink_markers.pop(key, None)
            else:
                try:
                    lat, lon = key
                    # larger, severity-colored marker to simulate a glow
                    glow = self.map_widget.set_marker(lat, lon, text='', marker_color_circle=color, marker_color_outside=NEON_GLOW, marker_size=16, marker_outline_width=6)
                    self.blink_markers[key] = glow
                except Exception:
                    pass
            # schedule next toggle
            try:
                job = self.after(interval, lambda: do_blink(count-1))
                self.blink_jobs[key] = job
            except Exception:
                pass

    def _fetch_url_content(self, url):
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"}
            response = requests.get(url, timeout=20, headers=headers)
            response.raise_for_status()
            return response.text
        except Exception:
            return None

    # ---------- URL Preview/Inspector ----------
    def _open_url_window_worker(self, values, url):
        html = self._fetch_url_content(url)
        meta = self._extract_metadata(html) if html else {}
        text = self._extract_text(html) if html else ''
        self.after(0, lambda: self._show_url_window(values, url, html, meta, text))

    def _show_url_window(self, values, url, html, meta, text):
        # Build window
        win = tk.Toplevel(self)
        win.title(f"URL Viewer — {urlparse(url).netloc}")
        win.geometry("1100x780")
        win.configure(bg="#000000")

        # Controls
        ctrl = tk.Frame(win, bg="#001f26")
        ctrl.pack(fill='x')
        tk.Label(ctrl, text=url, fg=NEON_CYAN, bg="#001f26", font=get_font(10, 'bold')).pack(side='left', padx=8, pady=6)
        tk.Button(ctrl, text="Open in Firefox", command=lambda u=url: self._open_in_firefox(u), bg="#003b46", fg="#e0e0e0").pack(side='right', padx=6)
        tk.Button(ctrl, text="Open in Browser", command=lambda u=url: webbrowser.open(u), bg="#003b46", fg="#e0e0e0").pack(side='right', padx=6)
        tk.Button(ctrl, text="Download & Save", command=lambda v=values, u=url, h=html, m=meta, t=text: self._save_snapshot(v, u, h, m, t), bg="#003b46", fg="#e0e0e0").pack(side='right', padx=6)

        # Notebook with Metadata and Preview
        nb = ttk.Notebook(win)
        nb.pack(fill='both', expand=True)

        # Metadata tab
        meta_frame = tk.Frame(nb, bg="#000000")
        meta_text = tk.Text(meta_frame, wrap='word', bg="#0a0a0a", fg="#d0d0d0", insertbackground=NEON_CYAN)
        meta_scroll = ttk.Scrollbar(meta_frame, command=meta_text.yview)
        meta_text.configure(yscrollcommand=meta_scroll.set)
        meta_text.pack(side='left', fill='both', expand=True)
        meta_scroll.pack(side='right', fill='y')
        meta_text.tag_configure('highlight', background='#2a4858', foreground='#ffffff')
        meta_text.insert('end', self._format_metadata(meta))

        # Preview tab (extracted text)
        prev_frame = tk.Frame(nb, bg="#000000")
        prev_text = tk.Text(prev_frame, wrap='word', bg="#0a0a0a", fg="#e0e0e0", insertbackground=NEON_CYAN)
        prev_scroll = ttk.Scrollbar(prev_frame, command=prev_text.yview)
        prev_text.configure(yscrollcommand=prev_scroll.set)
        prev_text.pack(side='left', fill='both', expand=True)
        prev_scroll.pack(side='right', fill='y')
        prev_text.tag_configure('highlight', background='#015958', foreground='#ffffff')
        prev_text.insert('end', text or '(no content)')

        nb.add(meta_frame, text='Metadata')
        nb.add(prev_frame, text='Preview')

        # Focus/highlight on relevant data from the row
        try:
            ctx = (values[5] or '').strip()
            trig = (values[4] or '').strip()
        except Exception:
            ctx = trig = ''
        terms = [t for t in [ctx, trig] if t]
        if terms:
            self._highlight_first(meta_text, terms)
            self._highlight_first(prev_text, terms)
            # Prefer showing the match in metadata first
            if self._has_match(meta_text):
                nb.select(meta_frame)
            elif self._has_match(prev_text):
                nb.select(prev_frame)

    def _has_match(self, text_widget):
        try:
            ranges = text_widget.tag_ranges('highlight')
            return bool(ranges)
        except Exception:
            return False

    def _highlight_first(self, text_widget, terms):
        try:
            content = text_widget.get('1.0', 'end')
            text_widget.tag_remove('highlight', '1.0', 'end')
            # Find first occurrence of any term (case-insensitive)
            lower = content.lower()
            idx = -1
            term_used = ''
            for t in terms:
                i = lower.find(t.lower())
                if i != -1 and (idx == -1 or i < idx):
                    idx = i
                    term_used = t
            if idx == -1:
                return
            # Compute index and highlight
            start = f"1.0+{idx}c"
            end = f"1.0+{idx+len(term_used)}c"
            text_widget.tag_add('highlight', start, end)
            text_widget.see(start)
        except Exception:
            pass

    def _open_in_firefox(self, url):
        try:
            if platform.system() == 'Darwin':
                # macOS: use the Firefox app
                os.system(f"open -a Firefox '{url}'")
            elif platform.system() == 'Windows':
                os.system(f'start firefox "{url}"')
            else:
                # Linux
                os.system(f'firefox "{url}" &')
        except Exception:
            webbrowser.open(url)

    def _extract_metadata(self, html):
        meta = {"title": None, "meta": []}
        if not html:
            return meta
        if BeautifulSoup:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                if soup.title and soup.title.string:
                    meta['title'] = soup.title.string.strip()
                for m in soup.find_all('meta'):
                    name = (m.get('name') or m.get('property') or '').strip()
                    content = (m.get('content') or '').strip()
                    if name or content:
                        meta['meta'].append({"name": name, "content": content})
                return meta
            except Exception:
                pass
        # Fallback: simple regex for meta tags
        try:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE|re.DOTALL)
            if title_match:
                meta['title'] = re.sub(r"\s+", " ", title_match.group(1)).strip()
            for m in re.finditer(r"<meta([^>]+)>", html, re.IGNORECASE):
                attrs = m.group(1)
                name_m = re.search(r"(?:name|property)\s*=\s*\"([^\"]+)\"", attrs, re.IGNORECASE)
                content_m = re.search(r"content\s*=\s*\"([^\"]*)\"", attrs, re.IGNORECASE)
                name = name_m.group(1) if name_m else ''
                content = content_m.group(1) if content_m else ''
                if name or content:
                    meta['meta'].append({"name": name, "content": content})
        except Exception:
            pass
        return meta

    def _format_metadata(self, meta):
        lines = []
        if meta.get('title'):
            lines.append(f"Title: {meta['title']}")
        if meta.get('meta'):
            lines.append("Meta tags:")
            for m in meta['meta']:
                lines.append(f"  - {m.get('name')}: {m.get('content')}")
        return "\n".join(lines) if lines else "(no metadata)"

    def _sanitize_dirname(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc or 'site'
        path = parsed.path.replace('/', '_') or 'root'
        base = f"{netloc}_{path}"[:80]
        base = re.sub(r"[^A-Za-z0-9_\-]", "_", base)
        return base

    def _save_snapshot(self, values, url, html, meta, text):
        try:
            dirname = self._sanitize_dirname(url)
            dir_path = Path(SNAPSHOT_BASE_DIR) / dirname
            dir_path.mkdir(parents=True, exist_ok=True)
            ts = datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S')
            # Files
            (dir_path / f"{ts}_page.html").write_text(html or '', encoding='utf-8')
            snapshot = {
                'url': url,
                'timestamp_utc': ts,
                'row': {col: values[idx] if idx < len(values) else '' for idx, (col, _) in enumerate(COLUMNS)},
                'metadata': meta
            }
            (dir_path / f"{ts}_metadata.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
            (dir_path / f"{ts}_text.txt").write_text(text or '', encoding='utf-8')
        except Exception:
            pass

    def _query_ollama_for_location(self, content):
        if not content:
            return None, None
        excerpt = content.strip()
        if len(excerpt) > 5000:
            excerpt = excerpt[:5000]
        # Build a deterministic prompt asking the model to return strict JSON with
        # address and coordinates. We ask for street-level/address inference when
        # possible and include a confidence score.
        prompt = (
            "You are a geolocation analyst. Read the following incident report and respond with a JSON object ONLY (no commentary)"
            " containing the following keys: 'location_name' (best human-readable name/address), 'address' (street address if available),"
            " 'city', 'state', 'postal_code', 'country', 'latitude', 'longitude', and 'confidence' (0.0-1.0). If a field is unknown, set it to null. "
            "Respond with valid JSON only. Incident report:\n" + excerpt
        )

        # Try the configured model and explicit fallback chain.
        models_to_try = [OLLAMA_MODEL] + [m for m in OLLAMA_FALLBACK if m and m != OLLAMA_MODEL]

        def try_parse_candidate(raw_candidate):
            # If the candidate is already a dict-like, accept it
            if isinstance(raw_candidate, dict):
                return raw_candidate
            if not isinstance(raw_candidate, str):
                raw_candidate = str(raw_candidate)
            cleaned = raw_candidate.strip()
            # Strip common fences and leading labels
            cleaned = cleaned.strip('`\n ')
            cleaned = re.sub(r'^json[:\s]*', '', cleaned, flags=re.IGNORECASE)

            # Try direct JSON parse
            try:
                return json.loads(cleaned)
            except Exception:
                pass

            # Try to extract the first JSON object substring
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except Exception:
                    pass
            return None

        for model in models_to_try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            # First try HTTP API
            try:
                t0 = time.time()
                resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
                elapsed = time.time() - t0
                try:
                    resp.raise_for_status()
                except Exception:
                    # HTTP error - try CLI fallback for this model
                    raise
                try:
                    data = resp.json()
                except Exception:
                    data = None
                raw_candidate = None
                if isinstance(data, dict):
                    # Ollama HTTP may return nested fields; try common ones
                    raw_candidate = data.get("response") or data.get("text") or data.get("output") or data
                elif isinstance(data, str):
                    raw_candidate = data
                # If we have something, try to parse it immediately
                if raw_candidate is not None:
                    parsed = try_parse_candidate(raw_candidate)
                    if parsed:
                        return parsed, raw_candidate
                    # otherwise continue to CLI fallback for this model
            except requests.Timeout:
                # timeout -> try next model
                continue
            except Exception:
                # fall through to CLI attempt
                pass

            # Try CLI fallback for this model (non-blocking attempt)
            try:
                # Prefer JSON flag if available
                proc = subprocess.run(["ollama", "generate", model, "--prompt", prompt, "--json"], capture_output=True, text=True, timeout=OLLAMA_TIMEOUT)
                if proc.returncode == 0 and proc.stdout:
                    raw_candidate = proc.stdout.strip()
                    parsed = try_parse_candidate(raw_candidate)
                    if parsed:
                        return parsed, raw_candidate
                # fallback without --json
                proc2 = subprocess.run(["ollama", "generate", model, "--prompt", prompt], capture_output=True, text=True, timeout=OLLAMA_TIMEOUT)
                if proc2.returncode == 0 and proc2.stdout:
                    raw_candidate = proc2.stdout.strip()
                    parsed = try_parse_candidate(raw_candidate)
                    if parsed:
                        return parsed, raw_candidate
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        # No model returned valid JSON
        return None, None

    def _save_incident_json(self, url, values, content, location_data, raw_response):
        filename = self._build_json_filename(url)
        data = {
            "url": url,
            "retrieved_at": datetime.utcnow().isoformat() + "Z",
            "columns": {col: values[idx] if idx < len(values) else "" for idx, (col, _) in enumerate(COLUMNS)},
            "location": location_data,
            "model_response": raw_response,
            "extracted_text": self._extract_text(content)
        }
        try:
            with open(os.path.join(OUTPUT_JSON_DIR, filename), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _build_json_filename(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc or "incident"
        path = parsed.path.replace('/', '_') or "root"
        base = f"{netloc}_{path}"[:80]
        base = re.sub(r"[^A-Za-z0-9_\-]", "_", base)
        unique = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
        return f"{base}_{unique}.json"

    def _extract_text(self, content):
        if not content:
            return ""
        if BeautifulSoup:
            try:
                soup = BeautifulSoup(content, "html.parser")
                text = soup.get_text(separator=" ", strip=True)
                return text[:10000]
            except Exception:
                pass
        # fallback strip tags
        text = re.sub(r"<[^>]+>", " ", content)
        text = re.sub(r"\s+", " ", text)
        return text.strip()[:10000]

    def _load_additional_urls(self):
        """Read the additional URLs file and return a cleaned list of URLs."""
        path = os.path.join(BASE_PATH, "data", "additional_urls.txt")
        urls = []
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        urls.append(line)
        except Exception:
            return []
        return urls

    def _fetch_additional_contents(self, main_url):
        """Fetch textual content from the configured additional URLs (excluding main_url).

        Returns a concatenated string limited in size to avoid overwhelming the model.
        """
        parts = []
        total = 0
        max_total = 10000  # characters
        max_per = 4000
        max_count = 10
        headers = {"User-Agent": "Mozilla/5.0 (compatible; ACE-T/1.0)"}
        for u in self.additional_urls:
            if not u or u == main_url:
                continue
            try:
                resp = requests.get(u, timeout=8, headers=headers)
                resp.raise_for_status()
                text = self._extract_text(resp.text)
                if not text:
                    continue
                snippet = text[:max_per]
                parts.append(snippet)
                total += len(snippet)
                if len(parts) >= max_count or total >= max_total:
                    break
            except Exception:
                continue
        return "\n\n".join(parts)

    def _benchmark_models(self, models_to_probe=None, per_model_timeout=10):
        """Probe a short, deterministic prompt against each model and pick the fastest
        model that returns valid JSON for the sample. Persist the choice to
        BASE_PATH/.preferred_ollama_model and return the selected model name or None.
        """
        sample_prompt = (
            "You are a geolocation extractor. Return ONLY a JSON object with keys:"
            " 'location_name','address','city','state','postal_code','country','latitude','longitude','confidence'."
            " If a field is unknown, set it to null. Text: '1600 Amphitheatre Parkway, Mountain View, CA'."
        )
        # prepare defaults
        orig_timeout = globals().get('OLLAMA_TIMEOUT', 30)
        chosen = None
        best_time = float('inf')
        if models_to_probe is None:
            # probe phi4-mini, then deepcoder
            models_to_probe = ["phi4-mini"] + [m for m in (OLLAMA_FALLBACK or []) if m]
        for model in models_to_probe:
            # temporarily set the module-level model and timeout
            prev_model = globals().get('OLLAMA_MODEL')
            globals()['OLLAMA_MODEL'] = model
            globals()['OLLAMA_TIMEOUT'] = per_model_timeout
            t0 = time.time()
            try:
                loc, raw = self._query_ollama_for_location(sample_prompt)
            except Exception:
                loc = None
                raw = None
            elapsed = time.time() - t0
            # restore
            globals()['OLLAMA_MODEL'] = prev_model
            globals()['OLLAMA_TIMEOUT'] = orig_timeout

            if loc:
                # prefer the fastest valid result
                if elapsed < best_time:
                    chosen = model
                    best_time = elapsed
        # persist if chosen
        try:
            if chosen:
                pref_file = os.path.join(BASE_PATH, '.preferred_ollama_model')
                with open(pref_file, 'w', encoding='utf-8') as fh:
                    fh.write(chosen)
                # update runtime preference
                globals()['OLLAMA_MODEL'] = chosen
                return chosen
        except Exception:
            pass
        return None

def run_gui(benchmark_only: bool = False):
    """Run the GUI. If benchmark_only is True, run the Ollama startup benchmark and print the chosen model to stdout, then exit.
    This is useful for automated startup testing without launching the full Tkinter loop.
    """
    app = AlertGUI()
    if benchmark_only:
        chosen = app._benchmark_models(models_to_probe=["phi4-mini", "deepcoder:1.5b"], per_model_timeout=10)
        if chosen:
            print(f"PREFERRED_MODEL={chosen}")
            return 0
        else:
            print("PREFERRED_MODEL=None")
            return 2
    app.mainloop()

if __name__ == "__main__":
    run_gui()
