import tkinter as tk
from tkinter import ttk
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

import requests

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None

from tkintermapview import TkinterMapView

SEVERITY_COLORS = {
    "low": "#39ff14",       # Neon green
    "mild": "#f4ff52",      # Neon yellow
    "medium": "#ff6ec7",    # Neon pink
    "high": "#ff073a"       # Neon red
}

# Neon styling for map highlights and UI accents
NEON_CYAN = "#00f5ff"
NEON_GLOW = "#00d8e6"

BASE_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(BASE_PATH, "output", "logs.csv")
OUTPUT_JSON_DIR = os.path.join(BASE_PATH, "output", "incidents")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
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

        # Severity legend (top-right)
        legend = tk.Frame(self, bg="#000000")
        for sev, color in SEVERITY_COLORS.items():
            lbl = tk.Label(legend, text=sev.capitalize(), bg="#001f26", fg=color, font=get_font(9, "bold"), width=9, relief='flat', bd=0, padx=2, pady=2)
            lbl.pack(side='right', padx=2, pady=2)
        legend.pack(fill='x', padx=8, pady=(0, 4), anchor='e')

        # Main content frame (top half: table, bottom half: map)
        self.content_frame = tk.Frame(self, bg="#000000")
        self.content_frame.pack(fill='both', expand=True)

        # Table for alerts (top half)
        self.table_frame = tk.Frame(self.content_frame, bg="#000000")
        self.table_frame.pack(fill='both', expand=True, side='top')
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("Treeview", background="#000000", fieldbackground="#000000", foreground="#e0e0e0", font=get_font(10), rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background="#001f26", foreground=NEON_CYAN, font=get_font(10, "bold"))
        style.map('Treeview', background=[('selected', '#003b46')])
        self.table = ttk.Treeview(self.table_frame, columns=[c[0] for c in COLUMNS], show='headings', selectmode='browse')
        for col, width in COLUMNS:
            self.table.heading(col, text=col)
            self.table.column(col, width=width, anchor='w')
        self.table.pack(expand=True, fill='both', padx=16, pady=6)

        # Map widget (bottom half)
        self.map_frame = tk.Frame(self.content_frame, bg="#000000")
        self.map_frame.pack(fill='both', expand=True, side='bottom')
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

        # Keep mapping of table items to marker locations for interactive highlighting
        self.table_item_to_key = {}
        self.blink_jobs = {}  # key -> after job id
        self.blink_markers = {}  # key -> glow marker
        self.dynamic_markers = {}
        self.pending_location_requests = set()

        self.popup = None  # For temporary alert popup

        footer = tk.Label(self, text="ACE-T Intelligence Platform | Alerts auto-refresh | Severity: Neon colors indicate risk level", font=get_font(8), fg="#4dffff", bg="#000000", pady=4)
        footer.pack(fill='x', side='bottom', padx=8, pady=(0, 6))

        self.last_line = 0
        # Bind table selection to show blinking marker
        self.table.bind('<<TreeviewSelect>>', self.on_table_select)
        self.after(1000, self.check_log)
        os.makedirs(OUTPUT_JSON_DIR, exist_ok=True)

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
        values = [ts, source, signal_type, severity.upper(), trigger_id, context, region, trend, sentiment, url]
        tag = severity.lower()
        item_id = self.table.insert('', 'end', values=values, tags=(tag,))
        self.table.tag_configure(tag, foreground=SEVERITY_COLORS.get(tag, "#e0e0e0"))

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
                color = SEVERITY_COLORS.get(tag, "#e0e0e0")
                label = f"{city}, {country}" if city else (state or country or zipcode)
                details = f"Time: {ts}\nSource: {source}\nType: {signal_type}\nSeverity: {severity}\nTrigger: {trigger_id}\nContext: {context}\nRegion: {region}\nCity: {city}\nState: {state}\nCountry: {country}\nZip: {zipcode}\nTrend: {trend}\nSentiment: {sentiment}\nURL: {url}"
                key = (float(lat), float(lon))
                if key not in self.marker_alerts:
                    self.marker_alerts[key] = []
                self.marker_alerts[key].append(details)
                # Use a small, unique, classy marker (circle with border)
                marker = self.map_widget.set_marker(float(lat), float(lon), text='', marker_color_circle=color, marker_color_outside="#232526", marker_size=8, marker_outline_width=2)
                # remember the table item -> key mapping so that clicking a row will highlight the marker
                try:
                    self.table_item_to_key[item_id] = key
                except Exception:
                    pass
                try:
                    marker.canvas.bind('<Enter>', lambda e, k=key: self.show_marker_popup(e, k))
                    marker.canvas.bind('<Leave>', lambda e: self.hide_marker_popup())
                except Exception:
                    # some marker implementations may not expose canvas; ignore
                    pass
                self.map_markers.append(marker)
        except Exception:
            pass

        # Enhanced alerting: pop to front and play sound on high severity
        if tag == "high":
            self.lift()
            self.attributes('-topmost', True)
            self.after(1000, lambda: self.attributes('-topmost', False))
            if platform.system() == "Darwin":
                print("\a", end="", flush=True)
            elif platform.system() == "Windows":
                import winsound
                try:
                    winsound.Beep(1000, 300)
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
        self._start_blink(key)

    def _process_row_location(self, item_id, values, url):
        try:
            content = self._fetch_url_content(url)
            if not content:
                return
            location_data, raw_response = self._query_ollama_for_location(content)
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

        marker = self.map_widget.set_marker(lat, lon, text='', marker_color_circle=NEON_CYAN, marker_color_outside="#001f26", marker_size=10, marker_outline_width=3)
        self.dynamic_markers[item_id] = marker
        self.table_item_to_key[item_id] = key

        try:
            marker.canvas.bind('<Enter>', lambda e, k=key: self.show_marker_popup(e, k))
            marker.canvas.bind('<Leave>', lambda e: self.hide_marker_popup())
        except Exception:
            pass

        if location_text:
            self.table.set(item_id, "Region", location_text)

        try:
            self.map_widget.set_position(lat, lon)
            self.map_widget.set_zoom(8)
        except Exception:
            pass

        self._start_blink(key)

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

    def _start_blink(self, key, blink_count=8, interval=400):
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
                    # larger, neon-colored marker to simulate a glow
                    glow = self.map_widget.set_marker(lat, lon, text='', marker_color_circle=NEON_CYAN, marker_color_outside=NEON_GLOW, marker_size=18, marker_outline_width=6)
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
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response.text
        except Exception:
            return None

    def _query_ollama_for_location(self, content):
        if not content:
            return None, None
        excerpt = content.strip()
        if len(excerpt) > 5000:
            excerpt = excerpt[:5000]
        prompt = (
            "You are a geolocation analyst. Read the following incident report and respond with a JSON object containing "
            "'location_name', 'city', 'region', 'country', 'latitude', 'longitude', and optionally 'confidence'. The JSON "
            "must be valid and should not include any additional commentary. Incident report:\n" + excerpt
        )
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            raw_response = data.get("response") or data
        except Exception:
            return None, None

        if isinstance(raw_response, dict):
            return raw_response, raw_response

        if not isinstance(raw_response, str):
            return None, None

        cleaned = raw_response.strip()
        cleaned = cleaned.strip('`\n')
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()
        cleaned = cleaned.strip()
        try:
            location_data = json.loads(cleaned)
            return location_data, raw_response
        except json.JSONDecodeError:
            # attempt to extract JSON substring
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    location_data = json.loads(match.group(0))
                    return location_data, raw_response
                except json.JSONDecodeError:
                    pass
        return None, raw_response

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

def run_gui():
    app = AlertGUI()
    app.mainloop()

if __name__ == "__main__":
    run_gui()
