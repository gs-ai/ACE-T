import tkinter as tk
from tkinter import ttk
import csv
import os
import platform
import sys
import json

SEVERITY_COLORS = {
    "low": "#2ecc40",
    "mild": "#ffe066",
    "medium": "#ffb347",
    "high": "#ff4c4c"
}

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "output", "logs.csv")

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
        self.configure(bg="#181a1b")
        self.geometry("1200x540")
        self.resizable(True, True)
        if platform.system() == "Darwin":
            self.attributes('-alpha', 0.97)
        self.config(highlightbackground="#222", highlightcolor="#222", highlightthickness=1)
        self['bd'] = 0
        header = tk.Label(self, text="ACE-T OSINT ALERTS", font=get_font(18, "bold"), fg="#ffe066", bg="#181a1b", pady=8)
        header.pack(fill='x', padx=8, pady=(8, 0))
        legend = tk.Frame(self, bg="#181a1b")
        for sev, color in SEVERITY_COLORS.items():
            lbl = tk.Label(legend, text=sev.capitalize(), bg="#232526", fg=color, font=get_font(9, "bold"), width=9, relief='flat', bd=0, padx=2, pady=2)
            lbl.pack(side='right', padx=2, pady=2)
        legend.pack(fill='x', padx=8, pady=(0, 4), anchor='e')
        # Table for alerts
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("Treeview", background="#181a1b", fieldbackground="#181a1b", foreground="#e0e0e0", font=get_font(10), rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background="#232526", foreground="#ffe066", font=get_font(10, "bold"))
        style.map('Treeview', background=[('selected', '#333')])
        self.table = ttk.Treeview(self, columns=[c[0] for c in COLUMNS], show='headings', selectmode='browse')
        for col, width in COLUMNS:
            self.table.heading(col, text=col)
            self.table.column(col, width=width, anchor='w')
        self.table.pack(expand=True, fill='both', padx=16, pady=6)
        footer = tk.Label(self, text="ACE-T Intelligence Platform | Alerts auto-refresh | Severity: Green=Low, Yellow=Mild, Orange=Medium, Red=High", font=get_font(8), fg="#888", bg="#181a1b", pady=4)
        footer.pack(fill='x', side='bottom', padx=8, pady=(0, 6))
        self.last_line = 0
        self.after(1000, self.check_log)

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
        self.table.insert('', 'end', values=values, tags=(tag,))
        self.table.tag_configure(tag, foreground=SEVERITY_COLORS.get(tag, "#e0e0e0"))
        # Enhanced alerting: pop to front and play sound on high severity
        if tag == "high":
            self.lift()
            self.attributes('-topmost', True)
            self.after(1000, lambda: self.attributes('-topmost', False))
            if platform.system() == "Darwin":
                print("\a", end="", flush=True)
            elif platform.system() == "Windows":
                import winsound
                winsound.Beep(1000, 300)
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()

    def check_log(self):
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                reader = list(csv.reader(f))
                for i, row in enumerate(reader[1:], 1):
                    if i > self.last_line:
                        self.display_alert(row)
                self.last_line = len(reader) - 1
        self.after(2000, self.check_log)

def run_gui():
    app = AlertGUI()
    app.mainloop()

if __name__ == "__main__":
    run_gui()