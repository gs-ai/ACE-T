# ace_t_osint/utils.py
# This file has been moved to ace_t_osint/utils/utils.py
import requests
import random
import time
import json
import csv
import os
from datetime import datetime

TOR_SOCKS = "socks5h://127.0.0.1:9050"
STEALTH_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

# Change output dir to project root 'output' directory
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "output")

def stealth_get(url, timeout=15, use_tor=True, retries=3):
    headers = {
        "User-Agent": random.choice(STEALTH_UAS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close"
    }
    proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS} if use_tor else None
    for _ in range(retries):
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except Exception:
            time.sleep(2)
    return None

def log_signal(source, signal_type, severity, trigger_id, context, output_dir=None, extra_data=None):
    if output_dir is None:
        output_dir = DEFAULT_OUTPUT_DIR
    # Ensure output directory exists (absolute path)
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.utcnow().isoformat()
    row = {
        "timestamp": ts,
        "source": source,
        "signal_type": signal_type,
        "severity": severity,
        "trigger_id": trigger_id,
        "context": context
    }
    # --- Ensure extra_data for GUI columns ---
    if extra_data is None:
        extra_data = {}
    # Fill required fields for GUI columns
    region = extra_data.get('region')
    if not region:
        # Try to extract from geo_info if present
        geo = extra_data.get('geo_info', {})
        region = geo.get('country', '')
    trend = extra_data.get('trend')
    if not trend:
        # Try to extract from trend_velocity if present
        tv = extra_data.get('trend_velocity', {})
        if tv:
            trend = f"{tv.get('increase_percent', '')}% (vol: {tv.get('current_volume', '')})"
        else:
            trend = ''
    sentiment = extra_data.get('sentiment', '')
    url = extra_data.get('source_url', '')
    # Compose the extra field for CSV as JSON string
    extra_for_csv = json.dumps({
        'region': region or '',
        'trend': trend or '',
        'sentiment': sentiment or '',
        'source_url': url or ''
    })
    row["extra_data"] = extra_data  # for JSON
    row["extra"] = extra_for_csv    # for CSV GUI parsing
    # CSV
    csv_path = os.path.join(output_dir, "logs.csv")
    csv_fieldnames = ["timestamp", "source", "signal_type", "severity", "trigger_id", "context", "extra"]
    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fieldnames)
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow({k: row.get(k, '') for k in csv_fieldnames})
    # JSON
    json_path = os.path.join(output_dir, "logs.json")
    with open(json_path, "a") as f:
        f.write(json.dumps(row) + "\n")
    # Write alert to its own JSON file
    safe_source = source.replace('/', '_').replace(' ', '_')
    safe_trigger = str(trigger_id).replace('/', '_').replace(' ', '_')
    safe_time = ts.replace(':', '-').replace('.', '-')
    alert_filename = f"{safe_time}_{safe_source}_{safe_trigger}.json"
    alert_path = os.path.join(output_dir, alert_filename)
    with open(alert_path, "w") as f:
        json.dump(row, f, indent=2)

def load_triggers(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "triggers", "triggers.json")
    with open(path, "r") as f:
        return json.load(f)
