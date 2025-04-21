"""
combine_alerts.py

Combines all alert JSON files in the output directory into a single file, robustly handling errors, duplicates, and file integrity. Moves the combined file to an external drive with a timestamp. Includes logging, validation, and summary reporting for maximum reliability.
"""
import os
import json
import shutil
from datetime import datetime
import logging
from typing import List, Dict, Any
from jsonschema import validate, ValidationError

# --- Logging Setup ---
LOG_FILE = os.path.join("output", "combine_alerts.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

# --- Config ---
ALERTS_DIR = "output"
DEST_DIR = "/Volumes/X10 Pro/Data/2_RAW_DATA/ACE-T"

# --- Advanced: Schema Validation ---
ALERT_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "timestamp": {"type": "string"},
        "title": {"type": "string"},
        "crawled_at": {"type": "string"},
        "error": {"type": ["string", "null"]},
    },
    "required": ["source", "timestamp", "title"]
}

def is_valid_alert(alert: Any) -> bool:
    # Schema validation for robust alert structure
    try:
        validate(instance=alert, schema=ALERT_SCHEMA)
        return True
    except ValidationError as ve:
        logging.warning(f"Schema validation failed: {ve.message}")
        return False
    except Exception as e:
        logging.error(f"Unexpected validation error: {e}")
        return False

def deduplicate_alerts(alerts: List[Dict]) -> List[Dict]:
    seen = set()
    unique_alerts = []
    for alert in alerts:
        # Use a tuple of (source, timestamp, title) as a unique key if available
        key = (
            alert.get("source", ""),
            alert.get("timestamp", alert.get("crawled_at", "")),
            alert.get("title", "")
        )
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)
    return unique_alerts

# --- Advanced: Alert Enrichment (GeoIP, Threat Intel Stub) ---
def enrich_alert(alert: Dict) -> Dict:
    # Example enrichment: add geolocation and threat score (stubbed)
    # In production, integrate with real APIs/services
    alert = alert.copy()
    # GeoIP stub (could use geoip2 or similar in production)
    if 'ip' in alert:
        alert['geo'] = {
            'country': 'Unknown',
            'city': 'Unknown',
            'lat': None,
            'lon': None
        }
    # Threat intelligence stub
    alert['threat_score'] = 0  # Replace with real scoring logic
    alert['enriched_at'] = datetime.utcnow().isoformat()
    return alert

# --- Main Logic ---
alert_files = [
    f for f in os.listdir(ALERTS_DIR)
    if f.endswith(".json") and not f.startswith("logs") and "combined_alerts" not in f
]

combined_alerts = []
deleted_files = []
skipped_files = 0
error_files = []
invalid_files = []

for filename in alert_files:
    filepath = os.path.join(ALERTS_DIR, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Accept both single alert dicts and lists of alerts
            if isinstance(data, list):
                valid = [a for a in data if is_valid_alert(a)]
                if len(valid) < len(data):
                    invalid_files.append(filename)
                combined_alerts.extend(valid)
            elif is_valid_alert(data):
                combined_alerts.append(data)
            else:
                invalid_files.append(filename)
                continue
        os.remove(filepath)
        deleted_files.append(filename)
    except Exception as e:
        logging.error(f"Error reading or deleting {filename}: {e}")
        error_files.append(filename)

# Enrich alerts after validation and before deduplication
combined_alerts = [enrich_alert(a) for a in combined_alerts]

# Deduplicate alerts
before_dedup = len(combined_alerts)
combined_alerts = deduplicate_alerts(combined_alerts)
after_dedup = len(combined_alerts)
duplicates_removed = before_dedup - after_dedup

# Generate output filename with current date and time
now = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
output_file = os.path.join(ALERTS_DIR, f"{now}_combined_alerts.json")

try:
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(combined_alerts, out, indent=2, ensure_ascii=False)
    dest_file = os.path.join(DEST_DIR, f"{now}_combined_alerts.json")
    shutil.move(output_file, dest_file)
    logging.info(f"Combined {after_dedup} unique alert(s) into {dest_file}")
except Exception as e:
    logging.critical(f"Failed to write or move combined file: {e}")
    raise

logging.info(f"Duplicates removed: {duplicates_removed}")
logging.info(f"Skipped {skipped_files} duplicate files.")
if deleted_files:
    logging.info(f"Deleted original files: {', '.join(deleted_files)}")
else:
    logging.info("No files were deleted.")
if error_files:
    logging.warning(f"Encountered errors with the following files: {', '.join(error_files)}")
if invalid_files:
    logging.warning(f"Files with invalid alert structure: {', '.join(invalid_files)}")
else:
    logging.info("No errors or invalid files encountered.")

print(f"Combined {after_dedup} unique alert(s) into {dest_file}")
print(f"Duplicates removed: {duplicates_removed}")
if deleted_files:
    print(f"Deleted original files: {', '.join(deleted_files)}")
if error_files:
    print(f"Encountered errors with the following files: {', '.join(error_files)}")
if invalid_files:
    print(f"Files with invalid alert structure: {', '.join(invalid_files)}")
