import os
import json
import shutil
from datetime import datetime

ALERTS_DIR = "/Users/mbaosint/Desktop/Projects/ACE-T/output"
DEST_DIR = "/Volumes/X10 Pro/Data/2_RAW_DATA/ACE-T"

# Get all JSON files (excluding logs.json and any combined/master files)
alert_files = [
    f for f in os.listdir(ALERTS_DIR)
    if f.endswith(".json")
    and not f.startswith("logs")
    and "combined_alerts" not in f
    and "master" not in f
]

alerts = []
seen = set()
skipped_files = 0
error_files = []

for filename in alert_files:
    filepath = os.path.join(ALERTS_DIR, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Use the string representation for deduplication
            data_str = json.dumps(data, sort_keys=True)
            if data_str not in seen:
                alerts.append(data)
                seen.add(data_str)
            else:
                skipped_files += 1
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        error_files.append(filename)

now = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
output_file = os.path.join(DEST_DIR, f"{now}_master.json")

with open(output_file, "w", encoding="utf-8") as out:
    json.dump(alerts, out, indent=2, ensure_ascii=False)

print(f"Combined {len(alerts)} unique alerts into {output_file}")
print(f"Skipped {skipped_files} duplicate files.")
if error_files:
    print(f"Encountered errors with the following files: {', '.join(error_files)}")
else:
    print("No errors encountered.")