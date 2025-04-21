import os
import json
import shutil

ALERTS_DIR = "output"
REVIEW_DIR = "alerts_for_review"
os.makedirs(REVIEW_DIR, exist_ok=True)

reviewed_files = 0
skipped_files = 0
error_files = []

for filename in os.listdir(ALERTS_DIR):
    if filename.endswith(".json") and filename != "logs.json":
        filepath = os.path.join(ALERTS_DIR, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                alerts = data if isinstance(data, list) else [data]
                for alert in alerts:
                    severity = alert.get("severity", "").lower()
                    if severity in ("medium", "high"):
                        shutil.copy(filepath, os.path.join(REVIEW_DIR, filename))
                        reviewed_files += 1
                        break  # Only need to copy once per file
                else:
                    skipped_files += 1
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            error_files.append(filename)

print(f"Copied {reviewed_files} files with medium/high severity alerts to {REVIEW_DIR}.")
print(f"Skipped {skipped_files} files (no medium/high severity alerts).")
if error_files:
    print(f"Errors encountered in: {', '.join(error_files)}")
else:
    print("No errors encountered.")