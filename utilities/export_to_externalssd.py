"""
export_to_externalssd.py

This utility moves the logs.csv and logs.json files from the ACE-T output directory to the external SSD, organizing them by type (csv/json) and appending the current date and time to the filenames. It ensures the destination directories exist before moving the files.
"""

import os
import shutil
from datetime import datetime

# Source files
src_csv = "/Users/mbaosint/Desktop/Projects/ACE-T/output/logs.csv"
src_json = "/Users/mbaosint/Desktop/Projects/ACE-T/output/logs.json"

# Destination directories
base_dst_dir = "/Volumes/X10 Pro/Data/2_RAW_DATA/ACE-T/Logs"
dst_csv_dir = os.path.join(base_dst_dir, "csv")
dst_json_dir = os.path.join(base_dst_dir, "json")

# Ensure destination directories exist
os.makedirs(dst_csv_dir, exist_ok=True)
os.makedirs(dst_json_dir, exist_ok=True)

# Get current date and time
now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Destination file paths with date/time in filename
csv_filename = f"{now}_logs.csv"
json_filename = f"{now}_logs.json"
dst_csv = os.path.join(dst_csv_dir, csv_filename)
dst_json = os.path.join(dst_json_dir, json_filename)

# Move and rename files instead of copying
shutil.move(src_csv, dst_csv)
shutil.move(src_json, dst_json)

print(f"Moved and renamed:\n{dst_csv}\n{dst_json}")