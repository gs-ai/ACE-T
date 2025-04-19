# This file has been moved to ace_t_osint/ingest/log_ingest.py

import csv
import os
import time
import requests

BACKEND_URL = "http://127.0.0.1:8000/api/osint/"
LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "logs.csv")
SENT = set()

def ingest_logs():
    while True:
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                reader = list(csv.reader(f))
                for row in reader[1:]:
                    key = tuple(row)
                    if key in SENT:
                        continue
                    data = {
                        "source": row[1],
                        "content": row[5],
                        "tags": row[2],
                    }
                    try:
                        requests.post(BACKEND_URL, json=data, timeout=5)
                        SENT.add(key)
                    except Exception as e:
                        print(f"[log_ingest] Error: {e}")
        time.sleep(10)

if __name__ == "__main__":
    ingest_logs()
