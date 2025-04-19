import csv
import os
from collections import Counter, defaultdict

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "logs.csv")

def summarize_logs():
    if not os.path.exists(LOG_PATH):
        print("No logs found.")
        return
    with open(LOG_PATH, "r") as f:
        reader = list(csv.reader(f))
        if len(reader) < 2:
            print("No log entries.")
            return
        sources = Counter()
        severities = Counter()
        triggers = Counter()
        for row in reader[1:]:
            sources[row[1]] += 1
            severities[row[3]] += 1
            triggers[row[4]] += 1
        print("\n--- OSINT Log Analytics ---")
        print(f"Total events: {len(reader)-1}")
        print("By Source:")
        for src, cnt in sources.most_common():
            print(f"  {src}: {cnt}")
        print("By Severity:")
        for sev, cnt in severities.most_common():
            print(f"  {sev}: {cnt}")
        print("By Trigger ID:")
        for trig, cnt in triggers.most_common():
            print(f"  {trig}: {cnt}")
        print("--------------------------\n")

if __name__ == "__main__":
    summarize_logs()

# This file has been moved to ace_t_osint/analytics/analytics.py
