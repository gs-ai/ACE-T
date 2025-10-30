import threading
import time
import os
import glob
import csv
import datetime
from ace_t_osint.modules import pastebin, reddit, ghostbin, rentry, chans, telegram, twitter, archive_org, github, shodan, crtsh, trends
import ace_t_osint.utils.utils as utils

# Set OUTPUT_DIR to project root 'output' directory
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Patch utils to use new output dir
utils.DEFAULT_OUTPUT_DIR = OUTPUT_DIR

def run_module(mod, triggers):
    while True:
        try:
            print(f"[DEBUG] Starting module: {mod.__name__}")
            mod(triggers)
        except Exception as e:
            print(f"[ERROR] Module {mod.__name__} crashed: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(10)

def show_log_sample():
    log_dir = OUTPUT_DIR
    csv_path = os.path.join(log_dir, "logs.csv")
    print(f"[i] Logs directory: {log_dir}")
    if os.path.exists(csv_path):
        print("[i] Recent log entries:")
        with open(csv_path, "r") as f:
            lines = f.readlines()[-5:]
            for line in lines:
                print(line.strip())
    else:
        print("[i] No logs yet. They will appear here as triggers are detected.")

def print_status(modules):
    print(f"[STATUS] {datetime.datetime.now().isoformat()} | Running modules: " + ", ".join([m.__name__ for m in modules]))
    try:
        log_dir = OUTPUT_DIR
        csv_path = os.path.join(log_dir, "logs.csv")
        if os.path.exists(csv_path):
            with open(csv_path, "r") as f:
                lines = f.readlines()[-3:]
                print("[STATUS] Last 3 log entries:")
                for line in lines:
                    print("[STATUS]   " + line.strip())
        else:
            print("[STATUS] No logs yet.")
    except Exception as e:
        print(f"[STATUS] Error reading logs: {e}")

if __name__ == "__main__":
    triggers_raw = utils.load_triggers()
    # Normalize triggers to canonical shape so modules receive consistent data
    triggers = utils.normalize_triggers(triggers_raw)
    modules = [
        pastebin.monitor_pastebin,
        reddit.monitor_reddit,
        ghostbin.monitor_ghostbin,
        rentry.monitor_rentry,
        chans.monitor_chans,
        telegram.monitor_telegram,
        twitter.monitor_twitter,
        archive_org.monitor_archive_org,
        github.monitor_github,
        shodan.monitor_shodan,
        crtsh.monitor_crtsh,
        trends.monitor_trends
    ]
    threads = []
    for mod in modules:
        print(f"[DEBUG] Launching thread for module: {mod.__name__}")
        t = threading.Thread(target=run_module, args=(mod, triggers), daemon=True)
        t.start()
        threads.append(t)
    print("[*] ACE-T OSINT Stealth Monitor running.")
    show_log_sample()
    try:
        while True:
            print_status(modules)
            time.sleep(60)
    except KeyboardInterrupt:
        print("Shutting down.")

# This file has been moved to ace_t_osint/monitor/main.py
