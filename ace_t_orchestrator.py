import subprocess
import sys
import os
import time
import threading
import logging

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable

def run_backend():
    print("[DEBUG] Launching backend API (FastAPI)...")
    backend_path = os.path.join(PROJECT_ROOT, "backend", "app", "main.py")
    return subprocess.Popen([PYTHON, "-m", "uvicorn", "backend.app.main:app", "--reload"], cwd=PROJECT_ROOT)

def run_osint_monitor():
    print("[DEBUG] Launching OSINT monitor (all modules)...")
    monitor_path = os.path.join(PROJECT_ROOT, "ace_t_osint", "monitor", "main.py")
    return subprocess.Popen([PYTHON, monitor_path], cwd=PROJECT_ROOT)

def run_log_ingest():
    print("[DEBUG] Launching log ingester...")
    ingest_path = os.path.join(PROJECT_ROOT, "ace_t_osint", "ingest", "log_ingest.py")
    return subprocess.Popen([PYTHON, ingest_path], cwd=PROJECT_ROOT)

def run_alert_gui():
    print("[DEBUG] Launching alert GUI...")
    gui_path = os.path.join(PROJECT_ROOT, "ace_t_osint", "gui", "alert_gui.py")
    return subprocess.Popen([PYTHON, gui_path], cwd=PROJECT_ROOT)

def run_analytics():
    print("[DEBUG] Launching analytics...")
    analytics_path = os.path.join(PROJECT_ROOT, "ace_t_osint", "analytics", "analytics.py")
    return subprocess.Popen([PYTHON, analytics_path], cwd=PROJECT_ROOT)

def run_web_crawlers(spider_name=None):
    """
    Launch the Scrapy web crawler. Controlled by env var ENABLE_WEB_CRAWLERS (default: True).
    Spider can be selected via env var SCRAPY_SPIDER (default: 'example' or passed arg).
    """
    enable = os.environ.get("ENABLE_WEB_CRAWLERS", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Web crawlers are disabled by environment variable.")
        return None
    crawlers_path = os.path.join(PROJECT_ROOT, "web_crawlers", "ace_t_scraper")
    output_dir = os.path.join(PROJECT_ROOT, "alerts_for_review")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%dT%H-%M-%S")
    # Allow dynamic spider selection
    spider = spider_name or os.environ.get("SCRAPY_SPIDER", "example")
    output_file = os.path.join(output_dir, f"{timestamp}_{spider}.json")
    print(f"[DEBUG] Launching web crawler spider: {spider}")
    proc = subprocess.Popen([
        PYTHON, "-m", "scrapy", "crawl", spider, "-o", output_file
    ], cwd=crawlers_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc, output_file

def main():
    print("Starting ACE-T Orchestrator...")
    procs = []
    try:
        print("Launching backend API...")
        procs.append(run_backend())
        print("[orchestrator] Launching module: backend API")
        time.sleep(2)
        print("Launching OSINT monitor...")
        procs.append(run_osint_monitor())
        print("[orchestrator] Launching module: OSINT monitor")
        time.sleep(2)
        print("Launching log ingester...")
        procs.append(run_log_ingest())
        print("[orchestrator] Launching module: log ingester")
        time.sleep(2)
        print("Launching alert GUI...")
        procs.append(run_alert_gui())
        print("[orchestrator] Launching module: alert GUI")
        time.sleep(2)
        print("Launching web crawlers...")
        crawler_proc, crawler_output = run_web_crawlers()
        if crawler_proc:
            procs.append(crawler_proc)
            print(f"[orchestrator] Launching module: web crawlers (output: {crawler_output})")
            # Monitor crawler in a thread
            def monitor_crawler(proc, output_file):
                try:
                    stdout, stderr = proc.communicate()
                    if proc.returncode == 0:
                        print(f"[web_crawlers] Spider completed successfully. Output: {output_file}")
                    else:
                        print(f"[web_crawlers] Spider failed (code {proc.returncode}). See logs below.")
                        print(stdout.decode())
                        print(stderr.decode())
                except Exception as e:
                    print(f"[web_crawlers] Error monitoring spider: {e}")
            threading.Thread(target=monitor_crawler, args=(crawler_proc, crawler_output), daemon=True).start()
        else:
            print("[orchestrator] Web crawlers not started.")
        print("All components launched. Press Ctrl+C to stop.")
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("Shutting down all ACE-T components...")
        for p in procs:
            p.terminate()
        print("All processes terminated.")

if __name__ == "__main__":
    main()