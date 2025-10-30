import subprocess
import sys
import os
import time
import threading
import logging

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# REPO_ROOT is one level up from scripts/
REPO_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, ".."))
PYTHON = sys.executable
import shutil
import urllib.request
import urllib.error

def _conda_run_prefix():
    """Return command prefix list to run commands under the ace-t-env conda env if conda is available.

    Returns an empty list if conda or the env isn't available. The caller should prepend the
    returned list to the command.
    """
    conda_path = shutil.which("conda")
    if not conda_path:
        return []
    # Return prefix that avoids capturing output and uses the named env
    return ["conda", "run", "-n", "ace-t-env", "--no-capture-output"]

def wait_for_backend(url="http://127.0.0.1:8000/openapi.json", timeout=30):
    """Poll the backend OpenAPI endpoint until ready or timeout (seconds).

    Returns True if reachable, False on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False

def run_backend():
    print("[DEBUG] Launching backend API (FastAPI)...")
    backend_path = os.path.join(REPO_ROOT, "backend", "app", "main.py")
    # allow disabling via env
    enable = os.environ.get("ENABLE_BACKEND", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Backend API disabled by environment variable.")
        return None
    # prefer module invocation for robustness
    cmd = _conda_run_prefix() + [PYTHON, "-m", "uvicorn", "backend.app.main:app", "--reload"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT)

def run_osint_monitor():
    print("[DEBUG] Launching OSINT monitor (all modules)...")
    monitor_path = os.path.join(REPO_ROOT, "ace_t_osint", "monitor", "main.py")
    enable = os.environ.get("ENABLE_MONITOR", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] OSINT monitor disabled by environment variable.")
        return None
    cmd = _conda_run_prefix() + [PYTHON, "-m", "ace_t_osint.monitor.main"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT)

def run_log_ingest():
    print("[DEBUG] Launching log ingester...")
    ingest_path = os.path.join(REPO_ROOT, "ace_t_osint", "ingest", "log_ingest.py")
    enable = os.environ.get("ENABLE_INGEST", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Log ingester disabled by environment variable.")
        return None
    cmd = _conda_run_prefix() + [PYTHON, "-m", "ace_t_osint.ingest.log_ingest"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT)

def run_alert_gui():
    print("[DEBUG] Launching alert GUI...")
    gui_path = os.path.join(REPO_ROOT, "ace_t_osint", "gui", "alert_gui.py")
    enable = os.environ.get("ENABLE_GUI", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Alert GUI disabled by environment variable.")
        return None
    cmd = _conda_run_prefix() + [PYTHON, "-m", "ace_t_osint.gui.alert_gui"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT)

def run_analytics():
    print("[DEBUG] Launching analytics...")
    analytics_path = os.path.join(REPO_ROOT, "ace_t_osint", "analytics", "analytics.py")
    enable = os.environ.get("ENABLE_ANALYTICS", "true").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Analytics disabled by environment variable.")
        return None
    cmd = _conda_run_prefix() + [PYTHON, "-m", "ace_t_osint.analytics.analytics"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT)

def run_web_crawlers(spider_name=None):
    """
    Launch the Scrapy web crawler. Controlled by env var ENABLE_WEB_CRAWLERS (default: True).
    Spider can be selected via env var SCRAPY_SPIDER (default: 'example' or passed arg).
    """
    # Web crawlers are disabled by default to avoid accidental spider runs ('example' errors)
    enable = os.environ.get("ENABLE_WEB_CRAWLERS", "false").lower() in ("1", "true", "yes")
    if not enable:
        print("[orchestrator] Web crawlers are disabled by environment variable.")
        return None, None
    crawlers_path = os.path.join(REPO_ROOT, "web_crawlers", "ace_t_scraper")
    output_dir = os.path.join(REPO_ROOT, "alerts_for_review")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%dT%H-%M-%S")
    # Allow dynamic spider selection
    spider = spider_name or os.environ.get("SCRAPY_SPIDER")
    if not spider:
        print("[orchestrator] SCRAPY_SPIDER not set; skipping web crawlers.")
        return None, None
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
        # Wait for backend to be ready before starting dependent components
        if wait_for_backend(timeout=20):
            procs.append(run_alert_gui())
        else:
            print("[orchestrator] Backend did not become ready in time; skipping GUI/start of dependent components.")
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
