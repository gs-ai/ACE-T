import subprocess
import sys
import os
import time
import threading

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