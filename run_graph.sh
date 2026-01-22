#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUI_PID=""
SCHED_PID=""
BROWSER_PID=""
PYTHON_BIN="/opt/anaconda3/envs/ace-t-env/bin/python"
# Ensure other scripts and the GUI know which conda env to expect
export ACE_T_EXPECT_ENV="${ACE_T_EXPECT_ENV:-ace-t-env}"
EXPECTED_ENV="${ACE_T_EXPECT_ENV}"
CURRENT_ENV="${CONDA_DEFAULT_ENV:-}"
if [[ -z "${CURRENT_ENV}" || "${CURRENT_ENV}" != "${EXPECTED_ENV}" ]]; then
  echo "[!] This launcher must run inside conda env '${EXPECTED_ENV}'."
  echo "    Run: conda activate ${EXPECTED_ENV} && ./run_graph.sh"
  exit 2
fi

GUI_ROOT_MARKER="${ROOT}/data/.gui_root_id"
GUI_ENTRY="${ACE_T_GUI_ENTRY:-three_view_3d_v2.html}"
GUI_ROOT_TOKEN="$("${PYTHON_BIN}" - <<'PY'
import time
print(f"ace-t-{int(time.time())}")
PY
)"
mkdir -p "$(dirname "${GUI_ROOT_MARKER}")"
printf "%s" "${GUI_ROOT_TOKEN}" > "${GUI_ROOT_MARKER}"

# Ensure project modules are importable (root for schema.py, src for modules).
# legacyV2 is opt-in via USE_LEGACY=1 for back-compat when needed.
if [ "${USE_LEGACY:-0}" = "1" ]; then
  export PYTHONPATH="${ROOT}:${ROOT}/src:${ROOT}/../legacyV2:${PYTHONPATH:-}"
else
  export PYTHONPATH="${ROOT}:${ROOT}/src:${PYTHONPATH:-}"
fi

# Always start with a clean graph (retention will refill up to 30 days)
rm -f "${ROOT}/data/graph_data.json" "${ROOT}/data/graph_positions.json" "${ROOT}/data/graph_3d.json" "${ROOT}/data/reddit_seen_posts.json"
mkdir -p "${ROOT}/data"
printf '%s' '{"nodes":[],"edges":[],"meta":{"built_at":0,"nodes":0,"edges":0}}' > "${ROOT}/data/graph_3d.json"

echo "[*] Starting ACE-T graph pipeline"

# Pipeline orchestration mode
export ACE_T_PIPELINE_MODE=1
export ACE_T_PIPELINE_LIVE_COLLECT="${ACE_T_PIPELINE_LIVE_COLLECT:-1}"
PIPELINE_PATH="${ROOT}/pipeline/acet_osint_spectrum.pipeline.json"
if [ ! -f "${PIPELINE_PATH}" ]; then
  PIPELINE_PATH="${ROOT}/pipelines/acet_osint_spectrum.pipeline.json"
fi
SEED_PATH="${ROOT}/data/pipeline_seed.json"
PIPELINE_INTERVAL="${ACE_T_PIPELINE_INTERVAL:-180}"

echo "[*] Building pipeline seed at ${SEED_PATH}"
"${PYTHON_BIN}" - <<PY
import json
import os
from pathlib import Path

seed_path = Path("${SEED_PATH}")
try:
    from runners.subreddit_targets import DEFAULT_SUBREDDITS
except Exception:
    DEFAULT_SUBREDDITS = []

targets_env = os.getenv("ACE_T_PIPELINE_TARGETS_JSON", "").strip()
targets = []
if targets_env:
    try:
        targets = json.loads(targets_env)
    except Exception:
        targets = []
if not targets:
    targets = [{"type": "handle", "value": f"{s}"} for s in DEFAULT_SUBREDDITS]

case_id = os.getenv("ACE_T_CASE_ID", "ace-t")
options = {
    "retention_days": int(os.getenv("ACE_T_RETENTION_DAYS", "30")),
}
seed = {"case_id": case_id, "targets": targets, "options": options}
seed_path.parent.mkdir(parents=True, exist_ok=True)
seed_path.write_text(json.dumps(seed, indent=2))
PY

run_pipeline_once() {
  "${PYTHON_BIN}" "${ROOT}/pipeline/runner.py" \
    --seed "${SEED_PATH}" \
    --pipeline "${PIPELINE_PATH}" \
    --output-root "${ROOT}"
}

cleanup() {
  echo ""
  echo "[*] Shutting down…"
  [[ -n "${GUI_PID}" ]] && kill "${GUI_PID}" 2>/dev/null || true
  [[ -n "${SCHED_PID}" ]] && kill "${SCHED_PID}" 2>/dev/null || true
  [[ -n "${BROWSER_PID}" ]] && kill "${BROWSER_PID}" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[*] Clean shutdown complete"
  exit 0
}

trap cleanup INT TERM

GUI_RUNNING=0
GUI_PORT="${ACE_T_GUI_PORT:-8050}"
GUI_URL="http://127.0.0.1:${GUI_PORT}"

is_port_in_use() {
  local port="$1"
  "${PYTHON_BIN}" -c 'import socket, sys
port = int(sys.argv[1])
def probe(family, addr):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((addr, port))
        s.close()
        return True
    except Exception:
        return False
if probe(socket.AF_INET, "127.0.0.1") or probe(socket.AF_INET6, "::1"):
    sys.exit(0)
sys.exit(1)
' "${port}" >/dev/null 2>&1
}

is_spectrum_gui() {
  local port="$1"
  local token="$2"
  "${PYTHON_BIN}" -c 'import sys, urllib.request
port = int(sys.argv[1])
token = sys.argv[2]
paths = [
    f"http://127.0.0.1:{port}/gui/{sys.argv[3]}",
    f"http://[::1]:{port}/gui/{sys.argv[3]}",
]
marker_paths = [
    f"http://127.0.0.1:{port}/data/.gui_root_id",
    f"http://[::1]:{port}/data/.gui_root_id",
]
marker_ok = False
for url in marker_paths:
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:
            if resp.status != 200:
                continue
            body = resp.read(200000).decode("utf-8", "ignore")
            if body.strip() == token:
                marker_ok = True
                break
    except Exception:
        pass
if not marker_ok:
    sys.exit(1)
for url in paths:
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:
            if resp.status != 200:
                continue
            body = resp.read(200000).decode("utf-8", "ignore")
            if "ACE-T" in body and "spectrum" in body.lower():
                sys.exit(0)
    except Exception:
        pass
sys.exit(1)
' "${port}" "${token}" "${GUI_ENTRY}" >/dev/null 2>&1
}

pick_open_port() {
  local start="$1"
  local end="$2"
  local p
  for p in $(seq "${start}" "${end}"); do
    if ! is_port_in_use "${p}"; then
      echo "${p}"
      return 0
    fi
  done
  return 1
}

if is_port_in_use "${GUI_PORT}"; then
  if is_spectrum_gui "${GUI_PORT}" "${GUI_ROOT_TOKEN}"; then
    GUI_RUNNING=1
    echo "[*] GUI server already running on port ${GUI_PORT}; reusing"
  else
    NEXT_PORT="$(pick_open_port "$((GUI_PORT + 1))" "$((GUI_PORT + 20))")" || true
    if [ -z "${NEXT_PORT:-}" ]; then
      echo "[!] No available port found for GUI (tried ${GUI_PORT}-$((GUI_PORT + 20)))."
      exit 2
    fi
    GUI_PORT="${NEXT_PORT}"
    GUI_URL="http://127.0.0.1:${GUI_PORT}"
    echo "[*] Port ${ACE_T_GUI_PORT:-8050} in use; starting GUI on ${GUI_PORT}"
  fi
fi

if [ "${GUI_RUNNING}" -eq 0 ]; then
  echo "[*] Launching 3D GUI"
  cd "${ROOT}" && "${PYTHON_BIN}" -m http.server "${GUI_PORT}" &
  GUI_PID=$!
fi

sleep 2

open_url() {
  local url="$1"
  if command -v open >/dev/null 2>&1; then
    open "$url"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url"
  else
    "${PYTHON_BIN}" - <<PY
import webbrowser
webbrowser.open("${url}", new=2)
PY
  fi
}

if [ "${OPEN_BROWSER:-1}" = "1" ]; then
  echo "[*] Waiting for server to be ready..."
  READY=0
  for i in {1..60}; do
    if is_port_in_use "${GUI_PORT}"; then
      READY=1
      break
    fi
    sleep 0.5
  done
  if [ "${READY}" -eq 1 ]; then
    open_url "${GUI_URL}/gui/${GUI_ENTRY}?v=$(date +%s)" || true
    echo "[*] Browser opened successfully"
    echo "[*] Open URL: ${GUI_URL}/gui/${GUI_ENTRY}"
  else
    echo "[!] Server failed to start within 30 seconds"
  fi
fi

echo "[*] Running pipeline"
run_pipeline_once

pipeline_loop() {
  while true; do
    sleep "${PIPELINE_INTERVAL}"
    run_pipeline_once
    "${PYTHON_BIN}" "${ROOT}/ACE-T-SPECTRUM.py"
  done
}
pipeline_loop &
SCHED_PID=$!

echo "[*] Waiting for graph data to materialize"
for i in {1..40}; do
  if [ -s "${ROOT}/data/graph_data.json" ]; then
    if "${PYTHON_BIN}" - <<'PY' 2>/dev/null; then break; fi
import json, sys
from pathlib import Path
p = Path("${ROOT}/data/graph_data.json")
try:
    j = json.loads(p.read_text())
    if any("source" in (e.get("data") or {}) and "target" in (e.get("data") or {}) for e in j):
      sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY
  fi
  sleep 2
done

echo "[*] Building 3D spectrum export"
"${PYTHON_BIN}" "${ROOT}/ACE-T-SPECTRUM.py"

echo "[*] GUI live at ${GUI_URL}"
echo "[*] Pipeline loop running (interval ${PIPELINE_INTERVAL}s)"
echo "[*] Press Ctrl-C to stop everything cleanly"

wait
