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

# Ensure project modules are importable (root for schema.py, src for modules).
# legacyV2 is opt-in via USE_LEGACY=1 for back-compat when needed.
if [ "${USE_LEGACY:-0}" = "1" ]; then
  export PYTHONPATH="${ROOT}:${ROOT}/src:${ROOT}/../legacyV2:${PYTHONPATH:-}"
else
  export PYTHONPATH="${ROOT}:${ROOT}/src:${PYTHONPATH:-}"
fi

# Always start with a clean graph (retention will refill up to 30 days)
rm -f "${ROOT}/data/graph_data.json" "${ROOT}/data/graph_positions.json" "${ROOT}/data/graph_3d.json" "${ROOT}/data/reddit_seen_posts.json"

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

echo "[*] Running pipeline"
run_pipeline_once

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

echo "[*] Launching 3D GUI"
cd "${ROOT}/gui" && "${PYTHON_BIN}" -m http.server 8050 &
GUI_PID=$!

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
  # Open 3D graph view
  open_url "http://127.0.0.1:8050/three_view_3d.html"
  BROWSER_PID=$!
fi

pipeline_loop() {
  while true; do
    sleep "${PIPELINE_INTERVAL}"
    run_pipeline_once
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

echo "[*] Building 3D export"
"${PYTHON_BIN}" "${ROOT}/src/three/export_3d.py"

echo "[*] GUI live at http://127.0.0.1:8050"
echo "[*] Pipeline loop running (interval ${PIPELINE_INTERVAL}s)"
echo "[*] Press Ctrl-C to stop everything cleanly"

wait
