#!/usr/bin/env python3
"""
Simple HTTP server to serve the SPECTRUM ACE-T graph viewer with streaming graph updates.
"""
import http.server
import socketserver
import os
import webbrowser
import subprocess
import signal
import sys
import functools
import shutil
import json
import time
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
WEB_DIR = BASE_DIR
FALLBACK_WEB_DIR = PROJECT_ROOT / 'gui'
BROWSER_OPEN_MARKER = Path(
    os.environ.get("ACE_T_BROWSER_OPEN_MARKER", os.path.join(tempfile.gettempdir(), "ace_t_browser_open.json"))
)


def _python_executable() -> str:
    configured = os.getenv("PYTHON_BIN", "").strip()
    if configured:
        return configured
    return sys.executable

def _resolve_static_path(url_path: str) -> Path:
    url_path = urlsplit(url_path).path
    if url_path.startswith('/'):
        url_path = url_path[1:]
    if url_path.startswith('graph_3d') or url_path.startswith('graph.json') or url_path.startswith('graph_3d_render'):
        return BASE_DIR / url_path
    if url_path.startswith('data/'):
        return BASE_DIR / url_path
    candidate = WEB_DIR / url_path
    if candidate.exists():
        return candidate
    return FALLBACK_WEB_DIR / url_path


def _sync_viewer_html() -> None:
    """Keep the fallback/gui viewer identical to the graph viewer script."""
    source_html = BASE_DIR / 'ace_t_spectrum_3d.html'
    target_html = FALLBACK_WEB_DIR / 'ace_t_spectrum_3d.html'
    try:
        if not source_html.exists():
            return
        FALLBACK_WEB_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_html, target_html)
    except Exception as exc:
        print(f"Viewer sync warning: {exc}")


def _should_auto_open(url: str) -> bool:
    if str(os.getenv("ACE_T_AUTO_OPEN", "1")).strip().lower() not in {"1", "true", "yes"}:
        return False
    if str(os.getenv("ACE_T_AUTO_OPEN_ONCE", "1")).strip().lower() not in {"1", "true", "yes"}:
        return True
    cooldown_sec = int(os.getenv("ACE_T_AUTO_OPEN_COOLDOWN_SEC", "600"))
    try:
        if BROWSER_OPEN_MARKER.exists():
            payload = json.loads(BROWSER_OPEN_MARKER.read_text(encoding="utf-8"))
            ts = float(payload.get("ts", 0))
            if (time.time() - ts) < cooldown_sec:
                return False
    except Exception:
        pass
    return True


def _mark_auto_open(url: str) -> None:
    try:
        payload = {"url": url, "ts": time.time(), "pid": os.getpid()}
        BROWSER_OPEN_MARKER.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '':
            self.path = '/ace_t_spectrum_3d.html'
        super().do_GET()

    def translate_path(self, path: str) -> str:
        return str(_resolve_static_path(path))

    def end_headers(self):
        # Add CORS headers to allow cross-origin requests
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        super().end_headers()

def start_streaming_build():
    """Start the streaming graph build process in the background."""
    try:
        py = _python_executable()
        process = subprocess.Popen([
            py, 'build_graph.py', '--streaming'
        ], cwd=str(BASE_DIR))  # Run from the graph bundle regardless of launch path

        print("Started streaming graph build process...")
        return process
    except Exception as e:
        print(f"Failed to start streaming build: {e}")
        return None

def main():
    _sync_viewer_html()
    graph_path = BASE_DIR / 'graph_3d.json'
    render_path = BASE_DIR / 'graph_3d_render.json'
    streaming_enabled = os.getenv('ACE_T_ENABLE_STREAMING', '').strip().lower() in {'1', 'true', 'yes'}
    has_cached_graph = graph_path.exists() and render_path.exists()
    async_initial_build = os.getenv('ACE_T_ASYNC_INITIAL_BUILD', '1').strip().lower() in {'1', 'true', 'yes'}

    # Build full graph once before server start unless explicitly skipped.
    # In streaming mode, we can optionally fast-start from cached artifacts.
    skip_build = os.getenv('ACE_T_SKIP_BUILD', '').strip().lower() in {'1', 'true', 'yes'}
    if (not skip_build) and streaming_enabled and async_initial_build and has_cached_graph:
        skip_build = True
        print("Fast streaming start enabled: using cached graph artifacts while background stream refreshes data.")

    initial_build_process = None
    if skip_build:
        if has_cached_graph:
            print("Skipping graph build (ACE_T_SKIP_BUILD=1). Using existing artifacts.")
        else:
            print("ACE_T_SKIP_BUILD=1 set but no cached graph artifacts found; running full build now.")
            skip_build = False

    if not skip_build:
        try:
            py = _python_executable()
            if async_initial_build:
                initial_build_process = subprocess.Popen(
                    [py, 'build_graph.py'],
                    cwd=str(BASE_DIR),
                )
                print("Initial graph build started in background.")
            else:
                subprocess.run(
                    [py, 'build_graph.py'],
                    cwd=str(BASE_DIR),  # Run from the graph bundle regardless of launch path
                    check=True
                )
                print("Initial full graph build complete.")
        except Exception as e:
            print(f"Initial graph build failed: {e}")
            # Avoid serving stale data if the build failed
            sys.exit(1)

    # Print summary from latest render graph
    try:
        if render_path.exists():
            import json
            payload = json.loads(render_path.read_text())
            nodes = len(payload.get('nodes', []))
            edges = len(payload.get('edges', []))
            print(f"Graph payload ready: {nodes} nodes, {edges} edges")
    except Exception:
        pass

    # Start streaming graph build only if explicitly enabled
    build_process = None
    if streaming_enabled:
        build_process = start_streaming_build()

    # Create server rooted at the viewer directory
    handler = functools.partial(CustomHTTPRequestHandler, directory=str(BASE_DIR))
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True
    with ReusableTCPServer(("", PORT), handler) as httpd:
        print("SPECTRUM ACE-T Graph Viewer")
        print(f"📊 Server running at http://localhost:{PORT}")
        if streaming_enabled:
            print("🔄 Graph building in streaming mode - watch nodes appear in real-time!")
        else:
            print("🧊 Static build mode (no streaming updates)")
        print("Press Ctrl+C to stop the server")
        print()

        # Open browser automatically
        try:
            suffix = "?poll=1" if streaming_enabled else ""
            target_url = f"http://localhost:{PORT}/ace_t_spectrum_3d.html{suffix}"
            if _should_auto_open(target_url):
                webbrowser.open(target_url)
                _mark_auto_open(target_url)
            else:
                print("Browser auto-open skipped (recent instance already opened).")
        except:
            pass  # Browser might not be available

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped.")
            if build_process:
                print("Stopping streaming build process...")
                build_process.terminate()
                try:
                    build_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    build_process.kill()
            if initial_build_process and initial_build_process.poll() is None:
                print("Stopping initial build process...")
                initial_build_process.terminate()
                try:
                    initial_build_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    initial_build_process.kill()
            httpd.shutdown()

if __name__ == "__main__":
    main()
