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
from pathlib import Path
from urllib.parse import urlsplit

PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
WEB_DIR = BASE_DIR
FALLBACK_WEB_DIR = PROJECT_ROOT / 'gui'


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
    # Build full graph once before streaming updates unless explicitly skipped
    skip_build = os.getenv('ACE_T_SKIP_BUILD', '').strip().lower() in {'1', 'true', 'yes'}
    if skip_build:
        print("Skipping graph build (ACE_T_SKIP_BUILD=1). Using existing artifacts.")
    else:
        try:
            py = _python_executable()
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
        render_path = BASE_DIR / 'graph_3d_render.json'
        if render_path.exists():
            import json
            payload = json.loads(render_path.read_text())
            nodes = len(payload.get('nodes', []))
            edges = len(payload.get('edges', []))
            print(f"Graph payload ready: {nodes} nodes, {edges} edges")
    except Exception:
        pass

    # Start streaming graph build only if explicitly enabled
    streaming_enabled = os.getenv('ACE_T_ENABLE_STREAMING', '').strip().lower() in {'1', 'true', 'yes'}
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
            webbrowser.open(f"http://localhost:{PORT}/ace_t_spectrum_3d.html{suffix}")
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
            httpd.shutdown()

if __name__ == "__main__":
    main()
