#!/usr/bin/env python3
"""
Simple HTTP server to serve the NADW Threat Graph viewer with streaming graph updates.
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
WEB_DIR = PROJECT_ROOT / 'gui'

def _resolve_static_path(url_path: str) -> Path:
    url_path = urlsplit(url_path).path
    if url_path.startswith('/'):
        url_path = url_path[1:]
    if url_path.startswith('graph_3d') or url_path.startswith('graph.json') or url_path.startswith('graph_3d_render'):
        return BASE_DIR / url_path
    if url_path.startswith('data/'):
        return BASE_DIR / url_path
    return WEB_DIR / url_path

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
        super().end_headers()

def start_streaming_build():
    """Start the streaming graph build process in the background."""
    try:
        # Start the streaming build process from the current directory
        # Use conda python explicitly
        conda_python = '/opt/anaconda3/envs/ace-t-env/bin/python'
        process = subprocess.Popen([
            conda_python, 'build_graph.py', '--streaming'
        ], cwd=str(BASE_DIR))  # Run from GRAPH_COPY regardless of launch path

        print("Started streaming graph build process...")
        return process
    except Exception as e:
        print(f"Failed to start streaming build: {e}")
        return None

def main():
    # Build full graph once before streaming updates
    try:
        conda_python = '/opt/anaconda3/envs/ace-t-env/bin/python'
        subprocess.run(
            [conda_python, 'build_graph.py'],
            cwd=str(BASE_DIR),  # Run from GRAPH_COPY regardless of launch path
            check=True
        )
        print("Initial full graph build complete.")
    except Exception as e:
        print(f"Initial graph build failed: {e}")

    # Start streaming graph build only if explicitly enabled
    build_process = None
    if os.getenv('ACE_T_ENABLE_STREAMING', '').strip().lower() in {'1', 'true', 'yes'}:
        build_process = start_streaming_build()

    # Create server rooted at the viewer directory
    handler = functools.partial(CustomHTTPRequestHandler, directory=str(BASE_DIR))
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print("🚀 NADW Threat Graph Viewer with Live Streaming")
        print(f"📊 Server running at http://localhost:{PORT}")
        print("🔄 Graph building in streaming mode - watch nodes appear in real-time!")
        print("Press Ctrl+C to stop the server")
        print()

        # Open browser automatically
        try:
            webbrowser.open(f"http://localhost:{PORT}/ace_t_spectrum_3d.html")
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
