#!/usr/bin/env python3
"""
Live Threat API Server
Provides REST endpoints for adding threats to the live monitoring system.
"""

from flask import Flask, request, jsonify
from pathlib import Path
import json
from datetime import datetime
import os
import subprocess
import threading
import sys

app = Flask(__name__)

def process_new_threat():
    """Automatically process new threats: score and rebuild graph"""
    try:
        print("🔄 Processing new threat: scoring...")
        py_bin = os.environ.get("PYTHON_BIN", "").strip() or sys.executable
        # Run scoring
        result = subprocess.run(
            [py_bin, 'score_live_threats.py'],
            capture_output=True, text=True, cwd=os.getcwd()
        )
        if result.returncode == 0:
            print("✅ Scoring completed")
        else:
            print(f"❌ Scoring failed: {result.stderr}")

        if os.environ.get('ACE_T_STREAMING_GRAPH', '1') != '1':
            print("🔄 Rebuilding graph...")
            # Run graph building
            result = subprocess.run(
                [py_bin, 'build_graph.py'],
                capture_output=True, text=True, cwd=os.getcwd()
            )
            if result.returncode == 0:
                print("✅ Graph rebuilt")
            else:
                print(f"❌ Graph build failed: {result.stderr}")
        else:
            print("🔄 Streaming graph enabled; skipping batch rebuild.")

    except Exception as e:
        print(f"❌ Processing error: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "spectrum-ace-t-live-threat-api"})

@app.route('/threats', methods=['POST'])
def add_threat():
    """
    Add a new threat to the live monitoring system.
    Expects JSON with threat features.
    """
    try:
        threat_data = request.get_json()

        if not threat_data:
            return jsonify({"error": "No JSON data provided"}), 400

        # Validate required fields
        required_fields = ['src_ip', 'dst_ip', 'protocol']
        missing = [f for f in required_fields if f not in threat_data]
        if missing:
            return jsonify({
                "error": f"Missing required fields: {missing}",
                "required": required_fields
            }), 400

        # Add timestamp
        threat_data['received_at'] = datetime.now().isoformat()

        # Save to live threats file
        live_feed = Path("live_threats.jsonl")
        live_feed.parent.mkdir(parents=True, exist_ok=True)

        with open(live_feed, 'a') as f:
            f.write(json.dumps(threat_data) + '\n')

        # Trigger automatic processing in background
        threading.Thread(target=process_new_threat).start()

        return jsonify({
            "status": "success",
            "message": "Threat added to live monitoring queue",
            "threat_id": f"api_{int(datetime.now().timestamp())}"
        }), 201

    except Exception:
        app.logger.error("Unhandled exception while adding threat", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/threats', methods=['GET'])
def get_threats():
    """Get recent threats (last 100)"""
    try:
        live_feed = Path("live_threats.jsonl")
        if not live_feed.exists():
            return jsonify({"threats": []})

        threats = []
        with open(live_feed, 'r') as f:
            for line in f:
                if line.strip():
                    threats.append(json.loads(line.strip()))

        # Return last 100 threats
        return jsonify({"threats": threats[-100:]})

    except Exception:
        app.logger.error("Unhandled exception while retrieving threats", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 SPECTRUM ACE-T Live Threat API Server starting on port {port}")
    print("Endpoints:")
    print("  GET  /health - Health check")
    print("  POST /threats - Add new threat (JSON)")
    print("  GET  /threats - Get recent threats")
    app.run(host='0.0.0.0', port=port, debug=False)
