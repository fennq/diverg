#!/usr/bin/env python3
"""
Diverg Web Scan API — HTTP server for the Chrome extension (full web scan, no blockchain).

Start: python api_server.py [--port 5000]
Endpoint: POST /api/scan with JSON {"url": "https://example.com"}
Returns: JSON with target_url, findings, scanned_at, summary (same shape as extension expects).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Run from project root so orchestrator and skills resolve
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Install Flask: pip install flask")
    sys.exit(1)

from orchestrator import run_web_scan

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run full web scan (no blockchain). Body: {"url": "https://..."}."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' in body"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        result = run_web_scan(url, scope="full")
        # Extension expects target_url, findings, scanned_at; optional summary
        return jsonify({
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scanned_at": result["scanned_at"],
            "summary": result.get("summary"),
            "skills_run": result.get("skills_run"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "diverg-web-scan"})


def main():
    parser = argparse.ArgumentParser(description="Diverg Web Scan API (for Chrome extension)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    args = parser.parse_args()
    print(f"Diverg Web Scan API — http://{args.host}:{args.port}/api/scan")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
