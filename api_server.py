#!/usr/bin/env python3
"""
Diverg Web Scan API — HTTP server for the Chrome extension (web scan, PoC simulate).

Start: python api_server.py [--port 5000]

Endpoints:
  POST /api/scan
    Body: {"url": "https://example.com", "goal": "optional", "scope": "optional"}
    scope: "full" | "quick" | "crypto" (default "full"). goal: natural-language goal for option scan.
    Returns: JSON with target_url, findings, scanned_at, summary, skills_run, site_classification, evidence_summary.

  POST /api/scan/stream
    Same body as /api/scan. Returns NDJSON stream: one JSON object per line.
    Events: {"event": "skill_start", "skill": "headers_ssl"}, {"event": "skill_done", "skill": "headers_ssl", "findings_count": 5}, {"event": "done", "report": {...}}
    Use for live progress in the extension or other clients.

  POST /api/poc/simulate  (Live PoC / Simulate)
    Body: {"finding": {...}} or {"type": "idor"|"unauthenticated", "url": "...", "method": "GET", "param_to_change": "user_id", "new_value": "2", ...}
    Runs a minimal proof-of-concept (e.g. IDOR: replay with different ID; unauthenticated: request without auth). Returns {success, status_code, body_preview, conclusion, error}.
    Extension uses this when user clicks "Simulate" on a finding.
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

from flask import Response, stream_with_context
from orchestrator import run_web_scan, run_web_scan_streaming
from poc_runner import run_poc_for_finding, run_idor_poc, run_unauth_poc, PoCResult

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.after_request
def _cors(resp):
    """Allow Chrome extension and other clients to call the API (e.g. from localhost)."""
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/api/scan", methods=["OPTIONS"])
def api_scan_options():
    return "", 204


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run full web scan (no blockchain). Body: {"url": "https://...", "goal": "optional natural-language goal"}."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' in body"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    goal = (data.get("goal") or "").strip() or None
    scope = (data.get("scope") or "full").strip().lower()
    if scope not in ("full", "quick", "crypto", "recon", "web", "api", "passive", "attack"):
        scope = "full"
    try:
        result = run_web_scan(url, scope=scope, goal=goal)
        return jsonify({
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scanned_at": result["scanned_at"],
            "summary": result.get("summary"),
            "skills_run": result.get("skills_run"),
            "site_classification": result.get("site_classification"),
            "evidence_summary": result.get("evidence_summary"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/stream", methods=["OPTIONS"])
def api_scan_stream_options():
    return "", 204


@app.route("/api/scan/stream", methods=["POST"])
def api_scan_stream():
    """Stream scan progress as NDJSON. Body: {"url": "https://...", "goal": "optional"}."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' in body"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    goal = (data.get("goal") or "").strip() or None
    scope = (data.get("scope") or "full").strip().lower()
    if scope not in ("full", "quick", "crypto", "recon", "web", "api", "passive", "attack"):
        scope = "full"

    def generate():
        import json as _json
        try:
            for event in run_web_scan_streaming(url, scope=scope, goal=goal):
                yield _json.dumps(event) + "\n"
        except Exception as e:
            yield _json.dumps({"event": "error", "error": str(e)}) + "\n"

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/poc/simulate", methods=["OPTIONS"])
def poc_simulate_options():
    return "", 204


@app.route("/api/poc/simulate", methods=["POST"])
def poc_simulate():
    """
    Live PoC / Simulate: run a minimal proof-of-concept for a finding.
    Body either:
      - {"finding": {url, title, category, evidence?, poc_type?}}  → we infer type and run
      - {"type": "idor", "url": "...", "method": "GET", "param_to_change": "user_id", "new_value": "2"}
      - {"type": "unauthenticated", "url": "...", "method": "GET"}
    Returns: {success, status_code?, body_preview?, conclusion, error?, poc_type?}
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}

    if data.get("finding"):
        finding = data["finding"]
        if not isinstance(finding, dict):
            return jsonify({"error": "finding must be an object"}), 400
        param_to_change = data.get("param_to_change")
        new_value = str(data.get("new_value") or "1").strip()
        cookies = data.get("cookies")
        try:
            result = run_poc_for_finding(
                finding,
                param_to_change=param_to_change,
                new_value=new_value,
                cookies=cookies,
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "conclusion": ""}), 200
        return jsonify({
            "success": result.success,
            "status_code": result.status_code,
            "body_preview": result.body_preview,
            "conclusion": result.conclusion,
            "error": result.error or None,
            "poc_type": result.poc_type or None,
        })
    # Explicit type + url
    poc_type = (data.get("type") or "").strip().lower()
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing url (or provide finding)"}), 400
    if poc_type not in ("idor", "unauthenticated"):
        return jsonify({"error": "type must be 'idor' or 'unauthenticated'"}), 400

    if poc_type == "idor":
        result = run_idor_poc(
            url=url,
            method=data.get("method") or "GET",
            params=data.get("params"),
            data=data.get("data"),
            headers=data.get("headers"),
            param_to_change=data.get("param_to_change"),
            new_value=str(data.get("new_value") or "1"),
            cookies=data.get("cookies"),
        )
    else:
        result = run_unauth_poc(
            url=url,
            method=data.get("method") or "GET",
            headers=data.get("headers"),
            cookies=data.get("cookies"),
        )

    return jsonify({
        "success": result.success,
        "status_code": result.status_code,
        "body_preview": result.body_preview,
        "conclusion": result.conclusion,
        "error": result.error or None,
        "poc_type": result.poc_type or None,
    })


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
