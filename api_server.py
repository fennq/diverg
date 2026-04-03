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
from urllib.parse import urlparse

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


def _error(message: str, status: int = 400):
    return jsonify({"error": True, "message": message}), status


def _validate_url(raw) -> tuple[str | None, str | None]:
    """Return (clean_url, None) or (None, err_msg)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "Missing or invalid 'url' in request body"

    url = raw.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return None, "Malformed URL"

    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        return None, "URL has no hostname"

    if parsed.scheme not in ("http", "https"):
        return None, f"Unsupported scheme '{parsed.scheme}'"

    if "." not in host and host != "localhost":
        return None, f"Invalid hostname '{host}'"

    if len(host) > 253 or any(len(part) > 63 for part in host.split(".")):
        return None, "Hostname exceeds DNS length limits"

    return url, None


@app.after_request
def _cors(resp):
    """CORS headers for extension + local dev."""
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
        return _error("Content-Type must be application/json")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Request body must be a JSON object")

    url, err = _validate_url(data.get("url"))
    if err:
        return _error(err)

    goal = (data.get("goal") or "").strip() or None
    scope = (data.get("scope") or "full").strip().lower()
    if scope not in ("full", "quick", "crypto", "recon", "web", "api", "passive", "attack"):
        scope = "full"
    output_format = (data.get("format") or "json").strip().lower()
    try:
        result = run_web_scan(url, scope=scope, goal=goal)

        if output_format == "sarif":
            from sarif_output import findings_to_sarif
            sarif = findings_to_sarif(
                result["findings"],
                target_url=result["target_url"],
                scanned_at=result["scanned_at"],
            )
            return jsonify(sarif)

        return jsonify({
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scanned_at": result["scanned_at"],
            "summary": result.get("summary"),
            "skills_run": result.get("skills_run"),
            "site_classification": result.get("site_classification"),
            "domain_trust": result.get("domain_trust"),
            "evidence_summary": result.get("evidence_summary"),
        })
    except Exception as e:
        return _error(f"Scan failed: {e}", status=500)


@app.route("/api/scan/stream", methods=["OPTIONS"])
def api_scan_stream_options():
    return "", 204


@app.route("/api/scan/stream", methods=["POST"])
def api_scan_stream():
    """Stream scan progress as NDJSON. Body: {"url": "https://...", "goal": "optional"}."""
    if not request.is_json:
        return _error("Content-Type must be application/json")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Request body must be a JSON object")

    url, err = _validate_url(data.get("url"))
    if err:
        return _error(err)

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
            yield _json.dumps({"event": "error", "error": True, "message": str(e)}) + "\n"

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
        return _error("Content-Type must be application/json")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Request body must be a JSON object")

    def _poc_response(result: PoCResult):
        return jsonify({
            "success": result.success,
            "status_code": result.status_code,
            "body_preview": result.body_preview,
            "conclusion": result.conclusion,
            "error": result.error or None,
            "poc_type": result.poc_type or None,
        })

    if data.get("finding"):
        finding = data["finding"]
        if not isinstance(finding, dict):
            return _error("'finding' must be a JSON object")
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
        return _poc_response(result)

    poc_type = (data.get("type") or "").strip().lower()
    poc_url, poc_err = _validate_url(data.get("url"))
    if poc_err:
        return _error(poc_err)
    if poc_type not in ("idor", "unauthenticated"):
        return _error("'type' must be 'idor' or 'unauthenticated'")

    try:
        if poc_type == "idor":
            result = run_idor_poc(
                url=poc_url,
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
                url=poc_url,
                method=data.get("method") or "GET",
                headers=data.get("headers"),
                cookies=data.get("cookies"),
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "conclusion": ""}), 200

    return _poc_response(result)


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
