#!/usr/bin/env python3
"""
Diverg Web Scan API — HTTP server for Chrome extension + dashboard console.

Start: python api_server.py [--port 5000]

Scan endpoints:
  POST /api/scan                 Run blocking full scan
  POST /api/scan/stream          Stream scan progress as NDJSON
  POST /api/poc/simulate         Run PoC for a finding

Dashboard endpoints:
  GET  /api/history              List all past scans (paginated)
  GET  /api/history/<id>         Get single scan report
  DELETE /api/history/<id>       Delete a scan
  PATCH /api/history/<id>        Update label/tags on a scan
  GET  /api/stats                Aggregate dashboard statistics
  GET  /api/health               Health check

Dashboard static files:
  GET  /dashboard/               Serve dashboard/index.html
  GET  /dashboard/<path>         Serve dashboard static assets
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, request, jsonify, send_from_directory
except ImportError:
    print("Install Flask: pip install flask")
    sys.exit(1)

from flask import Response, stream_with_context
from orchestrator import run_web_scan, run_web_scan_streaming
from poc_runner import run_poc_for_finding, run_idor_poc, run_unauth_poc

# ── Database ────────────────────────────────────────────────────────────────

DB_PATH = ROOT / "data" / "dashboard.db"
DB_PATH.parent.mkdir(exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target_url   TEXT NOT NULL,
    scope        TEXT DEFAULT 'full',
    scanned_at   TEXT,
    status       TEXT DEFAULT 'completed',
    risk_score   INTEGER,
    risk_verdict TEXT,
    total        INTEGER DEFAULT 0,
    critical     INTEGER DEFAULT 0,
    high         INTEGER DEFAULT 0,
    medium       INTEGER DEFAULT 0,
    low          INTEGER DEFAULT 0,
    info         INTEGER DEFAULT 0,
    label        TEXT DEFAULT '',
    report_json  TEXT,
    created_at   TEXT
);
"""


def _db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db() as conn:
        conn.executescript(SCHEMA)


def _count_severity(findings: list, level: str) -> int:
    return sum(1 for f in findings if (f.get("severity") or "").lower() == level.lower())


def save_scan(scan_id: str, result: dict, scope: str):
    findings = result.get("findings") or []
    sev = {s: _count_severity(findings, s) for s in ("Critical", "High", "Medium", "Low", "Info")}
    with _db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (id, target_url, scope, scanned_at, status, risk_score, risk_verdict,
                total, critical, high, medium, low, info, report_json, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id,
                result.get("target_url", ""),
                scope,
                result.get("scanned_at", datetime.now(timezone.utc).isoformat()),
                "completed",
                result.get("risk_score"),
                result.get("risk_verdict"),
                len(findings),
                sev["Critical"], sev["High"], sev["Medium"], sev["Low"], sev["Info"],
                json.dumps(result),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


# ── Flask app ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

VALID_SCOPES = ("full", "quick", "crypto", "recon", "web", "api", "passive", "attack")

init_db()


@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp


# ── Dashboard static files ───────────────────────────────────────────────────

DASHBOARD_DIR = ROOT / "dashboard"


@app.route("/dashboard/")
@app.route("/dashboard")
def dashboard_root():
    return send_from_directory(str(DASHBOARD_DIR), "index.html")


@app.route("/dashboard/<path:filename>")
def dashboard_static(filename):
    return send_from_directory(str(DASHBOARD_DIR), filename)


# ── URL validation ───────────────────────────────────────────────────────────

def _validate_url(url: str) -> tuple[str, str | None]:
    """Validate and normalize a URL. Returns (normalized_url, error_string_or_None)."""
    url = (url or "").strip()
    if not url:
        return "", "Missing URL"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "", f"Unsupported scheme '{parsed.scheme}' — only http and https are allowed"
    if not parsed.hostname:
        return "", "Invalid URL — no hostname found"
    return url, None


def _error_response(message: str, status: int = 400):
    """Return a standardized error JSON response for scan/history endpoints."""
    return jsonify({"error": True, "message": message}), status


# ── Scan endpoints ───────────────────────────────────────────────────────────

def _parse_scan_body():
    if not request.is_json:
        return None, None, None, _error_response("Content-Type must be application/json")
    data = request.get_json() or {}
    raw_url = (data.get("url") or "").strip()
    if not raw_url:
        return None, None, None, _error_response("Missing 'url' in body")
    url, err = _validate_url(raw_url)
    if err:
        return None, None, None, _error_response(err)
    goal = (data.get("goal") or "").strip() or None
    scope = (data.get("scope") or "full").strip().lower()
    if scope not in VALID_SCOPES:
        scope = "full"
    return url, goal, scope, None


@app.route("/api/scan", methods=["OPTIONS"])
def api_scan_options():
    return "", 204


@app.route("/api/scan", methods=["POST"])
def api_scan():
    url, goal, scope, err = _parse_scan_body()
    if err:
        return err
    try:
        result = run_web_scan(url, scope=scope, goal=goal)
        scan_id = str(uuid.uuid4())
        save_scan(scan_id, result, scope)
        payload = {
            "id": scan_id,
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scanned_at": result["scanned_at"],
            "summary": result.get("summary"),
            "skills_run": result.get("skills_run"),
            "site_classification": result.get("site_classification"),
            "evidence_summary": result.get("evidence_summary"),
            "attack_paths": result.get("attack_paths"),
            "gap_analysis": result.get("gap_analysis"),
            "suggested_next_tests": result.get("suggested_next_tests"),
            "attack_path_role_counts": result.get("attack_path_role_counts"),
            "attack_paths_note": result.get("attack_paths_note"),
            "risk_score": result.get("risk_score"),
            "risk_verdict": result.get("risk_verdict"),
            "risk_summary": result.get("risk_summary"),
            "safe_to_run": result.get("safe_to_run"),
            "remediation_plan": result.get("remediation_plan"),
        }
        return jsonify(payload)
    except Exception as e:
        return _error_response(str(e), 500)


@app.route("/api/scan/stream", methods=["OPTIONS"])
def api_scan_stream_options():
    return "", 204


@app.route("/api/scan/stream", methods=["POST"])
def api_scan_stream():
    url, goal, scope, err = _parse_scan_body()
    if err:
        return err

    scan_id = str(uuid.uuid4())

    def generate():
        accumulated = None
        try:
            # Emit scan ID immediately so client can track it
            yield json.dumps({"event": "scan_start", "id": scan_id, "url": url, "scope": scope}) + "\n"
            for event in run_web_scan_streaming(url, scope=scope, goal=goal):
                if event.get("event") == "done":
                    report = event.get("report") or {}
                    report["id"] = scan_id
                    accumulated = report
                    event["id"] = scan_id
                yield json.dumps(event) + "\n"
        except Exception as e:
            yield json.dumps({"event": "error", "error": str(e)}) + "\n"
        finally:
            if accumulated:
                try:
                    save_scan(scan_id, accumulated, scope)
                except Exception:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── PoC endpoint ─────────────────────────────────────────────────────────────

@app.route("/api/poc/simulate", methods=["OPTIONS"])
def poc_simulate_options():
    return "", 204


@app.route("/api/poc/simulate", methods=["POST"])
def poc_simulate():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    if data.get("finding"):
        finding = data["finding"]
        if not isinstance(finding, dict):
            return jsonify({"error": "finding must be an object"}), 400
        try:
            result = run_poc_for_finding(
                finding,
                param_to_change=data.get("param_to_change"),
                new_value=str(data.get("new_value") or "1").strip(),
                cookies=data.get("cookies"),
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "conclusion": ""}), 200
    else:
        poc_type = (data.get("type") or "").strip().lower()
        raw_url = (data.get("url") or "").strip()
        if not raw_url:
            return jsonify({"error": "Missing url (or provide finding)"}), 400
        url, url_err = _validate_url(raw_url)
        if url_err:
            return jsonify({"error": url_err}), 400
        if poc_type not in ("idor", "unauthenticated"):
            return jsonify({"error": "type must be 'idor' or 'unauthenticated'"}), 400
        try:
            if poc_type == "idor":
                result = run_idor_poc(url=url, method=data.get("method") or "GET",
                                      params=data.get("params"), data=data.get("data"),
                                      headers=data.get("headers"), param_to_change=data.get("param_to_change"),
                                      new_value=str(data.get("new_value") or "1"), cookies=data.get("cookies"))
            else:
                result = run_unauth_poc(url=url, method=data.get("method") or "GET",
                                        headers=data.get("headers"), cookies=data.get("cookies"))
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


# ── History endpoints ─────────────────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
def history_list():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        return _error_response("'limit' must be a number")
    try:
        offset = int(request.args.get("offset", 0))
    except (ValueError, TypeError):
        return _error_response("'offset' must be a number")
    scope_filter = request.args.get("scope", "").strip()
    verdict_filter = request.args.get("verdict", "").strip()

    where_clauses = []
    params: list = []
    if scope_filter:
        where_clauses.append("scope = ?")
        params.append(scope_filter)
    if verdict_filter:
        where_clauses.append("risk_verdict = ?")
        params.append(verdict_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        with _db() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM scans {where_sql}", params).fetchone()[0]
            rows = conn.execute(
                f"""SELECT id, target_url, scope, scanned_at, status, risk_score,
                           risk_verdict, total, critical, high, medium, low, info, label, created_at
                    FROM scans {where_sql}
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?""",
                params + [limit, offset],
            ).fetchall()
    except sqlite3.Error as e:
        return _error_response(f"Database error: {e}", 500)

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": [dict(r) for r in rows],
    })


@app.route("/api/history/<scan_id>", methods=["GET"])
def history_get(scan_id):
    try:
        with _db() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    except sqlite3.Error as e:
        return _error_response(f"Database error: {e}", 500)
    if not row:
        return _error_response("Scan not found", 404)
    data = dict(row)
    if data.get("report_json"):
        data["report"] = json.loads(data.pop("report_json"))
    else:
        data.pop("report_json", None)
    return jsonify(data)


@app.route("/api/history/<scan_id>", methods=["DELETE", "OPTIONS"])
def history_delete(scan_id):
    if request.method == "OPTIONS":
        return "", 204
    try:
        with _db() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    except sqlite3.Error as e:
        return _error_response(f"Database error: {e}", 500)
    return jsonify({"deleted": scan_id})


@app.route("/api/history/<scan_id>", methods=["PATCH"])
def history_patch(scan_id):
    data = (request.get_json() or {}) if request.is_json else {}
    label = data.get("label", "")
    try:
        with _db() as conn:
            conn.execute("UPDATE scans SET label = ? WHERE id = ?", (label, scan_id))
    except sqlite3.Error as e:
        return _error_response(f"Database error: {e}", 500)
    return jsonify({"id": scan_id, "label": label})


# ── Stats endpoint ────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        with _db() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) AS total_scans,
                    COALESCE(SUM(critical), 0) AS total_critical,
                    COALESCE(SUM(high), 0) AS total_high,
                    COALESCE(SUM(medium), 0) AS total_medium,
                    COALESCE(SUM(low), 0) AS total_low,
                    COALESCE(AVG(risk_score), 0) AS avg_risk_score,
                    COUNT(DISTINCT target_url) AS unique_targets
                FROM scans
            """).fetchone()

            recent = conn.execute("""
                SELECT id, target_url, risk_score, risk_verdict, total, critical, scanned_at, label
                FROM scans ORDER BY created_at DESC LIMIT 5
            """).fetchall()

            verdicts = conn.execute("""
                SELECT risk_verdict, COUNT(*) as cnt FROM scans
                WHERE risk_verdict IS NOT NULL GROUP BY risk_verdict
            """).fetchall()
    except sqlite3.Error as e:
        return _error_response(f"Database error: {e}", 500)

    return jsonify({
        "total_scans": row["total_scans"],
        "total_critical": row["total_critical"],
        "total_high": row["total_high"],
        "total_medium": row["total_medium"],
        "total_low": row["total_low"],
        "avg_risk_score": round(row["avg_risk_score"] or 0, 1),
        "unique_targets": row["unique_targets"],
        "recent_scans": [dict(r) for r in recent],
        "verdict_breakdown": {r["risk_verdict"]: r["cnt"] for r in verdicts},
    })


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "diverg-console", "version": "2.0"})


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Diverg Console API")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    print(f"  Diverg Console  →  http://{args.host}:{args.port}/dashboard/")
    print(f"  API             →  http://{args.host}:{args.port}/api/health")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
