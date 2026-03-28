#!/usr/bin/env python3
"""
Diverg Web Scan API — HTTP server for Chrome extension + dashboard console.

Start: python api_server.py [--port 5000]

Auth endpoints:
  POST /api/auth/register          Create account (email+password)
  POST /api/auth/login             Login, returns JWT
  POST /api/auth/google            Google OAuth login
  GET  /api/auth/me                Get current user

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
import re
import secrets
import sqlite3
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, request, jsonify, send_from_directory
except ImportError:
    print("Install Flask: pip install flask")
    sys.exit(1)

from flask import Response, stream_with_context

try:
    import bcrypt
except ImportError:
    print("Install bcrypt: pip install bcrypt")
    sys.exit(1)

try:
    import jwt
except ImportError:
    print("Install PyJWT: pip install pyjwt")
    sys.exit(1)

try:
    from orchestrator import run_web_scan, run_web_scan_streaming
    from poc_runner import run_poc_for_finding, run_idor_poc, run_unauth_poc
    SCANNER_AVAILABLE = True
except Exception as e:
    print(f"Warning: Scanner modules not fully available: {e}")
    SCANNER_AVAILABLE = False
    run_web_scan = None
    run_web_scan_streaming = None
    run_poc_for_finding = None
    run_idor_poc = None
    run_unauth_poc = None

# ── Config ────────────────────────────────────────────────────────────────

JWT_SECRET = os.environ.get("DIVERG_JWT_SECRET", secrets.token_hex(32))
JWT_EXPIRY_HOURS = 72
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
ALLOWED_ORIGINS = [
    o.strip() for o in
    os.environ.get(
        "DIVERG_ALLOWED_ORIGINS",
        "https://dash.divergsec.com,https://divergsec.com,http://127.0.0.1:5000,http://localhost:5000"
    ).split(",") if o.strip()
]
MAX_REQUEST_SIZE = 2 * 1024 * 1024  # 2 MB
IS_PRODUCTION = os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("DIVERG_PRODUCTION")

# ── Rate limiter ──────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int, lockout_seconds: int):
        self._max = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._locked: dict[str, float] = {}
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds). If not allowed, retry_after > 0."""
        now = time.time()
        with self._lock:
            if key in self._locked:
                unlock_at = self._locked[key]
                if now < unlock_at:
                    return False, int(unlock_at - now) + 1
                del self._locked[key]
                self._attempts[key] = []

            self._attempts[key] = [t for t in self._attempts[key] if now - t < self._window]
            if len(self._attempts[key]) >= self._max:
                self._locked[key] = now + self._lockout
                return False, self._lockout
            return True, 0

    def record(self, key: str):
        now = time.time()
        with self._lock:
            self._attempts[key].append(now)

    def clear(self, key: str):
        with self._lock:
            self._attempts.pop(key, None)
            self._locked.pop(key, None)


auth_limiter = RateLimiter(max_attempts=10, window_seconds=300, lockout_seconds=600)
register_limiter = RateLimiter(max_attempts=5, window_seconds=3600, lockout_seconds=1800)

# ── Database ────────────────────────────────────────────────────────────────

DB_PATH = Path(os.environ.get("DIVERG_DB_PATH", str(ROOT / "data" / "dashboard.db")).strip().lstrip("="))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
print(f"  DB path: {DB_PATH}  (exists: {DB_PATH.exists()})")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    name         TEXT DEFAULT '',
    password     TEXT,
    provider     TEXT DEFAULT 'email',
    avatar_url   TEXT DEFAULT '',
    created_at   TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    user_id      TEXT,
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
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _db() as conn:
        conn.executescript(SCHEMA)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT ''")


def _count_severity(findings: list, level: str) -> int:
    return sum(1 for f in findings if (f.get("severity") or "").lower() == level.lower())


def save_scan(scan_id: str, result: dict, scope: str, user_id: str = ""):
    findings = result.get("findings") or []
    sev = {s: _count_severity(findings, s) for s in ("Critical", "High", "Medium", "Low", "Info")}
    with _db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (id, user_id, target_url, scope, scanned_at, status, risk_score, risk_verdict,
                total, critical, high, medium, low, info, report_json, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id,
                user_id,
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


# ── Auth helpers ────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def check_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def _get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        return None
    if not token or len(token) > 4096:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    with _db() as conn:
        row = conn.execute("SELECT id, email, name, provider, avatar_url, created_at FROM users WHERE id = ?",
                           (payload["sub"],)).fetchone()
    return dict(row) if row else None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated


def validate_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def sanitize_text(text: str, max_len: int = 100) -> str:
    return text.strip()[:max_len]


# ── Flask app ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_SIZE

VALID_SCOPES = ("full", "quick", "crypto", "recon", "web", "api", "passive", "attack")

init_db()


@app.after_request
def _security_headers(resp):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "0"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-site"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    connect_src = "'self' https://mainnet.helius-rpc.com"
    if not IS_PRODUCTION:
        connect_src += " http://127.0.0.1:*"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        f"connect-src {connect_src}; "
        "frame-ancestors 'none'"
    )
    if request.path.startswith("/dashboard") or request.path.startswith("/login"):
        resp.headers["Content-Security-Policy"] = csp

    resp.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/auth") else "private, no-cache"
    return resp


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST", "OPTIONS"])
def auth_register():
    if request.method == "OPTIONS":
        return "", 204

    ip = _get_client_ip()
    allowed, retry = register_limiter.check(ip)
    if not allowed:
        return jsonify({"error": "Too many attempts. Try again later."}), 429

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    email = sanitize_text(data.get("email") or "", 254).lower()
    password = (data.get("password") or "")
    name = sanitize_text(data.get("name") or "", 100)

    if not validate_email(email):
        return jsonify({"error": "Valid email required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(password) > 128:
        return jsonify({"error": "Password too long"}), 400

    register_limiter.record(ip)

    with _db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            # Identical response to prevent email enumeration
            time.sleep(0.1)
            return jsonify({"error": "Registration failed"}), 400

        user_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO users (id, email, name, password, provider, created_at) VALUES (?,?,?,?,?,?)",
            (user_id, email, name or email.split("@")[0], hash_password(password), "email",
             datetime.now(timezone.utc).isoformat()),
        )

    token = create_token(user_id, email)
    return jsonify({
        "token": token,
        "user": {"id": user_id, "email": email, "name": name or email.split("@")[0], "provider": "email"},
    }), 201


@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
def auth_login():
    if request.method == "OPTIONS":
        return "", 204

    ip = _get_client_ip()
    allowed, retry = auth_limiter.check(ip)
    if not allowed:
        resp = jsonify({"error": "Too many login attempts. Try again later."})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    email = sanitize_text(data.get("email") or "", 254).lower()
    password = (data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) > 128:
        return jsonify({"error": "Invalid credentials"}), 401

    auth_limiter.record(ip)

    with _db() as conn:
        row = conn.execute("SELECT id, email, name, password, provider, avatar_url FROM users WHERE email = ?",
                           (email,)).fetchone()

    if not row:
        # Burn CPU to prevent timing-based user enumeration
        bcrypt.hashpw(b"dummy_timing_pad", bcrypt.gensalt(rounds=12))
        return jsonify({"error": "Invalid credentials"}), 401

    user = dict(row)

    if not user.get("password"):
        # Don't reveal auth method — same generic error
        bcrypt.hashpw(b"dummy_timing_pad", bcrypt.gensalt(rounds=12))
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password(password, user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    auth_limiter.clear(ip)
    token = create_token(user["id"], user["email"])
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "provider": user["provider"],
                 "avatar_url": user.get("avatar_url", "")},
    })


@app.route("/api/auth/google", methods=["POST", "OPTIONS"])
def auth_google():
    if request.method == "OPTIONS":
        return "", 204

    ip = _get_client_ip()
    allowed, _ = auth_limiter.check(ip)
    if not allowed:
        return jsonify({"error": "Too many attempts. Try again later."}), 429

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    credential = (data.get("credential") or "").strip()

    if not credential or len(credential) > 4096:
        return jsonify({"error": "Missing Google credential"}), 400

    auth_limiter.record(ip)

    try:
        import urllib.request
        verify_url = f"https://www.googleapis.com/oauth2/v3/userinfo"
        req = urllib.request.Request(verify_url, headers={"Authorization": f"Bearer {credential}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            info = json.loads(resp.read().decode())
    except Exception:
        return jsonify({"error": "Google verification failed"}), 401

    if not info.get("email_verified", False):
        return jsonify({"error": "Google email not verified"}), 401

    if GOOGLE_CLIENT_ID and info.get("aud") != GOOGLE_CLIENT_ID:
        return jsonify({"error": "Invalid Google credentials"}), 401

    email = sanitize_text(info.get("email", ""), 254).lower()
    name = sanitize_text(info.get("name", ""), 100)
    avatar = sanitize_text(info.get("picture", ""), 500)

    if not email:
        return jsonify({"error": "Could not get email from Google"}), 401

    with _db() as conn:
        existing = conn.execute("SELECT id, email, name, provider, avatar_url FROM users WHERE email = ?",
                                (email,)).fetchone()
        if existing:
            user = dict(existing)
            conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar, user["id"]))
        else:
            user_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO users (id, email, name, password, provider, avatar_url, created_at) VALUES (?,?,?,?,?,?,?)",
                (user_id, email, name, None, "google", avatar, datetime.now(timezone.utc).isoformat()),
            )
            user = {"id": user_id, "email": email, "name": name, "provider": "google", "avatar_url": avatar}

    auth_limiter.clear(ip)
    token = create_token(user["id"], email)
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": email, "name": user.get("name", name),
                 "provider": "google", "avatar_url": user.get("avatar_url", avatar)},
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def auth_me():
    return jsonify({"user": request.user})


# ── Dashboard static files ───────────────────────────────────────────────────

DASHBOARD_DIR = ROOT / "dashboard"


@app.route("/dashboard/")
@app.route("/dashboard")
def dashboard_root():
    return send_from_directory(str(DASHBOARD_DIR), "index.html")


@app.route("/dashboard/<path:filename>")
def dashboard_static(filename):
    return send_from_directory(str(DASHBOARD_DIR), filename)


@app.route("/login")
@app.route("/login/")
def login_page():
    return send_from_directory(str(DASHBOARD_DIR), "login.html")


# ── Scan endpoints ───────────────────────────────────────────────────────────

def _parse_scan_body():
    if not request.is_json:
        return None, None, None, (jsonify({"error": "Content-Type must be application/json"}), 400)
    data = request.get_json(silent=True) or {}
    url = sanitize_text(data.get("url") or "", 2048)
    if not url:
        return None, None, None, (jsonify({"error": "Missing 'url' in body"}), 400)
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    goal = sanitize_text(data.get("goal") or "", 500) or None
    scope = sanitize_text(data.get("scope") or "full", 20).lower()
    if scope not in VALID_SCOPES:
        scope = "full"
    return url, goal, scope, None


@app.route("/api/scan", methods=["OPTIONS"])
def api_scan_options():
    return "", 204


@app.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    if not SCANNER_AVAILABLE:
        return jsonify({"error": "Scanner engine not available on this instance"}), 503
    url, goal, scope, err = _parse_scan_body()
    if err:
        return err
    try:
        result = run_web_scan(url, scope=scope, goal=goal)
        scan_id = str(uuid.uuid4())
        save_scan(scan_id, result, scope, user_id=request.user["id"])
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
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/stream", methods=["OPTIONS"])
def api_scan_stream_options():
    return "", 204


@app.route("/api/scan/stream", methods=["POST"])
@require_auth
def api_scan_stream():
    if not SCANNER_AVAILABLE:
        return jsonify({"error": "Scanner engine not available on this instance"}), 503
    url, goal, scope, err = _parse_scan_body()
    if err:
        return err

    scan_id = str(uuid.uuid4())
    user_id = request.user["id"]

    def generate():
        accumulated = None
        try:
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
                    save_scan(scan_id, accumulated, scope, user_id=user_id)
                except Exception:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── PoC endpoint ─────────────────────────────────────────────────────────────

@app.route("/api/poc/simulate", methods=["OPTIONS"])
def poc_simulate_options():
    return "", 204


@app.route("/api/poc/simulate", methods=["POST"])
@require_auth
def poc_simulate():
    if not SCANNER_AVAILABLE:
        return jsonify({"error": "Scanner engine not available on this instance"}), 503
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True) or {}
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
        poc_type = sanitize_text(data.get("type") or "", 20).lower()
        url = sanitize_text(data.get("url") or "", 2048)
        if not url:
            return jsonify({"error": "Missing url (or provide finding)"}), 400
        if poc_type not in ("idor", "unauthenticated"):
            return jsonify({"error": "type must be 'idor' or 'unauthenticated'"}), 400
        if poc_type == "idor":
            result = run_idor_poc(url=url, method=data.get("method") or "GET",
                                  params=data.get("params"), data=data.get("data"),
                                  headers=data.get("headers"), param_to_change=data.get("param_to_change"),
                                  new_value=str(data.get("new_value") or "1"), cookies=data.get("cookies"))
        else:
            result = run_unauth_poc(url=url, method=data.get("method") or "GET",
                                    headers=data.get("headers"), cookies=data.get("cookies"))

    return jsonify({
        "success": result.success,
        "status_code": result.status_code,
        "body_preview": result.body_preview,
        "conclusion": result.conclusion,
        "error": result.error or None,
        "poc_type": result.poc_type or None,
    })


# ── History endpoints ─────────────────────────────────────────────────────────

def _safe_int(val, default: int, minimum: int = 0, maximum: int = 999999) -> int:
    try:
        n = int(val)
        return max(minimum, min(n, maximum))
    except (TypeError, ValueError):
        return default


@app.route("/api/history", methods=["GET"])
@require_auth
def history_list():
    limit = _safe_int(request.args.get("limit"), 50, 1, 200)
    offset = _safe_int(request.args.get("offset"), 0, 0, 999999)
    user_id = request.user["id"]

    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)).fetchone()[0]
        rows = conn.execute(
            """SELECT id, target_url, scope, scanned_at, status, risk_score,
                       risk_verdict, total, critical, high, medium, low, info, label, created_at
                FROM scans WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?""",
            (user_id, limit, offset),
        ).fetchall()

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": [dict(r) for r in rows],
    })


@app.route("/api/history/<scan_id>", methods=["GET"])
@require_auth
def history_get(scan_id):
    if len(scan_id) > 50:
        return jsonify({"error": "Invalid scan ID"}), 400
    with _db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?",
                           (scan_id, request.user["id"])).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    data = dict(row)
    if data.get("report_json"):
        data["report"] = json.loads(data.pop("report_json"))
    else:
        data.pop("report_json", None)
    data.pop("user_id", None)
    return jsonify(data)


@app.route("/api/history/<scan_id>", methods=["DELETE", "OPTIONS"])
def history_delete(scan_id):
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    if len(scan_id) > 50:
        return jsonify({"error": "Invalid scan ID"}), 400
    with _db() as conn:
        conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user["id"]))
    return jsonify({"deleted": scan_id})


@app.route("/api/history/<scan_id>", methods=["PATCH"])
@require_auth
def history_patch(scan_id):
    if len(scan_id) > 50:
        return jsonify({"error": "Invalid scan ID"}), 400
    data = (request.get_json(silent=True) or {}) if request.is_json else {}
    label = sanitize_text(data.get("label", ""), 200)
    with _db() as conn:
        conn.execute("UPDATE scans SET label = ? WHERE id = ? AND user_id = ?",
                     (label, scan_id, request.user["id"]))
    return jsonify({"id": scan_id, "label": label})


# ── Stats endpoint ────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@require_auth
def stats():
    user_id = request.user["id"]
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
            FROM scans WHERE user_id = ?
        """, (user_id,)).fetchone()

        recent = conn.execute("""
            SELECT id, target_url, risk_score, risk_verdict, total, critical, scanned_at, label
            FROM scans WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 5
        """, (user_id,)).fetchall()

        verdicts = conn.execute("""
            SELECT risk_verdict, COUNT(*) as cnt FROM scans
            WHERE risk_verdict IS NOT NULL AND user_id = ?
            GROUP BY risk_verdict
        """, (user_id,)).fetchall()

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
    user_count = 0
    try:
        with _db() as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        pass
    return jsonify({
        "status": "ok",
        "service": "diverg-console",
        "version": "2.3",
        "db_path": str(DB_PATH),
        "db_exists": DB_PATH.exists(),
        "users": user_count,
    })


# ── Catch-all redirect to login ──────────────────────────────────────────────

@app.route("/")
def root_redirect():
    from flask import redirect
    return redirect("/login")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Diverg Console API")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    print(f"  Diverg Console  →  http://{args.host}:{args.port}/dashboard/")
    print(f"  Login           →  http://{args.host}:{args.port}/login")
    print(f"  API             →  http://{args.host}:{args.port}/api/health")
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "Diverg"
    WSGIRequestHandler.sys_version = ""
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
