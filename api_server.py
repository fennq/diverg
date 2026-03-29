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

Investigation (console):
  POST /api/investigation/blockchain   Solana via Helius + EVM via public RPC
  POST /api/investigation/solana-bundle  Token mint: holders, cluster %, coordination / risk score (extension parity)
  POST /api/investigation/domain       OSINT + recon + headers (full skill JSON)
  POST /api/investigation/reputation   OSINT context + entity reputation

Rewards:
  GET  /api/rewards/me           Points balance, referral code, recent ledger
  GET  /api/rewards/leaderboard  Top users by points (window=all|30d|7d)

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
import concurrent.futures
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
    from orchestrator import run_web_scan, run_web_scan_streaming, run_skill, aggregate_findings
    from poc_runner import run_poc_for_finding, run_idor_poc, run_unauth_poc
    SCANNER_AVAILABLE = True
except Exception as e:
    print(f"Warning: Scanner modules not fully available: {e}")
    SCANNER_AVAILABLE = False
    run_web_scan = None
    run_web_scan_streaming = None
    run_skill = None
    aggregate_findings = None
    run_poc_for_finding = None
    run_idor_poc = None
    run_unauth_poc = None

try:
    import requests
except ImportError:
    requests = None

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
# Authenticated reads only; stops leaderboard/ledger scraping.
rewards_read_limiter = RateLimiter(max_attempts=90, window_seconds=60, lockout_seconds=120)

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

CREATE TABLE IF NOT EXISTS user_points (
    user_id       TEXT PRIMARY KEY,
    balance       INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    referral_code TEXT UNIQUE,
    referred_by   TEXT,
    updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS points_ledger (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    delta      INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    ref_type   TEXT,
    ref_id     TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS referral_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id TEXT NOT NULL,
    referee_id  TEXT NOT NULL UNIQUE,
    credited_at TEXT NOT NULL
);
"""


def _db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with _db() as conn:
        conn.executescript(SCHEMA)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT ''")
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_points_ledger_idem
               ON points_ledger (user_id, reason, IFNULL(ref_type,''), ref_id)
               WHERE ref_id IS NOT NULL"""
        )


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
        if user_id:
            try:
                from dashboard_points import award_scan_points

                award_scan_points(conn, user_id, scan_id, scope)
            except Exception:
                pass


def _reward_investigation(user_id: str, slug: str) -> None:
    if not user_id:
        return
    try:
        from dashboard_points import investigation_delta, try_award_investigation_or_poc

        delta = investigation_delta(slug)
        with _db() as conn:
            try_award_investigation_or_poc(conn, user_id, f"investigation_{slug}", delta)
    except Exception:
        pass


def _reward_poc(user_id: str) -> None:
    if not user_id:
        return
    try:
        from dashboard_points import investigation_delta, try_award_investigation_or_poc

        delta = investigation_delta("poc")
        with _db() as conn:
            try_award_investigation_or_poc(conn, user_id, "poc_simulate", delta)
    except Exception:
        pass


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
    referral_raw = data.get("referral_code") or data.get("ref") or ""
    referral_raw = referral_raw.strip()[:64] if isinstance(referral_raw, str) else ""

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
        from dashboard_points import apply_referral_on_register, ensure_user_points_row

        ensure_user_points_row(conn, user_id)
        apply_referral_on_register(conn, user_id, referral_raw)

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
    with _db() as conn:
        from dashboard_points import ensure_user_points_row

        ensure_user_points_row(conn, user["id"])
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

    referral_raw = data.get("referral_code") or data.get("ref") or ""
    referral_raw = referral_raw.strip()[:64] if isinstance(referral_raw, str) else ""

    with _db() as conn:
        existing = conn.execute("SELECT id, email, name, provider, avatar_url FROM users WHERE email = ?",
                                (email,)).fetchone()
        from dashboard_points import apply_referral_on_register, ensure_user_points_row

        if existing:
            user = dict(existing)
            conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar, user["id"]))
            ensure_user_points_row(conn, user["id"])
        else:
            user_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO users (id, email, name, password, provider, avatar_url, created_at) VALUES (?,?,?,?,?,?,?)",
                (user_id, email, name, None, "google", avatar, datetime.now(timezone.utc).isoformat()),
            )
            ensure_user_points_row(conn, user_id)
            apply_referral_on_register(conn, user_id, referral_raw)
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
        return None, None, None, None, (jsonify({"error": "Content-Type must be application/json"}), 400)
    data = request.get_json(silent=True) or {}
    url = sanitize_text(data.get("url") or "", 2048)
    if not url:
        return None, None, None, None, (jsonify({"error": "Missing 'url' in body"}), 400)
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    goal = sanitize_text(data.get("goal") or "", 500) or None
    scope = sanitize_text(data.get("scope") or "full", 20).lower()
    if scope not in VALID_SCOPES:
        scope = "full"
    cookie_header = sanitize_text(
        data.get("cookie_header") or data.get("cookies") or "",
        8192,
    ).strip()
    bearer_token = sanitize_text(
        data.get("bearer_token") or data.get("bearer") or "",
        4096,
    ).strip()
    auth_context = None
    if cookie_header or bearer_token:
        auth_context = {}
        if cookie_header:
            auth_context["cookie_header"] = cookie_header
        if bearer_token:
            auth_context["bearer_token"] = bearer_token
    return url, goal, scope, auth_context, None


@app.route("/api/scan", methods=["OPTIONS"])
def api_scan_options():
    return "", 204


@app.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    if not SCANNER_AVAILABLE:
        return jsonify({"error": "Scanner engine not available on this instance"}), 503
    url, goal, scope, auth_context, err = _parse_scan_body()
    if err:
        return err
    try:
        result = run_web_scan(url, scope=scope, goal=goal, auth_context=auth_context)
        scan_id = str(uuid.uuid4())
        save_scan(scan_id, result, scope, user_id=request.user["id"])
        payload = {
            "id": scan_id,
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scanned_at": result["scanned_at"],
            "summary": result.get("summary"),
            "skills_run": result.get("skills_run"),
            "scan_metrics": result.get("scan_metrics"),
            "auth_supplied": result.get("auth_supplied"),
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
    url, goal, scope, auth_context, err = _parse_scan_body()
    if err:
        return err

    scan_id = str(uuid.uuid4())
    user_id = request.user["id"]

    def generate():
        accumulated = None
        try:
            yield json.dumps({"event": "scan_start", "id": scan_id, "url": url, "scope": scope}) + "\n"
            for event in run_web_scan_streaming(url, scope=scope, goal=goal, auth_context=auth_context):
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
    verbose = bool(data.get("verbose"))
    pv_lim = 20000 if verbose else None
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
                max_body_preview=pv_lim,
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
                                  new_value=str(data.get("new_value") or "1"), cookies=data.get("cookies"),
                                  max_body_preview=pv_lim)
        else:
            result = run_unauth_poc(url=url, method=data.get("method") or "GET",
                                    headers=data.get("headers"), cookies=data.get("cookies"),
                                    max_body_preview=pv_lim)

    if result.success:
        _reward_poc(request.user["id"])
    return jsonify({
        "success": result.success,
        "status_code": result.status_code,
        "body_preview": result.body_preview,
        "conclusion": result.conclusion,
        "error": result.error or None,
        "poc_type": result.poc_type or None,
        "verbose": verbose,
    })


# ── Investigation tools (full skill / chain data for console) ─────────────────

_bundle_api_lock = Lock()

_ETH_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _helius_solana_rpc(network: str, api_key: str, method: str, params: list | dict) -> dict:
    base = "https://devnet.helius-rpc.com" if network == "devnet" else "https://mainnet.helius-rpc.com"
    url = f"{base}/?api-key={api_key}"
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=25,
        headers={"Content-Type": "application/json"},
    )
    return r.json()


def _evm_public_rpc(method: str, params: list) -> dict:
    r = requests.post(
        "https://cloudflare-eth.com",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=20,
        headers={"Content-Type": "application/json"},
    )
    return r.json()


def _summarize_chain_solana(raw: dict) -> dict:
    s: dict = {}
    bal = raw.get("getBalance") or {}
    if isinstance(bal, dict) and "result" in bal:
        v = bal["result"]
        if isinstance(v, dict) and "value" in v:
            lamports = v["value"]
        else:
            lamports = v
        if isinstance(lamports, int):
            s["lamports"] = lamports
            s["sol_approx"] = round(lamports / 1e9, 9)
    acct = raw.get("getAccountInfo") or {}
    if isinstance(acct, dict) and acct.get("result") and isinstance(acct["result"], dict):
        val = acct["result"].get("value")
        if isinstance(val, dict):
            s["owner"] = val.get("owner")
            if val.get("data") and isinstance(val["data"], dict):
                parsed = val["data"].get("parsed") or {}
                s["parsed_type"] = parsed.get("type")
    sigs = raw.get("getSignaturesForAddress") or {}
    if isinstance(sigs, dict) and isinstance(sigs.get("result"), list):
        s["recent_signatures_count"] = len(sigs["result"])
        s["recent_signatures_sample"] = [x.get("signature") for x in sigs["result"][:5] if isinstance(x, dict)]
    tok = raw.get("getTokenAccountsByOwner") or {}
    if isinstance(tok, dict) and isinstance(tok.get("result"), dict):
        ta = tok["result"].get("value")
        if isinstance(ta, list):
            s["token_accounts_count"] = len(ta)
    for k, v in raw.items():
        if isinstance(v, dict) and v.get("error"):
            s.setdefault("rpc_errors", []).append({k: v.get("error")})
    return s


def _summarize_chain_evm(raw: dict) -> dict:
    s = {}
    bal = raw.get("eth_getBalance") or {}
    if isinstance(bal, dict) and bal.get("result"):
        wei_hex = bal["result"]
        if isinstance(wei_hex, str) and wei_hex.startswith("0x"):
            try:
                wei = int(wei_hex, 16)
                s["balance_wei"] = wei
                s["eth_approx"] = round(wei / 1e18, 8)
            except ValueError:
                s["balance_raw"] = wei_hex
    nonce = raw.get("eth_getTransactionCount") or {}
    if isinstance(nonce, dict) and nonce.get("result") is not None:
        s["transaction_count_hex"] = nonce["result"]
    return s


@app.route("/api/investigation/blockchain", methods=["OPTIONS"])
def investigation_blockchain_options():
    return "", 204


@app.route("/api/investigation/blockchain", methods=["POST"])
@require_auth
def investigation_blockchain():
    if not requests:
        return jsonify({"error": "requests library unavailable"}), 503
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    addr = sanitize_text(data.get("address") or "", 128).strip()
    if not addr:
        return jsonify({"error": "Missing address"}), 400
    network = sanitize_text(data.get("network") or "mainnet", 16).lower()
    if network not in ("mainnet", "devnet"):
        network = "mainnet"

    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = sanitize_text(data.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key

    out: dict = {"address": addr, "network": network}

    if _ETH_ADDR_RE.match(addr):
        out["chain"] = "evm"
        try:
            raw = {
                "eth_getBalance": _evm_public_rpc("eth_getBalance", [addr, "latest"]),
                "eth_getTransactionCount": _evm_public_rpc("eth_getTransactionCount", [addr, "latest"]),
            }
            out["raw"] = raw
            out["summary"] = _summarize_chain_evm(raw)
        except Exception as e:
            return jsonify({"error": str(e), "address": addr, "chain": "evm"}), 200
        _reward_investigation(request.user["id"], "blockchain")
        return jsonify(out)

    # Solana-style (base58)
    if not api_key:
        return jsonify({
            "error": "Helius API key required for Solana lookups. Add it in Settings or set HELIUS_API_KEY on the server.",
            "address": addr,
            "chain": "solana",
        }), 400

    out["chain"] = "solana"
    raw: dict = {}
    try:
        raw["getBalance"] = _helius_solana_rpc(network, api_key, "getBalance", [addr])
        raw["getAccountInfo"] = _helius_solana_rpc(
            network, api_key, "getAccountInfo",
            [addr, {"encoding": "jsonParsed", "commitment": "confirmed"}],
        )
        raw["getSignaturesForAddress"] = _helius_solana_rpc(
            network, api_key, "getSignaturesForAddress", [addr, {"limit": 35}],
        )
    except Exception as e:
        return jsonify({"error": str(e), "address": addr, "chain": "solana", "raw": raw}), 200
    try:
        raw["getTokenAccountsByOwner"] = _helius_solana_rpc(
            network,
            api_key,
            "getTokenAccountsByOwner",
            [
                addr,
                {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                {"encoding": "jsonParsed"},
            ],
        )
    except Exception as e:
        raw["getTokenAccountsByOwner"] = {"error": str(e)}
    out["raw"] = raw
    out["summary"] = _summarize_chain_solana(raw)
    _reward_investigation(request.user["id"], "blockchain")
    return jsonify(out)


@app.route("/api/investigation/domain", methods=["OPTIONS"])
def investigation_domain_options():
    return "", 204


@app.route("/api/investigation/domain", methods=["POST"])
@require_auth
def investigation_domain():
    if not SCANNER_AVAILABLE or not run_skill or not aggregate_findings:
        return jsonify({"error": "Scanner engine not available"}), 503
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    domain = sanitize_text(data.get("domain") or "", 253).strip().lower()
    if not domain:
        return jsonify({"error": "Missing domain"}), 400
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    target_url = "https://" + domain

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_os = pool.submit(run_skill, "osint", domain, target_url, None, scan_type="full")
            f_rc = pool.submit(run_skill, "recon", domain, target_url, None, scan_type="full")
            f_hd = pool.submit(run_skill, "headers_ssl", domain, target_url, None, scan_type="full")
            osint = f_os.result(timeout=120)
            recon = f_rc.result(timeout=120)
            headers_ssl = f_hd.result(timeout=120)
        combined = {"osint": osint, "recon": recon, "headers_ssl": headers_ssl}
        findings = aggregate_findings(combined)
        _reward_investigation(request.user["id"], "domain")
        return jsonify({
            "domain": domain,
            "target_url": target_url,
            "findings": findings,
            "findings_count": len(findings),
            "skills": combined,
        })
    except Exception as e:
        return jsonify({"error": str(e), "domain": domain}), 500


@app.route("/api/investigation/reputation", methods=["OPTIONS"])
def investigation_reputation_options():
    return "", 204


@app.route("/api/investigation/reputation", methods=["POST"])
@require_auth
def investigation_reputation():
    if not SCANNER_AVAILABLE or not run_skill:
        return jsonify({"error": "Scanner engine not available"}), 503
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    target = sanitize_text(data.get("target") or "", 512).strip()
    if not target:
        return jsonify({"error": "Missing target"}), 400
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
    target_url = "https://" + domain

    try:
        osint = run_skill("osint", domain, target_url, None, scan_type="full")
        ctx = {}
        if isinstance(osint, dict) and "error" not in osint:
            ctx["osint_json"] = json.dumps(osint)
        rep = run_skill("entity_reputation", domain, target_url, ctx, scan_type="full")
        _reward_investigation(request.user["id"], "reputation")
        return jsonify({
            "domain": domain,
            "target_url": target_url,
            "osint": osint,
            "entity_reputation": rep,
        })
    except Exception as e:
        return jsonify({"error": str(e), "domain": domain}), 500


def _enrich_solana_bundle_payload(raw: dict) -> dict:
    """Top-level risk_score / cluster fields for dashboard + extension parity."""
    if not raw.get("ok"):
        return raw
    bs = raw.get("bundle_signals") or {}
    coord = bs.get("coordination_score")
    try:
        coord_f = float(coord) if coord is not None else 0.0
    except (TypeError, ValueError):
        coord_f = 0.0
    coord_f = max(0.0, min(100.0, coord_f))
    cluster_pct = raw.get("focus_cluster_pct_supply")
    try:
        cp = float(cluster_pct) if cluster_pct is not None else 0.0
    except (TypeError, ValueError):
        cp = 0.0
    raw["risk_score"] = round(coord_f, 2)
    raw["cluster_pct_supply"] = cp
    raw["cluster_wallet_count"] = len(raw.get("focus_cluster_wallets") or [])
    reasons = bs.get("coordination_reasons") or []
    raw["risk_signals"] = reasons if isinstance(reasons, list) else []
    if coord_f >= 50 or cp >= 35:
        verdict = "Elevated"
    elif coord_f >= 28 or cp >= 18:
        verdict = "Moderate"
    else:
        verdict = "Lower in sampled holders"
    raw["risk_verdict"] = verdict
    sig_txt = ", ".join(str(x) for x in raw["risk_signals"][:8]) if raw["risk_signals"] else "none"
    raw["risk_summary"] = (
        f"{verdict}: coordination {raw['risk_score']}/100; "
        f"cluster {raw['cluster_wallet_count']} wallets hold ~{cp}% of sampled supply. "
        f"Signals: {sig_txt}."
    )
    return raw


@app.route("/api/investigation/solana-bundle", methods=["OPTIONS"])
def investigation_solana_bundle_options():
    return "", 204


@app.route("/api/investigation/solana-bundle", methods=["POST"])
@require_auth
def investigation_solana_bundle():
    """
    Solana SPL token bundle snapshot — same logic as extension/solana_bundle.js +
    investigation/solana_bundle.py (holders, same-funder cluster %, coordination score).
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    mint = sanitize_text(data.get("mint") or "", 128).strip()
    wallet = sanitize_text(data.get("wallet") or "", 128).strip() or None
    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = sanitize_text(data.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key
    if not mint:
        return jsonify({"error": "Missing mint"}), 400
    if not api_key:
        return jsonify({"error": "Helius API key required. Add it in Settings or set HELIUS_API_KEY on the server."}), 400

    exclude_wallets = None
    ex = data.get("exclude_wallets")
    if isinstance(ex, list):
        exclude_wallets = [
            sanitize_text(str(x), 128).strip()
            for x in ex[:30]
            if x and str(x).strip()
        ] or None

    include_x_intel = None
    x_raw = data.get("include_x_intel")
    if x_raw is True or x_raw is False:
        include_x_intel = bool(x_raw)
    elif isinstance(x_raw, str) and x_raw.strip().lower() in ("true", "1", "yes"):
        include_x_intel = True
    elif isinstance(x_raw, str) and x_raw.strip().lower() in ("false", "0", "no"):
        include_x_intel = False

    inv_dir = ROOT / "investigation"
    inv_path = str(inv_dir)
    if inv_path not in sys.path:
        sys.path.insert(0, inv_path)

    try:
        import onchain_clients as oc  # type: ignore
        import solana_bundle as sb  # type: ignore
    except ImportError as e:
        return jsonify({"error": f"Solana bundle module unavailable: {e}"}), 503

    with _bundle_api_lock:
        old_key = getattr(oc, "HELIUS_KEY", "") or ""
        try:
            oc.HELIUS_KEY = api_key.strip()
            out = sb.run_bundle_snapshot(
                mint,
                wallet,
                max_holders=120,
                max_funded_by_lookups=120,
                exclude_wallets=exclude_wallets,
                include_x_intel=include_x_intel,
            )
        finally:
            oc.HELIUS_KEY = old_key

    if isinstance(out, dict) and out.get("ok"):
        out = _enrich_solana_bundle_payload(out)
    payload = out if isinstance(out, dict) else {"ok": False, "error": "Unexpected response"}
    if isinstance(payload, dict) and payload.get("ok"):
        _reward_investigation(request.user["id"], "solana_bundle")
    try:
        return jsonify(payload)
    except TypeError:
        return Response(
            json.dumps(payload, default=str),
            mimetype="application/json",
        )


# ── Shared API helpers (history, rewards) ───────────────────────────────────

def _safe_int(val, default: int, minimum: int = 0, maximum: int = 999999) -> int:
    try:
        n = int(val)
        return max(minimum, min(n, maximum))
    except (TypeError, ValueError):
        return default


# ── Rewards ───────────────────────────────────────────────────────────────────


@app.route("/api/rewards/me", methods=["GET", "OPTIONS"])
def rewards_me():
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    uid = user["id"]
    ip = _get_client_ip()
    allowed, retry = rewards_read_limiter.check(f"rw:me:{uid}:{ip}")
    if not allowed:
        resp = jsonify({"error": "Too many requests. Try again shortly."})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429
    rewards_read_limiter.record(f"rw:me:{uid}:{ip}")
    from dashboard_points import ensure_user_points_row

    with _db() as conn:
        ensure_user_points_row(conn, uid)
        row = conn.execute(
            "SELECT balance, referral_code, referred_by FROM user_points WHERE user_id = ?",
            (uid,),
        ).fetchone()
        ledger_rows = conn.execute(
            """SELECT delta, reason, ref_type, ref_id, created_at FROM points_ledger
               WHERE user_id = ? ORDER BY id DESC LIMIT 20""",
            (uid,),
        ).fetchall()
    recent = [dict(r) for r in ledger_rows]
    return jsonify({
        "balance": int(row["balance"]) if row else 0,
        "referral_code": row["referral_code"] if row else None,
        "referred_by": row["referred_by"] if row else None,
        "recent_ledger": recent,
    })


@app.route("/api/rewards/leaderboard", methods=["GET", "OPTIONS"])
def rewards_leaderboard():
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    ip = _get_client_ip()
    allowed, retry = rewards_read_limiter.check(f"rw:lb:{user['id']}:{ip}")
    if not allowed:
        resp = jsonify({"error": "Too many requests. Try again shortly."})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429
    rewards_read_limiter.record(f"rw:lb:{user['id']}:{ip}")
    window = (request.args.get("window") or "all").lower()
    if window not in ("all", "30d", "7d"):
        window = "all"
    limit = _safe_int(request.args.get("limit"), 50, 1, 100)
    from dashboard_points import leaderboard_since_iso, privacy_display_name

    since = leaderboard_since_iso(window)
    with _db() as conn:
        if since:
            rows = conn.execute(
                """SELECT u.id AS user_id, u.name, u.email, SUM(pl.delta) AS pts
                   FROM points_ledger pl
                   JOIN users u ON u.id = pl.user_id
                   WHERE pl.created_at >= ?
                   GROUP BY u.id
                   HAVING SUM(pl.delta) > 0
                   ORDER BY SUM(pl.delta) DESC
                   LIMIT ?""",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT u.id AS user_id, u.name, u.email, SUM(pl.delta) AS pts
                   FROM points_ledger pl
                   JOIN users u ON u.id = pl.user_id
                   GROUP BY u.id
                   HAVING SUM(pl.delta) > 0
                   ORDER BY SUM(pl.delta) DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
    board = []
    for i, r in enumerate(rows, start=1):
        board.append({
            "rank": i,
            "user_id": r["user_id"],
            "display_name": privacy_display_name(r["name"], r["email"]),
            "points": int(r["pts"]),
        })
    return jsonify({"window": window, "leaderboard": board})


# ── History endpoints ─────────────────────────────────────────────────────────

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


@app.route("/api/history", methods=["DELETE", "OPTIONS"])
def history_bulk_delete():
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    with _db() as conn:
        rows = conn.execute("SELECT id FROM scans WHERE user_id = ?", (user["id"],)).fetchall()
        deleted_ids = [r["id"] for r in rows]
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user["id"],))
    return jsonify({"deleted_count": len(deleted_ids), "deleted_ids": deleted_ids[:500]})


def _safe_report_json(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


@app.route("/api/analytics/summary", methods=["GET"])
@require_auth
def analytics_summary():
    user_id = request.user["id"]
    limit = _safe_int(request.args.get("limit"), 100, 1, 400)
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, target_url, scanned_at, created_at, risk_score, risk_verdict, total,
                      critical, high, medium, low, info, report_json
               FROM scans
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    scans = [dict(r) for r in rows]
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    verdict_breakdown: dict[str, int] = defaultdict(int)
    categories: dict[str, int] = defaultdict(int)
    total_risk = 0.0
    risk_n = 0

    now = datetime.now(timezone.utc)
    day_counts: dict[str, int] = {}
    for i in range(29, -1, -1):
        day = (now - timedelta(days=i)).date().isoformat()
        day_counts[day] = 0

    for s in scans:
        severity["critical"] += int(s.get("critical") or 0)
        severity["high"] += int(s.get("high") or 0)
        severity["medium"] += int(s.get("medium") or 0)
        severity["low"] += int(s.get("low") or 0)
        rv = str(s.get("risk_verdict") or "").strip()
        if rv:
            verdict_breakdown[rv] += 1
        rs = s.get("risk_score")
        try:
            if rs is not None:
                total_risk += float(rs)
                risk_n += 1
        except (TypeError, ValueError):
            pass

        ts_raw = s.get("scanned_at") or s.get("created_at")
        if isinstance(ts_raw, str) and ts_raw:
            try:
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                key = dt.date().isoformat()
                if key in day_counts:
                    day_counts[key] += 1
            except Exception:
                pass

        rep = _safe_report_json(s.get("report_json"))
        findings = rep.get("findings") if isinstance(rep.get("findings"), list) else []
        for f in findings:
            if not isinstance(f, dict):
                continue
            cat = str(f.get("category") or "Other").strip() or "Other"
            categories[cat] += 1

    top_categories = sorted(categories.items(), key=lambda kv: kv[1], reverse=True)[:8]
    return jsonify({
        "scans_considered": len(scans),
        "severity": severity,
        "avg_risk_score": round(total_risk / risk_n, 1) if risk_n else 0.0,
        "verdict_breakdown": dict(verdict_breakdown),
        "activity_30d": [{"date": d, "count": c} for d, c in day_counts.items()],
        "top_categories": [{"category": k, "count": v} for k, v in top_categories],
    })


@app.route("/api/findings", methods=["GET"])
@require_auth
def findings_list():
    user_id = request.user["id"]
    scan_limit = _safe_int(request.args.get("scan_limit"), 120, 1, 400)
    finding_limit = _safe_int(request.args.get("finding_limit"), 2000, 1, 10000)
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, target_url, scanned_at, created_at, report_json
               FROM scans WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, scan_limit),
        ).fetchall()
    out: list[dict] = []
    for row in rows:
        s = dict(row)
        rep = _safe_report_json(s.get("report_json"))
        findings = rep.get("findings") if isinstance(rep.get("findings"), list) else []
        for f in findings:
            if not isinstance(f, dict):
                continue
            out.append({
                "scan_id": s["id"],
                "target_url": s.get("target_url"),
                "scanned_at": s.get("scanned_at") or s.get("created_at"),
                "finding": f,
            })
            if len(out) >= finding_limit:
                break
        if len(out) >= finding_limit:
            break
    return jsonify({"total": len(out), "findings": out})


@app.route("/api/attack-paths", methods=["GET"])
@require_auth
def attack_paths_list():
    user_id = request.user["id"]
    scan_limit = _safe_int(request.args.get("scan_limit"), 120, 1, 400)
    path_limit = _safe_int(request.args.get("path_limit"), 1000, 1, 5000)
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, target_url, scanned_at, created_at, report_json
               FROM scans WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, scan_limit),
        ).fetchall()
    out: list[dict] = []
    for row in rows:
        s = dict(row)
        rep = _safe_report_json(s.get("report_json"))
        paths = rep.get("attack_paths") if isinstance(rep.get("attack_paths"), list) else []
        for p in paths:
            if not isinstance(p, dict):
                continue
            out.append({
                "scan_id": s["id"],
                "target_url": s.get("target_url"),
                "scanned_at": s.get("scanned_at") or s.get("created_at"),
                "attack_path": p,
            })
            if len(out) >= path_limit:
                break
        if len(out) >= path_limit:
            break
    return jsonify({"total": len(out), "attack_paths": out})


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
