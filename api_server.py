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
  POST /api/investigation/blockchain   Solana via Helius + EVM via public RPC; requires server ARKHAM_API_KEY (Intel summary)
  POST /api/investigation/blockchain-full  Full blockchain_investigation skill (crime_report, flow_graph; server API keys incl. ARKHAM_API_KEY)
  POST /api/investigation/solana-bundle  Token mint: holders, cluster %, coordination / risk score; requires server ARKHAM_API_KEY
  GET/POST/PATCH /api/solana/watchlist   Per-user SPL mint watchlist (Phase 2 hooks)
  DELETE /api/solana/watchlist/<id>      Remove one watchlist row
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
import errno
import json
import logging
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

import copy

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import (
        Flask,
        Response,
        g,
        jsonify,
        request,
        send_from_directory,
        stream_with_context,
    )
except ImportError:
    print("Install Flask: pip install flask")
    sys.exit(1)

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

try:
    import base58
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:
    base58 = None
    BadSignatureError = Exception  # type: ignore[assignment]
    VerifyKey = None  # type: ignore[assignment]

# ── Config ────────────────────────────────────────────────────────────────

IS_PRODUCTION = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("DIVERG_PRODUCTION"))
DIVERG_JWT_SECRET = (os.environ.get("DIVERG_JWT_SECRET") or "").strip()


def _resolve_jwt_secret() -> str:
    """JWT signing key. Production: set DIVERG_JWT_SECRET. Local dev: persist under data/ so restarts keep sessions valid."""
    if DIVERG_JWT_SECRET:
        return DIVERG_JWT_SECRET
    if IS_PRODUCTION:
        return secrets.token_hex(32)
    path = ROOT / "data" / ".jwt_secret"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            raw = path.read_text(encoding="utf-8").strip()
            if len(raw) >= 16:
                return raw
    except OSError as e:
        logging.getLogger("diverg.api").warning("jwt secret file read: %s", e)
    key = secrets.token_hex(32)
    try:
        path.write_text(key + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as e:
        logging.getLogger("diverg.api").warning("jwt secret file write: %s", e)
    return key


JWT_SECRET = _resolve_jwt_secret()
JWT_EXPIRY_HOURS = 72
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
ALLOWED_ORIGINS = [
    o.strip() for o in
    os.environ.get(
        "DIVERG_ALLOWED_ORIGINS",
        "https://dash.divergsec.com,https://divergsec.com,http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5001,http://localhost:5001"
    ).split(",") if o.strip()
]
MAX_REQUEST_SIZE = 2 * 1024 * 1024  # 2 MB
DIVERG_AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("DIVERG_AUDIT_LOG_RETENTION_DAYS", "90") or "90")
DIVERG_ENABLE_STRICT_PROOF_API = (os.environ.get("DIVERG_ENABLE_STRICT_PROOF_API", "1").strip().lower() in ("1", "true", "yes"))
# Default off so deploy healthchecks succeed; set DIVERG_REQUIRE_ARKHAM=1 when ARKHAM_API_KEY is always in env.
DIVERG_REQUIRE_ARKHAM = (os.environ.get("DIVERG_REQUIRE_ARKHAM", "0").strip().lower() in ("1", "true", "yes"))
DIVERG_HEALTH_ARKHAM_PROBE = (os.environ.get("DIVERG_HEALTH_ARKHAM_PROBE", "0").strip().lower() in ("1", "true", "yes"))
PRIVY_APP_ID = (os.environ.get("PRIVY_APP_ID") or "").strip()
PRIVY_CLIENT_ID = (os.environ.get("PRIVY_CLIENT_ID") or "").strip()
PRIVY_APP_SECRET = (os.environ.get("PRIVY_APP_SECRET") or "").strip()
DIVERG_ENABLE_PRIVY = (os.environ.get("DIVERG_ENABLE_PRIVY", "1").strip().lower() in ("1", "true", "yes"))
PRIVY_ENABLED = bool(DIVERG_ENABLE_PRIVY and PRIVY_APP_ID and PRIVY_APP_SECRET)

_INVESTIGATION_DIR = str(ROOT / "investigation")
if _INVESTIGATION_DIR not in sys.path:
    sys.path.insert(0, _INVESTIGATION_DIR)
FP_MEMORY_PATH = ROOT / "content" / "false_positive_memory.json"


def _arkham_capabilities(required: bool = True) -> dict:
    """Arkham capability metadata for user-facing payloads (never exposes secrets)."""
    available = bool((os.environ.get("ARKHAM_API_KEY") or "").strip())
    return {
        "provider": "arkham",
        "mode": "server_managed",
        "required_for_endpoint": bool(required),
        "available": available,
        "client_supplied_key_allowed": False,
        "status": "enabled" if available else "unavailable",
    }


def _attach_arkham_capabilities(out: dict, required: bool = True) -> None:
    out["intelligence_capabilities"] = _arkham_capabilities(required=required)


def _arkham_env_error_response(endpoint_label: str = "blockchain investigation"):
    """Return (jsonify(...), status) if ARKHAM_API_KEY is missing on the server; else None."""
    if (os.environ.get("ARKHAM_API_KEY") or "").strip():
        return None
    return jsonify({
        "error": f"Arkham intelligence is currently unavailable for {endpoint_label}.",
        "hint": "Set ARKHAM_API_KEY on the server. End-users should not provide personal Arkham keys.",
        "intelligence_capabilities": _arkham_capabilities(required=True),
    }), 503


def _attach_arkham_intel_block(out: dict, addr: str) -> None:
    """Mutate out with arkham explorer URL, summary, and optional error (never silent)."""
    try:
        import arkham_intel as ai
    except ImportError:
        out["arkham"] = {
            "explorer_url": "",
            "summary": {},
            "ok": False,
            "error": "arkham_intel module unavailable on server",
            "mode": "server_managed",
            "client_supplied_key_allowed": False,
        }
        return
    key = (os.environ.get("ARKHAM_API_KEY") or "").strip()
    sess = requests.Session() if requests else None
    data, err = ai.address_intelligence_all(addr, api_key=key, session=sess)
    out["arkham"] = {
        "explorer_url": ai.explorer_url_for_address(addr),
        "summary": ai.summarize_for_report(data),
        "ok": err is None,
        "error": err,
        "mode": "server_managed",
        "client_supplied_key_allowed": False,
    }


def _enrich_solana_bundle_arkham(raw: dict) -> dict:
    """Batch Arkham labels for focus cluster + top holders (requires ARKHAM_API_KEY)."""
    if not raw.get("ok") or not requests:
        return raw
    key = (os.environ.get("ARKHAM_API_KEY") or "").strip()
    if not key:
        raw["arkham"] = {"ok": False, "error": "ARKHAM_API_KEY missing", "batch_labels": {}}
        return raw
    try:
        import arkham_intel as ai
    except ImportError:
        raw["arkham"] = {"ok": False, "error": "arkham_intel unavailable", "batch_labels": {}}
        return raw
    wallets: list[str] = []
    for w in (raw.get("focus_cluster_wallets") or [])[:40]:
        if isinstance(w, str) and w.strip():
            wallets.append(w.strip())
    for row in (raw.get("top_holders") or [])[:15]:
        if not isinstance(row, dict):
            continue
        wa = row.get("wallet")
        if isinstance(wa, str) and wa.strip() and wa not in wallets:
            wallets.append(wa.strip())
    wallets = wallets[:50]
    if not wallets:
        raw["arkham"] = {"ok": True, "batch_labels": {}, "wallets_queried": 0}
        return raw
    sess = requests.Session()
    labels = ai.intel_batch(sess, wallets, key, chain="solana")
    raw["arkham"] = {
        "ok": True,
        "batch_labels": labels,
        "wallets_queried": len(wallets),
        "labeled_count": len(labels),
    }
    return raw


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

# ── Credits config/helpers ───────────────────────────────────────────────────

DIVERG_HOLDER_MINT = (os.environ.get("DIVERG_HOLDER_MINT") or "F1JxPbcYDwbvvQjsznEtcDcusnguNoFt1qt4CpsvBAGS").strip()
DIVERG_CREDITS_SOLANA_NETWORK = (os.environ.get("DIVERG_CREDITS_SOLANA_NETWORK") or "mainnet").strip().lower()
if DIVERG_CREDITS_SOLANA_NETWORK not in ("mainnet", "devnet"):
    DIVERG_CREDITS_SOLANA_NETWORK = "mainnet"
DIVERG_WALLET_CHALLENGE_TTL_SEC = max(60, min(int(os.environ.get("DIVERG_WALLET_CHALLENGE_TTL_SEC", "600") or "600"), 3600))


def _credits_module():
    import credits as c

    return c


def _credit_cost(scan_kind: str) -> float:
    return float(_credits_module().scan_cost(scan_kind))


def _credits_insufficient_response(state: dict, required: float):
    available = float((state or {}).get("credits_available") or 0.0)
    payload = {
        "error": "Insufficient credits",
        "code": "insufficient_credits",
        "required": round(float(required), 6),
        "available": round(available, 6),
        "credits": state or {},
    }
    return jsonify(payload), 402


def _sanitize_wallet_address(raw: str) -> str:
    return sanitize_text(raw or "", 128).strip()


def _decode_wallet_signature_bytes(
    signature_b58: str | None = None,
    signature_base64: str | None = None,
    signature_hex: str | None = None,
    signature_bytes: list[int] | None = None,
) -> bytes | None:
    if signature_bytes and isinstance(signature_bytes, list):
        try:
            vals = [int(x) for x in signature_bytes]
            if vals and all(0 <= v <= 255 for v in vals):
                return bytes(vals)
        except (TypeError, ValueError):
            pass
    if signature_base64:
        try:
            import base64

            return base64.b64decode(signature_base64, validate=True)
        except Exception:
            pass
    if signature_hex:
        try:
            return bytes.fromhex(signature_hex)
        except Exception:
            pass
    if signature_b58 and base58 is not None:
        try:
            return base58.b58decode(signature_b58)
        except Exception:
            pass
    return None


def _verify_wallet_signature(
    wallet_address: str,
    message: str,
    *,
    signature_b58: str | None = None,
    signature_base64: str | None = None,
    signature_hex: str | None = None,
    signature_bytes: list[int] | None = None,
) -> bool:
    if not wallet_address or not message:
        return False
    if base58 is None or VerifyKey is None:
        return False
    try:
        pub_bytes = base58.b58decode(wallet_address)
        sig_bytes = _decode_wallet_signature_bytes(
            signature_b58=signature_b58,
            signature_base64=signature_base64,
            signature_hex=signature_hex,
            signature_bytes=signature_bytes,
        )
        if not sig_bytes:
            return False
        vk = VerifyKey(pub_bytes)
        vk.verify(message.encode("utf-8"), sig_bytes)
        return True
    except (ValueError, BadSignatureError, TypeError):
        return False


def _sum_token_balance_from_rpc_result(result: dict) -> float:
    rows = ((result or {}).get("result") or {}).get("value")
    if not isinstance(rows, list):
        return 0.0
    total = 0.0
    for row in rows:
        if not isinstance(row, dict):
            continue
        acct = row.get("account")
        parsed = (((acct or {}).get("data") or {}).get("parsed") or {}).get("info") if isinstance(acct, dict) else {}
        token_amt = (parsed or {}).get("tokenAmount") if isinstance(parsed, dict) else {}
        ui = token_amt.get("uiAmount") if isinstance(token_amt, dict) else None
        ui_s = token_amt.get("uiAmountString") if isinstance(token_amt, dict) else None
        try:
            if ui is not None:
                total += float(ui)
            elif ui_s is not None:
                total += float(str(ui_s))
        except (TypeError, ValueError):
            continue
    return max(0.0, total)


def _fetch_diverg_holder_balance(wallet_address: str, api_key: str) -> tuple[float, str | None]:
    if not wallet_address:
        return 0.0, "missing_wallet_address"
    if not api_key:
        return 0.0, "missing_helius_api_key"
    try:
        raw = _helius_solana_rpc(
            DIVERG_CREDITS_SOLANA_NETWORK,
            api_key,
            "getTokenAccountsByOwner",
            [
                wallet_address,
                {"mint": DIVERG_HOLDER_MINT},
                {"encoding": "jsonParsed", "commitment": "confirmed"},
            ],
        )
    except Exception as e:
        return 0.0, str(e)
    if not isinstance(raw, dict):
        return 0.0, "unexpected_rpc_response"
    err = raw.get("error")
    if err:
        if isinstance(err, dict):
            return 0.0, str(err.get("message") or "rpc_error")
        return 0.0, str(err)
    return _sum_token_balance_from_rpc_result(raw), None


def _reserve_scan_credits(user_id: str, *, amount: float, reason: str, ref_type: str, ref_id: str, meta: dict | None = None):
    meta_s = json.dumps(meta or {}, default=str)[:1000]
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        ok, state, err = _credits_module().reserve_credits(
            conn,
            user_id,
            amount,
            reason=reason,
            ref_type=ref_type,
            ref_id=ref_id,
            meta_json=meta_s,
        )
    return ok, state, err


def _finalize_scan_credits(user_id: str, *, reason: str, ref_type: str, ref_id: str, meta: dict | None = None):
    meta_s = json.dumps(meta or {}, default=str)[:1000]
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        ok, state, err = _credits_module().finalize_reserved_credits(
            conn,
            user_id,
            reason=reason,
            ref_type=ref_type,
            ref_id=ref_id,
            meta_json=meta_s,
        )
    return ok, state, err


def _release_scan_credits(user_id: str, *, ref_type: str, ref_id: str):
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        return _credits_module().release_reserved_credits(conn, user_id, ref_type=ref_type, ref_id=ref_id)

# ── Database ────────────────────────────────────────────────────────────────

DB_PATH = Path(os.environ.get("DIVERG_DB_PATH", str(ROOT / "data" / "dashboard.db")).strip().lstrip("="))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
print(f"  DB path: {DB_PATH}  (exists: {DB_PATH.exists()})")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    name         TEXT DEFAULT '',
    role         TEXT DEFAULT 'analyst',
    org_id       TEXT DEFAULT '',
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

CREATE TABLE IF NOT EXISTS user_credits (
    user_id             TEXT PRIMARY KEY,
    wallet_address      TEXT DEFAULT '',
    wallet_verified_at  TEXT DEFAULT '',
    daily_bucket_date   TEXT NOT NULL,
    daily_grant_total   REAL NOT NULL DEFAULT 0,
    credits_remaining   REAL NOT NULL DEFAULT 0,
    credits_locked      REAL NOT NULL DEFAULT 0,
    credits_spent_today REAL NOT NULL DEFAULT 0,
    token_balance_ui    REAL NOT NULL DEFAULT 0,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credit_ledger (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    delta      REAL NOT NULL,
    reason     TEXT NOT NULL,
    ref_type   TEXT,
    ref_id     TEXT,
    meta_json  TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credit_holds (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    ref_type   TEXT NOT NULL,
    ref_id     TEXT NOT NULL,
    amount     REAL NOT NULL,
    reason     TEXT NOT NULL,
    meta_json  TEXT DEFAULT '{}',
    nonce      TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(user_id, ref_type, ref_id)
);

CREATE TABLE IF NOT EXISTS wallet_link_challenges (
    user_id       TEXT PRIMARY KEY,
    wallet_address TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    message       TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    role        TEXT,
    org_id      TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    status      TEXT DEFAULT 'ok',
    metadata    TEXT DEFAULT '{}',
    ip          TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS solana_watchlist (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          TEXT NOT NULL,
    mint             TEXT NOT NULL,
    label            TEXT DEFAULT '',
    tvl_usd          REAL,
    last_verdict     TEXT DEFAULT '',
    last_risk_score  REAL,
    last_checked_at  TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE(user_id, mint)
);

CREATE INDEX IF NOT EXISTS idx_solana_watchlist_user ON solana_watchlist(user_id);
"""


def _db():
    try:
        timeout = float(os.environ.get("DIVERG_SQLITE_TIMEOUT_SEC", "30"))
    except ValueError:
        timeout = 30.0
    conn = sqlite3.connect(str(DB_PATH), timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with _db() as conn:
        conn.executescript(SCHEMA)
        user_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "role" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst'")
        if "org_id" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN org_id TEXT DEFAULT ''")
        cols = [row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT ''")
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_points_ledger_idem
               ON points_ledger (user_id, reason, IFNULL(ref_type,''), ref_id)
               WHERE ref_id IS NOT NULL"""
        )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_ledger_idem
               ON credit_ledger (user_id, reason, IFNULL(ref_type,''), ref_id)
               WHERE ref_id IS NOT NULL"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_credit_ledger_user_created ON credit_ledger(user_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_credit_holds_user_created ON credit_holds(user_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_action ON audit_log(user_id, action)")


def _count_severity(findings: list, level: str) -> int:
    return sum(1 for f in findings if (f.get("severity") or "").lower() == level.lower())


def _severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(str(sev or "").strip().lower(), 5)


def _finding_signature(finding: dict) -> str:
    if not isinstance(finding, dict):
        return ""
    title = str(finding.get("title") or "").strip().lower()
    category = str(finding.get("category") or "").strip().lower()
    source = str(finding.get("source") or finding.get("_source_skill") or "").strip().lower()
    url = str(finding.get("url") or finding.get("endpoint") or "").strip().lower()
    return "|".join([title[:180], category[:120], source[:120], url[:240]])


def _finding_base_signature(finding: dict) -> str:
    if not isinstance(finding, dict):
        return ""
    title = str(finding.get("title") or "").strip().lower()
    category = str(finding.get("category") or "").strip().lower()
    source = str(finding.get("source") or finding.get("_source_skill") or "").strip().lower()
    url = str(finding.get("url") or finding.get("endpoint") or "").strip().lower()
    return "|".join([title[:180], category[:120], source[:120], url[:240]])


def _safe_findings(report: dict | None) -> list[dict]:
    if not isinstance(report, dict):
        return []
    findings = report.get("findings")
    if not isinstance(findings, list):
        return []
    return [f for f in findings if isinstance(f, dict)]


def _scan_diff(previous_report: dict, current_report: dict) -> dict:
    previous_findings = _safe_findings(previous_report)
    current_findings = _safe_findings(current_report)

    prev_by_sig = {}
    curr_by_sig = {}
    for f in previous_findings:
        sig = _finding_signature(f)
        if sig and sig not in prev_by_sig:
            prev_by_sig[sig] = f
    for f in current_findings:
        sig = _finding_signature(f)
        if sig and sig not in curr_by_sig:
            curr_by_sig[sig] = f

    prev_sigs = set(prev_by_sig.keys())
    curr_sigs = set(curr_by_sig.keys())

    new_rows = [curr_by_sig[s] for s in sorted(curr_sigs - prev_sigs)]
    fixed_rows = [prev_by_sig[s] for s in sorted(prev_sigs - curr_sigs)]

    prev_by_base = {}
    curr_by_base = {}
    for f in previous_findings:
        base = _finding_base_signature(f)
        if not base:
            continue
        rank = _severity_rank(str(f.get("severity") or ""))
        old = prev_by_base.get(base)
        if old is None or rank < _severity_rank(str(old.get("severity") or "")):
            prev_by_base[base] = f
    for f in current_findings:
        base = _finding_base_signature(f)
        if not base:
            continue
        rank = _severity_rank(str(f.get("severity") or ""))
        old = curr_by_base.get(base)
        if old is None or rank < _severity_rank(str(old.get("severity") or "")):
            curr_by_base[base] = f

    regressed = []
    improved = []
    unchanged = 0
    for base, curr in curr_by_base.items():
        prev = prev_by_base.get(base)
        if not prev:
            continue
        curr_rank = _severity_rank(str(curr.get("severity") or ""))
        prev_rank = _severity_rank(str(prev.get("severity") or ""))
        if curr_rank < prev_rank:
            regressed.append({"before": prev, "after": curr})
        elif curr_rank > prev_rank:
            improved.append({"before": prev, "after": curr})
        else:
            unchanged += 1

    return {
        "baseline_total": len(prev_by_sig),
        "current_total": len(curr_by_sig),
        "new_count": len(new_rows),
        "fixed_count": len(fixed_rows),
        "regressed_count": len(regressed),
        "improved_count": len(improved),
        "unchanged_count": unchanged,
        "new_findings": new_rows[:25],
        "fixed_findings": fixed_rows[:25],
        "regressed_findings": regressed[:25],
        "improved_findings": improved[:25],
    }


def _normalize_target_for_diff(target_url: str) -> str:
    raw = str(target_url or "").strip().lower()
    if not raw:
        return ""
    # Normalize only lightweight URL variance for matching:
    # - trim trailing slash noise
    # - collapse duplicated terminal slashes
    raw = re.sub(r"/+$", "", raw)
    return raw


def _latest_previous_report_for_target(user_id: str, target_url: str) -> dict:
    target_norm = _normalize_target_for_diff(target_url)
    if not user_id or not target_norm:
        return {}
    with _db() as conn:
        rows = conn.execute(
            """SELECT report_json, target_url
               FROM scans
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT 40""",
            (user_id,),
        ).fetchall()
    if not rows:
        return {}
    for row in rows:
        if _normalize_target_for_diff(str(row["target_url"] or "")) == target_norm:
            return _safe_report_json(row["report_json"])
    return {}


def _attach_scan_diff(result: dict, user_id: str) -> dict:
    if not isinstance(result, dict):
        return result
    prev_report = _latest_previous_report_for_target(user_id, str(result.get("target_url") or ""))
    if not prev_report:
        result["scan_diff"] = {
            "baseline_total": 0,
            "current_total": len(_safe_findings(result)),
            "new_count": len(_safe_findings(result)),
            "fixed_count": 0,
            "regressed_count": 0,
            "improved_count": 0,
            "unchanged_count": 0,
            "new_findings": _safe_findings(result)[:25],
            "fixed_findings": [],
            "regressed_findings": [],
            "improved_findings": [],
            "has_baseline": False,
        }
        return result
    diff = _scan_diff(prev_report, result)
    diff["has_baseline"] = True
    diff["baseline_scanned_at"] = prev_report.get("scanned_at")
    result["scan_diff"] = diff
    return result


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


def _audit_log(user_id: str, action: str, *, status: str = "ok", target: str = "", metadata: dict | None = None) -> None:
    meta = metadata or {}
    try:
        ip = _get_client_ip()
    except Exception:
        ip = ""
    role = ""
    org_id = ""
    if user_id:
        try:
            with _db() as conn:
                row = conn.execute("SELECT role, org_id FROM users WHERE id = ?", (user_id,)).fetchone()
                if row:
                    role = str(row["role"] or "")
                    org_id = str(row["org_id"] or "")
        except Exception:
            pass
    try:
        with _db() as conn:
            conn.execute(
                """INSERT INTO audit_log (user_id, role, org_id, action, target, status, metadata, ip, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user_id or "",
                    role,
                    org_id,
                    action[:120],
                    target[:400],
                    status[:24],
                    json.dumps(meta, default=str)[:4000],
                    ip[:80],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception:
        pass


def _cleanup_old_audit_logs() -> None:
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(7, DIVERG_AUDIT_LOG_RETENTION_DAYS))
        with _db() as conn:
            conn.execute("DELETE FROM audit_log WHERE created_at < ?", (cutoff.isoformat(),))
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


def _bearer_token_from_request() -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return ""


def _obj_to_dict(obj) -> dict:
    if isinstance(obj, dict):
        return dict(obj)
    if obj is None:
        return {}
    out = {}
    for key in dir(obj):
        if key.startswith("_"):
            continue
        try:
            val = getattr(obj, key)
        except Exception:
            continue
        if callable(val):
            continue
        out[key] = val
    return out


_privy_client_singleton = None


def _privy_client():
    global _privy_client_singleton
    if not PRIVY_ENABLED:
        return None
    if _privy_client_singleton is not None:
        return _privy_client_singleton
    try:
        from privy import PrivyAPI  # type: ignore
    except Exception as e:
        logging.getLogger("diverg.api").warning("privy sdk import failed: %s", e)
        return None
    try:
        _privy_client_singleton = PrivyAPI(app_id=PRIVY_APP_ID, app_secret=PRIVY_APP_SECRET)
        return _privy_client_singleton
    except Exception as e:
        logging.getLogger("diverg.api").warning("privy client init failed: %s", e)
        return None


def _verify_privy_access_token(access_token: str) -> dict | None:
    if not access_token or not PRIVY_ENABLED:
        return None
    client = _privy_client()
    if client is None:
        return None
    try:
        claims = client.users.verify_access_token(access_token)  # type: ignore[attr-defined]
    except Exception:
        return None
    c = _obj_to_dict(claims)
    did = (
        c.get("user_id")
        or c.get("userId")
        or c.get("sub")
        or c.get("did")
    )
    if not isinstance(did, str) or not did.strip():
        return None
    c["did"] = did.strip()
    return c


def _get_or_create_privy_user(claims: dict, *, referral_code: str = "") -> dict | None:
    did = str(claims.get("did") or "").strip()
    if not did:
        return None
    email_local = re.sub(r"[^a-zA-Z0-9_.-]+", "_", did)[:120]
    default_email = f"{email_local}@privy.local"
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        row = conn.execute(
            "SELECT id, email, name, role, org_id, provider, avatar_url, created_at FROM users WHERE id = ?",
            (did,),
        ).fetchone()
        if not row:
            conn.execute(
                """
                INSERT INTO users (id, email, name, role, org_id, password, provider, avatar_url, created_at)
                VALUES (?, ?, ?, 'analyst', '', NULL, 'privy', '', ?)
                """,
                (did, default_email, "Privy User", now),
            )
            try:
                from dashboard_points import apply_referral_on_register

                apply_referral_on_register(conn, did, referral_code or "")
            except Exception:
                pass
        else:
            if (row["provider"] or "") != "privy":
                conn.execute("UPDATE users SET provider = 'privy' WHERE id = ?", (did,))
        try:
            from dashboard_points import ensure_user_points_row

            ensure_user_points_row(conn, did)
            _credits_module().ensure_user_credits_row(conn, did)
        except Exception:
            pass
        row2 = conn.execute(
            "SELECT id, email, name, role, org_id, provider, avatar_url, created_at FROM users WHERE id = ?",
            (did,),
        ).fetchone()
    return dict(row2) if row2 else None


def get_current_user():
    token = _bearer_token_from_request()
    if not token or len(token) > 4096:
        return None
    payload = decode_token(token)
    if payload:
        try:
            with _db() as conn:
                row = conn.execute(
                    "SELECT id, email, name, role, org_id, provider, avatar_url, created_at FROM users WHERE id = ?",
                    (payload["sub"],),
                ).fetchone()
            user = dict(row) if row else None
            if user:
                user["_auth_source"] = "diverg_jwt"
            return user
        except sqlite3.Error as e:
            logging.getLogger("diverg.api").warning("get_current_user db error: %s", e)
            return None
    privy_claims = _verify_privy_access_token(token)
    if not privy_claims:
        return None
    user = _get_or_create_privy_user(privy_claims)
    if user:
        user["_auth_source"] = "privy_access_token"
    return user


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        g.user = user
        return f(*args, **kwargs)
    return decorated


def require_role(*allowed_roles):
    allowed = {str(r).strip().lower() for r in allowed_roles if str(r).strip()}

    def _decorator(f):
        @wraps(f)
        def _wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            role = str(user.get("role") or "analyst").lower()
            if allowed and role not in allowed:
                return jsonify({"error": "Forbidden for role", "required_roles": sorted(allowed)}), 403
            g.user = user
            return f(*args, **kwargs)
        return _wrapped

    return _decorator


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
    elif (
        origin.startswith("chrome-extension://")
        and (os.environ.get("DIVERG_ALLOW_EXTENSION_CORS") or "").strip().lower() in ("1", "true", "yes")
    ):
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
    # JSON API must be readable from the Chrome extension origin when CORS is enabled.
    if request.path.startswith("/api/"):
        resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    else:
        resp.headers["Cross-Origin-Resource-Policy"] = "same-site"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    connect_src = "'self' https://mainnet.helius-rpc.com https://auth.privy.io https://api.privy.io"
    if not IS_PRODUCTION:
        connect_src += " http://127.0.0.1:*"
    # Cloudflare Web Analytics injects beacon on proxied pages; allow or browser console shows CSP noise.
    script_src = "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com"
    if IS_PRODUCTION:
        script_src += " https://static.cloudflareinsights.com"
    csp = (
        "default-src 'self'; "
        f"script-src {script_src}; "
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
    role = sanitize_text(data.get("role") or "analyst", 32).lower()
    if role not in {"owner", "admin", "analyst", "viewer", "api_client"}:
        role = "analyst"
    org_id = sanitize_text(data.get("org_id") or "", 120)
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
            "INSERT INTO users (id, email, name, role, org_id, password, provider, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (user_id, email, name or email.split("@")[0], role, org_id, hash_password(password), "email",
             datetime.now(timezone.utc).isoformat()),
        )
        from dashboard_points import apply_referral_on_register, ensure_user_points_row

        ensure_user_points_row(conn, user_id)
        _credits_module().ensure_user_credits_row(conn, user_id)
        apply_referral_on_register(conn, user_id, referral_raw)

    token = create_token(user_id, email)
    _audit_log(user_id, "auth.register", target=email, metadata={"role": role, "org_id": org_id})
    return jsonify({
        "token": token,
        "user": {"id": user_id, "email": email, "name": name or email.split("@")[0], "provider": "email", "role": role, "org_id": org_id},
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
        row = conn.execute("SELECT id, email, name, role, org_id, password, provider, avatar_url FROM users WHERE email = ?",
                           (email,)).fetchone()

    if not row:
        # Burn CPU to prevent timing-based user enumeration
        bcrypt.hashpw(b"dummy_timing_pad", bcrypt.gensalt(rounds=12))
        _audit_log("", "auth.login", status="failed", target=email, metadata={"reason": "email_not_found"})
        return jsonify({"error": "Invalid credentials"}), 401

    user = dict(row)

    if not user.get("password"):
        # Don't reveal auth method — same generic error
        bcrypt.hashpw(b"dummy_timing_pad", bcrypt.gensalt(rounds=12))
        _audit_log(user.get("id") or "", "auth.login", status="failed", target=email, metadata={"reason": "provider_mismatch"})
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password(password, user["password"]):
        _audit_log(user.get("id") or "", "auth.login", status="failed", target=email, metadata={"reason": "bad_password"})
        return jsonify({"error": "Invalid credentials"}), 401

    auth_limiter.clear(ip)
    with _db() as conn:
        from dashboard_points import ensure_user_points_row

        ensure_user_points_row(conn, user["id"])
        _credits_module().ensure_user_credits_row(conn, user["id"])
    token = create_token(user["id"], user["email"])
    _audit_log(user["id"], "auth.login", target=email, metadata={"role": user.get("role", "analyst")})
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "provider": user["provider"],
                 "avatar_url": user.get("avatar_url", ""), "role": user.get("role", "analyst"), "org_id": user.get("org_id", "")},
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
        verify_url = "https://www.googleapis.com/oauth2/v3/userinfo"
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
        existing = conn.execute("SELECT id, email, name, role, org_id, provider, avatar_url FROM users WHERE email = ?",
                                (email,)).fetchone()
        from dashboard_points import apply_referral_on_register, ensure_user_points_row

        if existing:
            user = dict(existing)
            conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar, user["id"]))
            ensure_user_points_row(conn, user["id"])
            _credits_module().ensure_user_credits_row(conn, user["id"])
        else:
            user_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO users (id, email, name, role, org_id, password, provider, avatar_url, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (user_id, email, name, "analyst", "", None, "google", avatar, datetime.now(timezone.utc).isoformat()),
            )
            ensure_user_points_row(conn, user_id)
            _credits_module().ensure_user_credits_row(conn, user_id)
            apply_referral_on_register(conn, user_id, referral_raw)
            user = {"id": user_id, "email": email, "name": name, "role": "analyst", "org_id": "", "provider": "google", "avatar_url": avatar}

    auth_limiter.clear(ip)
    token = create_token(user["id"], email)
    _audit_log(user["id"], "auth.google", target=email, metadata={"role": user.get("role", "analyst")})
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": email, "name": user.get("name", name),
                 "provider": "google", "avatar_url": user.get("avatar_url", avatar), "role": user.get("role", "analyst"), "org_id": user.get("org_id", "")},
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def auth_me():
    _audit_log(g.user["id"], "auth.me")
    return jsonify({"user": g.user})


@app.route("/api/auth/privy", methods=["POST", "OPTIONS"])
def auth_privy():
    if request.method == "OPTIONS":
        return "", 204
    if not PRIVY_ENABLED:
        return jsonify({"error": "Privy authentication is not enabled on this server."}), 503
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    access_token = sanitize_text(data.get("access_token") or "", 4096).strip()
    auth_mode = sanitize_text(data.get("mode") or "login", 24).strip().lower()
    if auth_mode not in ("login", "register"):
        auth_mode = "login"
    referral_code = sanitize_text(data.get("referral_code") or "", 64).strip().upper()
    if not access_token:
        return jsonify({"error": "Missing access_token"}), 400
    claims = _verify_privy_access_token(access_token)
    if not claims:
        return jsonify({"error": "Invalid Privy access token"}), 401
    user = _get_or_create_privy_user(claims, referral_code=referral_code if auth_mode == "register" else "")
    if not user:
        return jsonify({"error": "Could not resolve Privy user"}), 500
    token = create_token(user["id"], user["email"])
    _audit_log(user["id"], "auth.privy", metadata={"auth_source": "privy_access_token"})
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "email": user.get("email", ""),
            "name": user.get("name", "Privy User"),
            "provider": "privy",
            "avatar_url": user.get("avatar_url", ""),
            "role": user.get("role", "analyst"),
            "org_id": user.get("org_id", ""),
        },
    })


@app.route("/api/auth/privy/config", methods=["GET", "OPTIONS"])
def auth_privy_config():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "enabled": bool(PRIVY_ENABLED),
        "app_id": PRIVY_APP_ID if PRIVY_ENABLED else "",
        "client_id": PRIVY_CLIENT_ID if PRIVY_ENABLED else "",
    })


# ── Dashboard static files ───────────────────────────────────────────────────

DASHBOARD_DIR = ROOT / "dashboard"


@app.route("/dashboard/")
@app.route("/dashboard")
def dashboard_root():
    return send_from_directory(str(DASHBOARD_DIR), "index.html")


@app.route("/dashboard/<path:filename>")
def dashboard_static(filename):
    return send_from_directory(str(DASHBOARD_DIR), filename)


@app.route("/favicon.ico")
def dashboard_favicon():
    return send_from_directory(str(DASHBOARD_DIR), "logo.png")


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
    user_id = g.user["id"]
    scan_id = str(uuid.uuid4())
    cost = _credit_cost("web_scan")
    ok_reserve, st_reserve, _ = _reserve_scan_credits(
        user_id,
        amount=cost,
        reason="web_scan_charge",
        ref_type="scan",
        ref_id=scan_id,
        meta={"scope": scope, "target": url},
    )
    if not ok_reserve:
        return _credits_insufficient_response(st_reserve, cost)
    try:
        _audit_log(user_id, "scan.start", target=url, metadata={"scope": scope, "goal": goal or "", "scan_id": scan_id})
        result = run_web_scan(url, scope=scope, goal=goal, auth_context=auth_context)
        result = _attach_scan_diff(result, user_id)
        result = _attach_solana_security_profile_to_scan_result(result)
        save_scan(scan_id, result, scope, user_id=user_id)
        ok_finalize, st_final, err_final = _finalize_scan_credits(
            user_id,
            reason="web_scan_charge",
            ref_type="scan",
            ref_id=scan_id,
            meta={"scope": scope, "target": url},
        )
        if not ok_finalize:
            if err_final == "hold_not_found":
                return _credits_insufficient_response(st_final, cost)
            raise RuntimeError(f"credit_finalize_failed:{err_final or 'unknown'}")
        payload = {
            "id": scan_id,
            "target_url": result["target_url"],
            "findings": result["findings"],
            "scan_diagnostics": result.get("scan_diagnostics"),
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
            "proof_bundle": result.get("proof_bundle"),
            "report_provenance": result.get("report_provenance"),
            "scan_fingerprint": result.get("scan_fingerprint"),
            "scan_diff": result.get("scan_diff"),
            "solana_security_profile": result.get("solana_security_profile"),
            "credits": st_final,
            "credits_charged": cost,
        }
        _audit_log(user_id, "scan.complete", target=url, metadata={"scope": scope, "scan_id": scan_id, "findings": len(result.get("findings") or []), "credits_charged": cost})
        return jsonify(payload)
    except Exception as e:
        try:
            _release_scan_credits(user_id, ref_type="scan", ref_id=scan_id)
        except Exception:
            pass
        _audit_log(user_id, "scan.complete", status="failed", target=url, metadata={"scope": scope, "scan_id": scan_id, "error": str(e)})
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
    user_id = g.user["id"]
    cost = _credit_cost("web_scan")
    ok_reserve, st_reserve, _ = _reserve_scan_credits(
        user_id,
        amount=cost,
        reason="web_scan_charge",
        ref_type="scan",
        ref_id=scan_id,
        meta={"scope": scope, "target": url, "streaming": True},
    )
    if not ok_reserve:
        return _credits_insufficient_response(st_reserve, cost)
    _log = logging.getLogger("diverg.api")

    def _ndjson(obj: dict) -> str:
        """NDJSON line. ensure_ascii=True keeps output UTF-8-safe on the wire (e.g. lone surrogates)."""
        return json.dumps(obj, default=str, ensure_ascii=True) + "\n"

    def generate():
        accumulated = None
        try:
            _audit_log(user_id, "scan.start", target=url, metadata={"scope": scope, "streaming": True, "goal": goal or ""})
            yield _ndjson({"event": "scan_start", "id": scan_id, "url": url, "scope": scope})
            for event in run_web_scan_streaming(url, scope=scope, goal=goal, auth_context=auth_context):
                if event.get("event") == "done":
                    report = event.get("report") or {}
                    report = _attach_scan_diff(report, user_id)
                    report = _attach_solana_security_profile_to_scan_result(report)
                    report["id"] = scan_id
                    accumulated = report
                    event["report"] = report
                    event["id"] = scan_id
                try:
                    yield _ndjson(event)
                except (TypeError, ValueError) as enc_err:
                    _log.exception("scan stream encode failed: %s", enc_err)
                    yield _ndjson({"event": "error", "error": f"encode_failed: {enc_err}"})
                    break
        except Exception as e:
            _log.exception("scan stream failed: %s", e)
            yield _ndjson({"event": "error", "error": str(e)})
        finally:
            if accumulated:
                try:
                    save_scan(scan_id, accumulated, scope, user_id=user_id)
                    ok_finalize, _st, _err = _finalize_scan_credits(
                        user_id,
                        reason="web_scan_charge",
                        ref_type="scan",
                        ref_id=scan_id,
                        meta={"scope": scope, "target": url, "streaming": True},
                    )
                    if not ok_finalize:
                        raise RuntimeError(f"credit_finalize_failed:{_err or 'unknown'}")
                    _audit_log(
                        user_id,
                        "scan.complete",
                        target=url,
                        metadata={"scope": scope, "scan_id": scan_id, "streaming": True, "findings": len(accumulated.get("findings") or []), "credits_charged": cost},
                    )
                except Exception:
                    try:
                        _release_scan_credits(user_id, ref_type="scan", ref_id=scan_id)
                    except Exception:
                        pass
            else:
                try:
                    _release_scan_credits(user_id, ref_type="scan", ref_id=scan_id)
                except Exception:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/plain; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
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
        _reward_poc(g.user["id"])
    _audit_log(
        g.user["id"],
        "poc.simulate",
        target=sanitize_text(str(data.get("url") or ""), 500),
        status="ok" if result.success else "failed",
        metadata={"success": bool(result.success), "status_code": result.status_code, "poc_type": result.poc_type or data.get("type")},
    )
    return jsonify({
        "success": result.success,
        "status_code": result.status_code,
        "body_preview": result.body_preview,
        "conclusion": result.conclusion,
        "error": result.error or None,
        "poc_type": result.poc_type or None,
        "verbose": verbose,
    })


@app.route("/api/proof/replay", methods=["POST"])
@require_auth
def proof_replay():
    if not DIVERG_ENABLE_STRICT_PROOF_API:
        return jsonify({"error": "Proof replay API disabled"}), 403
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    payload = request.get_json(silent=True) or {}
    finding = payload.get("finding")
    if not isinstance(finding, dict):
        return jsonify({"error": "finding must be an object"}), 400
    try:
        from orchestrator import replay_verify_finding

        timeout_sec = _safe_int(payload.get("timeout_sec"), 10, 2, 30)
        result = replay_verify_finding(finding, timeout_sec=timeout_sec)
        _audit_log(
            g.user["id"],
            "proof.replay",
            target=sanitize_text(str(finding.get("url") or ""), 500),
            metadata={"ok": bool(result.get("ok")), "status": result.get("status", "")},
        )
        return jsonify({"replay": result})
    except Exception as exc:
        _audit_log(g.user["id"], "proof.replay", status="failed", metadata={"error": str(exc)})
        return jsonify({"error": str(exc)}), 500


@app.route("/api/findings/false-positive", methods=["POST"])
@require_role("owner", "admin", "analyst")
def mark_false_positive():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True) or {}
    finding = data.get("finding")
    if not isinstance(finding, dict):
        return jsonify({"error": "finding must be an object"}), 400
    reason = sanitize_text(str(data.get("reason") or ""), 240)
    notes = sanitize_text(str(data.get("notes") or ""), 1000)
    memory = _read_fp_memory()
    rules = memory.get("rules") if isinstance(memory.get("rules"), list) else []
    src = str(finding.get("source") or finding.get("_source_skill") or "").strip().lower()
    rule = {
        "active": True,
        "title_contains": str(finding.get("title") or "").strip().lower()[:120],
        "category_contains": str(finding.get("category") or "").strip().lower()[:120],
        "source_equals": src,
    }
    existing = any(
        isinstance(r, dict)
        and str(r.get("title_contains") or "") == rule["title_contains"]
        and str(r.get("category_contains") or "") == rule["category_contains"]
        and str(r.get("source_equals") or "") == rule["source_equals"]
        for r in rules
    )
    if not existing and rule["title_contains"]:
        rules.append(rule)
    memory["rules"] = rules[:500]
    feedback = memory.get("feedback") if isinstance(memory.get("feedback"), list) else []
    feedback.append({
        "ts": int(time.time()),
        "title": rule["title_contains"],
        "category": rule["category_contains"],
        "source": rule["source_equals"],
        "reason": reason,
        "notes": notes,
    })
    memory["feedback"] = feedback[-500:]
    _write_fp_memory(memory)
    _audit_log(
        g.user["id"],
        "finding.mark_false_positive",
        target=sanitize_text(str(finding.get("url") or ""), 500),
        metadata={
            "title": rule["title_contains"],
            "source": rule["source_equals"],
            "existing": existing,
            "reason": reason,
            "notes_len": len(notes),
        },
    )
    return jsonify({"ok": True, "rules_total": len(memory["rules"]), "added": not existing})


# ── Investigation tools (full skill / chain data for console) ─────────────────

_bundle_api_lock = Lock()
_blockchain_full_lock = Lock()

_ETH_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_EVM_CHAIN_META = {
    "ethereum": {"chainid": 1, "explorer": "https://etherscan.io", "rpc": "https://cloudflare-eth.com"},
    "bsc": {"chainid": 56, "explorer": "https://bscscan.com", "rpc": "https://bsc-rpc.publicnode.com"},
    "polygon": {"chainid": 137, "explorer": "https://polygonscan.com", "rpc": "https://polygon-bor-rpc.publicnode.com"},
    "base": {"chainid": 8453, "explorer": "https://basescan.org", "rpc": "https://base-rpc.publicnode.com"},
    "arbitrum": {"chainid": 42161, "explorer": "https://arbiscan.io", "rpc": "https://arbitrum-one-rpc.publicnode.com"},
    "optimism": {"chainid": 10, "explorer": "https://optimistic.etherscan.io", "rpc": "https://optimism-rpc.publicnode.com"},
    "avalanche": {"chainid": 43114, "explorer": "https://snowtrace.io", "rpc": "https://avalanche-c-chain-rpc.publicnode.com"},
    "linea": {"chainid": 59144, "explorer": "https://lineascan.build", "rpc": "https://linea-rpc.publicnode.com"},
    "scroll": {"chainid": 534352, "explorer": "https://scrollscan.com", "rpc": "https://scroll-rpc.publicnode.com"},
    "blast": {"chainid": 81457, "explorer": "https://blastscan.io", "rpc": "https://blast-rpc.publicnode.com"},
    "celo": {"chainid": 42220, "explorer": "https://celoscan.io", "rpc": "https://forno.celo.org"},
    "gnosis": {"chainid": 100, "explorer": "https://gnosisscan.io", "rpc": "https://rpc.gnosischain.com"},
    "fantom": {"chainid": 250, "explorer": "https://ftmscan.com", "rpc": "https://rpcapi.fantom.network"},
}

BLOCKCHAIN_FULL_HTTP_TIMEOUT_SEC = max(60, int(os.environ.get("DIVERG_BLOCKCHAIN_FULL_TIMEOUT_SEC", "120")))
BLOCKCHAIN_FULL_MAX_FINDINGS = min(500, max(40, int(os.environ.get("DIVERG_BLOCKCHAIN_FULL_MAX_FINDINGS", "120"))))
BLOCKCHAIN_FULL_MAX_FLOW_EDGES = min(300, max(40, int(os.environ.get("DIVERG_BLOCKCHAIN_FULL_MAX_FLOW_EDGES", "150"))))


def _normalize_evm_chain_slug(chain: str) -> str:
    c = (chain or "ethereum").strip().lower()
    aliases = {
        "eth": "ethereum",
        "bnb": "bsc",
        "matic": "polygon",
        "arb": "arbitrum",
        "op": "optimism",
        "avax": "avalanche",
        "xdai": "gnosis",
        "ftm": "fantom",
    }
    c = aliases.get(c, c)
    return c if c in _EVM_CHAIN_META else "ethereum"


def _truncate_blockchain_full_payload(d: dict) -> dict:
    """Cap list sizes so browser JSON stays usable."""
    out = copy.deepcopy(d)
    findings = out.get("findings")
    if isinstance(findings, list) and len(findings) > BLOCKCHAIN_FULL_MAX_FINDINGS:
        out["_truncated_findings"] = len(findings) - BLOCKCHAIN_FULL_MAX_FINDINGS
        out["findings"] = findings[:BLOCKCHAIN_FULL_MAX_FINDINGS]
    fg = out.get("flow_graph")
    if isinstance(fg, dict):
        edges = fg.get("edges")
        if isinstance(edges, list) and len(edges) > BLOCKCHAIN_FULL_MAX_FLOW_EDGES:
            fg = dict(fg)
            fg["_truncated_edges"] = len(edges) - BLOCKCHAIN_FULL_MAX_FLOW_EDGES
            fg["edges"] = edges[:BLOCKCHAIN_FULL_MAX_FLOW_EDGES]
            out["flow_graph"] = fg
    cr = out.get("crime_report")
    if isinstance(cr, dict):
        fwe = cr.get("findings_with_evidence")
        if isinstance(fwe, list) and len(fwe) > 80:
            cr = dict(cr)
            cr["findings_with_evidence"] = fwe[:80]
            out["crime_report"] = cr
    return out


def _sanitize_crypto_relation_api(val) -> str | None:
    if val is None or val is False:
        return None
    s = sanitize_text(str(val), 48).strip().lower()
    if not s or not re.match(r"^[a-z0-9][a-z0-9_-]{0,47}$", s):
        return None
    return s


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


def _evm_public_rpc(method: str, params: list, chain: str = "ethereum") -> dict:
    c = _normalize_evm_chain_slug(chain)
    rpc_url = _EVM_CHAIN_META.get(c, _EVM_CHAIN_META["ethereum"])["rpc"]
    r = requests.post(
        rpc_url,
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
    bal_wei = raw.get("etherscan_balance_wei")
    if isinstance(bal_wei, int):
        s["balance_wei"] = bal_wei
        s["eth_approx"] = round(bal_wei / 1e18, 8)
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
    etx = raw.get("etherscan_recent_txs")
    if isinstance(etx, list) and etx:
        s["etherscan_recent_tx_count"] = len(etx)
        s["etherscan_recent_tx_sample"] = [
            {
                "hash": t.get("hash"),
                "from": t.get("from"),
                "to": t.get("to"),
                "timeStamp": t.get("timeStamp"),
            }
            for t in etx[:8]
            if isinstance(t, dict)
        ]
    return s


def _etherscan_v2_txlist(address: str, chain: str = "ethereum", offset: int = 14) -> list | None:
    """Recent tx list from Etherscan v2 multichain API."""
    if not requests:
        return None
    api_key = (os.environ.get("ETHERSCAN_API_KEY") or "").strip()
    if not api_key or not _ETH_ADDR_RE.match(address):
        return None
    c = _normalize_evm_chain_slug(chain)
    chain_id = _EVM_CHAIN_META.get(c, _EVM_CHAIN_META["ethereum"])["chainid"]
    try:
        r = requests.get(
            "https://api.etherscan.io/v2/api",
            params={
                "chainid": chain_id,
                "apikey": api_key,
                "module": "account",
                "action": "txlist",
                "address": address,
                "page": 1,
                "offset": min(max(offset, 1), 30),
                "sort": "desc",
            },
            timeout=18,
        )
        j = r.json()
        if j.get("status") != "1" or not isinstance(j.get("result"), list):
            return None
        rows = []
        for t in j["result"][:offset]:
            if not isinstance(t, dict):
                continue
            rows.append(
                {
                    "hash": t.get("hash"),
                    "from": t.get("from"),
                    "to": t.get("to"),
                    "value": t.get("value"),
                    "timeStamp": t.get("timeStamp"),
                    "blockNumber": t.get("blockNumber"),
                }
            )
        return rows
    except Exception:
        return None


def _etherscan_v2_balance_wei(address: str, chain: str = "ethereum") -> int | None:
    if not requests:
        return None
    api_key = (os.environ.get("ETHERSCAN_API_KEY") or "").strip()
    if not api_key or not _ETH_ADDR_RE.match(address):
        return None
    c = _normalize_evm_chain_slug(chain)
    chain_id = _EVM_CHAIN_META.get(c, _EVM_CHAIN_META["ethereum"])["chainid"]
    try:
        r = requests.get(
            "https://api.etherscan.io/v2/api",
            params={
                "chainid": chain_id,
                "apikey": api_key,
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
            },
            timeout=18,
        )
        j = r.json()
        if j.get("status") != "1":
            return None
        return int(str(j.get("result") or "0"))
    except Exception:
        return None


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
    requested_chain = sanitize_text(data.get("chain") or "", 32).lower().strip()

    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = sanitize_text(data.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key

    out: dict = {"address": addr, "network": network}
    _attach_arkham_capabilities(out, required=False)
    if any(k in data for k in ("arkham_api_key", "arkhamKey", "arkham_key")):
        out["intelligence_notice"] = (
            "Client-supplied Arkham keys are ignored. Diverg uses a server-managed Arkham key when configured."
        )

    if _ETH_ADDR_RE.match(addr):
        evm_chain = _normalize_evm_chain_slug(requested_chain or "ethereum")
        out["chain"] = "evm"
        out["evm_chain"] = evm_chain
        try:
            raw: dict = {
                "eth_getTransactionCount": _evm_public_rpc("eth_getTransactionCount", [addr, "latest"], chain=evm_chain),
                "explorer_address_url": f"{_EVM_CHAIN_META[evm_chain]['explorer']}/address/{addr}",
            }
            bal = _etherscan_v2_balance_wei(addr, chain=evm_chain)
            if bal is not None:
                raw["etherscan_balance_wei"] = bal
            else:
                raw["eth_getBalance"] = _evm_public_rpc("eth_getBalance", [addr, "latest"], chain=evm_chain)
            etx = _etherscan_v2_txlist(addr, chain=evm_chain)
            if etx is not None:
                raw["etherscan_recent_txs"] = etx
            out["raw"] = raw
            out["summary"] = _summarize_chain_evm(raw)
        except Exception as e:
            err_out = {"error": str(e), "address": addr, "chain": "evm", "evm_chain": evm_chain}
            _attach_arkham_capabilities(err_out, required=False)
            return jsonify(err_out), 200
        _attach_arkham_intel_block(out, addr)
        _reward_investigation(g.user["id"], "blockchain")
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
        err_out = {"error": str(e), "address": addr, "chain": "solana", "raw": raw}
        _attach_arkham_capabilities(err_out, required=False)
        return jsonify(err_out), 200
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
    _attach_arkham_intel_block(out, addr)
    _reward_investigation(g.user["id"], "blockchain")
    return jsonify(out)


@app.route("/api/investigation/blockchain-full", methods=["OPTIONS"])
def investigation_blockchain_full_options():
    return "", 204


@app.route("/api/investigation/blockchain-full", methods=["POST"])
@require_auth
def investigation_blockchain_full():
    """
    Full skills.blockchain_investigation output (crime_report, flow_graph, findings).
    Uses server-side API keys only. May take up to ~2 minutes.
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    deployer = sanitize_text(data.get("deployer_address") or data.get("address") or "", 128).strip()

    tokens_raw = data.get("token_addresses")
    token_addresses: list[str] | None = None
    if isinstance(tokens_raw, list):
        token_addresses = [
            sanitize_text(str(x), 128).strip()
            for x in tokens_raw[:24]
            if x is not None and str(x).strip()
        ] or None
    elif isinstance(tokens_raw, str) and tokens_raw.strip():
        token_addresses = [
            sanitize_text(p, 128).strip()
            for p in tokens_raw.split(",")
            if p.strip()
        ][:24] or None

    if not deployer and not token_addresses:
        return jsonify({"error": "Provide address, deployer_address, or token_addresses"}), 400

    ark_miss = _arkham_env_error_response("full blockchain investigation")
    if ark_miss is not None:
        return ark_miss

    target_url = sanitize_text(data.get("target_url") or "", 2048).strip()
    chain = sanitize_text(data.get("chain") or "solana", 32).lower().strip()
    flow_depth = sanitize_text(data.get("flow_depth") or "full", 16).lower().strip()
    if flow_depth not in ("full", "deep"):
        flow_depth = "full"
    crypto_relation = _sanitize_crypto_relation_api(data.get("crypto_relation"))

    skills_path = str(ROOT / "skills")
    if skills_path not in sys.path:
        sys.path.insert(0, skills_path)

    log = logging.getLogger("diverg.api")
    log.info(
        "blockchain_full user_id=%s chain=%s deployer=%s tokens=%s",
        g.user.get("id"),
        chain,
        bool(deployer),
        len(token_addresses or ()),
    )

    def _invoke_skill() -> str:
        import blockchain_investigation as bi

        return bi.run(
            target_url=target_url,
            scan_type="full",
            deployer_address=deployer or None,
            token_addresses=token_addresses,
            chain=chain,
            crypto_relation=crypto_relation,
            flow_depth=flow_depth,
        )

    try:
        with _blockchain_full_lock:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_invoke_skill)
                raw_json = fut.result(timeout=float(BLOCKCHAIN_FULL_HTTP_TIMEOUT_SEC))
    except concurrent.futures.TimeoutError:
        log.warning("blockchain_full timeout user_id=%s", g.user.get("id"))
        return jsonify({"error": "Full investigation timed out; try flow_depth=full or a narrower target."}), 504
    except Exception as e:
        log.exception("blockchain_full failed: %s", e)
        return jsonify({"error": str(e)}), 500

    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid investigation output"}), 500

    if not isinstance(payload, dict):
        return jsonify({"error": "Unexpected investigation shape"}), 500

    payload = _truncate_blockchain_full_payload(payload)
    if isinstance(payload, dict):
        _attach_arkham_capabilities(payload, required=True)
    _reward_investigation(g.user["id"], "blockchain_full")
    try:
        return jsonify(payload)
    except TypeError:
        return Response(json.dumps(payload, default=str), mimetype="application/json")


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
        _reward_investigation(g.user["id"], "domain")
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
        _reward_investigation(g.user["id"], "reputation")
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
    fc = bs.get("funding_cluster_bridge_mixer") or {}
    fc_lines = fc.get("risk_lines") if isinstance(fc, dict) else None
    if isinstance(fc_lines, list) and fc_lines:
        extra = [str(x) for x in fc_lines[:6] if x]
        raw["risk_signals"] = list(raw["risk_signals"]) + [f"bridge_mixer: {x}" for x in extra]
    if coord_f >= 70 or (coord_f >= 45 and cp >= 20):
        verdict = "High risk"
    elif coord_f >= 40 or (coord_f >= 25 and cp >= 12):
        verdict = "Moderate"
    else:
        verdict = "Clean"
    raw["risk_verdict"] = verdict
    cw = raw["cluster_wallet_count"]
    raw["risk_summary"] = (
        f"{verdict}: {raw['risk_score']}/100 funding overlap across {cw} cluster wallet{'s' if cw != 1 else ''} "
        f"holding {cp:.2f}% of sampled supply."
    )
    ccb = raw.get("cross_chain_bundle")
    if isinstance(ccb, dict) and ccb.get("combined_escalation"):
        raw["risk_summary"] += " Cross-chain bridge and mixer funding signals detected."
    return raw


_SOLANA_SECURITY_PROGRAM_URL = "https://solana.com/news/solana-ecosystem-security"
_SOLANA_STRIDE_URL = "http://blog.asymmetric.re/introducing-stride-a-security-program-for-the-solana-ecosystem"
_SOLANA_SIRN_FORM_URL = "https://docs.google.com/forms/d/e/1FAIpQLSfwHege_H4TyJGI50hYtx-mfOmNukJyT_c9v4oO4KdOEqC1Mg/viewform"

_SOLANA_MINT_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _normalize_solana_mint(m: str) -> str:
    """Collapse whitespace (line breaks / accidental spaces in pasted mints)."""
    return re.sub(r"\s+", "", (m or "").strip())


def _is_plausible_solana_mint(m: str) -> bool:
    s = _normalize_solana_mint(m)
    return bool(s and _SOLANA_MINT_BASE58_RE.match(s))


def _solana_program_tools() -> list[dict]:
    return [
        {"name": "Hypernative", "status": "available", "url": "https://www.hypernative.io/blog/solana-network-and-projects-building-on-it-are-now-secured-by-hypernative"},
        {"name": "Range Security", "status": "available", "url": "http://docs.range.org/"},
        {"name": "Riverguard (Neodyme)", "status": "available", "url": "https://neodyme.io/de/blog/riverguard_3_fuzzcases/"},
        {"name": "Sec3 X-Ray", "status": "available", "url": "https://www.sec3.dev/x-ray"},
        {"name": "AuditWare Radar", "status": "available", "url": "https://github.com/Auditware/radar?tab=readme-ov-file#-github-action"},
    ]


def _solana_pillars_from_signals(risk_score: float, cluster_pct: float, wallet_count: int, risk_signals: list[str]) -> list[dict]:
    signals_lower = [str(x).lower() for x in (risk_signals or [])]
    suspicious_funding = any("bridge_mixer" in s or "mixer" in s for s in signals_lower)
    same_funder = any("same_" in s or "shared_" in s for s in signals_lower)

    flow_status = "needs_attention" if risk_score >= 60 or suspicious_funding else ("watch" if risk_score >= 35 else "strong")
    distribution_status = "needs_attention" if cluster_pct >= 25 else ("watch" if cluster_pct >= 12 else "strong")
    identity_status = "watch" if same_funder or wallet_count >= 4 else "strong"
    readiness_status = "needs_attention" if risk_score >= 70 else ("watch" if risk_score >= 45 else "strong")

    return [
        {
            "id": "funding_integrity",
            "label": "Funding Integrity",
            "status": flow_status,
            "confidence": "high" if risk_signals else "medium",
            "evidence": [
                f"Risk score {risk_score:.2f}/100",
                "Bridge/mixer-linked funding signals detected" if suspicious_funding else "No bridge/mixer escalation detected",
            ],
        },
        {
            "id": "holder_distribution",
            "label": "Holder Distribution Resilience",
            "status": distribution_status,
            "confidence": "high",
            "evidence": [
                f"Cluster supply concentration {cluster_pct:.2f}%",
                f"{wallet_count} wallets in focus cluster",
            ],
        },
        {
            "id": "entity_linkage",
            "label": "Entity and Linkage Traceability",
            "status": identity_status,
            "confidence": "medium",
            "evidence": [
                "Shared or same-funder linkage signals present" if same_funder else "No strong same-funder concentration detected",
                "Cross-entity attribution should be reviewed against labels and funding paths",
            ],
        },
        {
            "id": "incident_readiness",
            "label": "Incident Readiness",
            "status": readiness_status,
            "confidence": "medium",
            "evidence": [
                "Escalation runbook recommended for elevated overlap scores",
                "24/7 monitoring fit should be evaluated for high-TVL protocols",
            ],
        },
    ]


def _solana_next_actions(risk_score: float, cluster_pct: float, has_tvl: bool) -> list[dict]:
    actions = [
        {
            "priority": "high" if risk_score >= 60 else "medium",
            "action": "Run STRIDE-style control review",
            "reason": "Align protocol controls with Solana ecosystem security standards and publish transparent findings.",
        },
        {
            "priority": "high" if cluster_pct >= 20 else "medium",
            "action": "Validate concentration and funding cluster assumptions",
            "reason": "High concentration and shared-funding paths increase exploit and governance risk.",
        },
        {
            "priority": "medium",
            "action": "Define SIRN-compatible incident response workflow",
            "reason": "Predefined escalation contacts and response windows reduce blast radius during active incidents.",
        },
    ]
    if not has_tvl:
        actions.append({
            "priority": "low",
            "action": "Provide protocol TVL context",
            "reason": "TVL enables more accurate tiering for 24/7 monitoring and formal verification recommendations.",
        })
    return actions[:5]


def _build_solana_security_profile(
    *,
    risk_score: float,
    cluster_pct: float,
    wallet_count: int,
    risk_signals: list[str],
    tvl_usd: float | None,
    context: str,
) -> dict:
    monitoring_eligible = bool(tvl_usd is not None and tvl_usd >= 10_000_000)
    formal_verification_eligible = bool(tvl_usd is not None and tvl_usd >= 100_000_000)
    tier_label = (
        "formal_verification_priority"
        if formal_verification_eligible
        else "active_monitoring_priority"
        if monitoring_eligible
        else "baseline_program"
    )

    return {
        "version": "2026-04",
        "context": context,
        "references": {
            "program": _SOLANA_SECURITY_PROGRAM_URL,
            "stride": _SOLANA_STRIDE_URL,
            "sirn_request_form": _SOLANA_SIRN_FORM_URL,
        },
        "tiering": {
            "tvl_usd": tvl_usd,
            "monitoring_10m_eligible": monitoring_eligible,
            "formal_verification_100m_eligible": formal_verification_eligible,
            "tier_label": tier_label,
        },
        "pillars": _solana_pillars_from_signals(risk_score, cluster_pct, wallet_count, risk_signals),
        "incident_response": {
            "sirn_recommended": True,
            "priority_level": "high" if risk_score >= 60 else ("medium" if risk_score >= 35 else "baseline"),
            "checklist": [
                "Define emergency owner and backup responder",
                "Define first-15-minute containment actions",
                "Define exchange and ecosystem escalation contacts",
                "Run tabletop simulation for exploit and treasury compromise scenarios",
            ],
        },
        "tooling_coverage": _solana_program_tools(),
        "next_actions": _solana_next_actions(risk_score, cluster_pct, tvl_usd is not None),
        "disclaimer": "Framework guidance supports protocol decisions; it does not replace protocol-level security responsibility.",
    }


def _attach_solana_security_profile_to_bundle(raw: dict, tvl_usd: float | None = None) -> dict:
    if not isinstance(raw, dict) or not raw.get("ok"):
        return raw
    try:
        risk_score = float(raw.get("risk_score") or 0.0)
    except (TypeError, ValueError):
        risk_score = 0.0
    try:
        cluster_pct = float(raw.get("cluster_pct_supply") or 0.0)
    except (TypeError, ValueError):
        cluster_pct = 0.0
    wallet_count = int(raw.get("cluster_wallet_count") or 0)
    risk_signals = raw.get("risk_signals") if isinstance(raw.get("risk_signals"), list) else []
    raw["solana_security_profile"] = _build_solana_security_profile(
        risk_score=max(0.0, min(100.0, risk_score)),
        cluster_pct=max(0.0, cluster_pct),
        wallet_count=max(0, wallet_count),
        risk_signals=[str(x) for x in risk_signals[:25]],
        tvl_usd=tvl_usd,
        context="solana_bundle",
    )
    return raw


def _attach_solana_security_profile_to_scan_result(report: dict) -> dict:
    if not isinstance(report, dict):
        return report
    site_classification = report.get("site_classification") if isinstance(report.get("site_classification"), dict) else {}
    if not bool(site_classification.get("is_crypto")):
        return report
    try:
        risk_score = float(report.get("risk_score") or 0.0)
    except (TypeError, ValueError):
        risk_score = 0.0
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    crypto_findings = [f for f in findings if isinstance(f, dict) and "solana" in str(f.get("title") or "").lower()]
    report_signals = report.get("risk_signals")
    signals = report_signals if isinstance(report_signals, list) else []
    report["solana_security_profile"] = _build_solana_security_profile(
        risk_score=max(0.0, min(100.0, risk_score)),
        cluster_pct=0.0,
        wallet_count=max(0, len(crypto_findings)),
        risk_signals=[str(x) for x in signals[:25]],
        tvl_usd=None,
        context="scanner_crypto",
    )
    return report


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
    user_id = g.user["id"]
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    mint = _normalize_solana_mint(str(data.get("mint") or ""))[:128]
    wallet = sanitize_text(data.get("wallet") or "", 128).strip() or None
    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = sanitize_text(data.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key
    if not mint:
        return jsonify({"error": "Missing mint"}), 400
    if not _is_plausible_solana_mint(mint):
        return jsonify({"error": "Invalid Solana mint (expected base58, typically 32–44 characters)."}), 400
    if not api_key:
        return jsonify({"error": "Helius API key required. Add it in Settings or set HELIUS_API_KEY on the server."}), 400

    ark_miss = _arkham_env_error_response("Solana bundle investigation")
    if ark_miss is not None:
        return ark_miss

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

    all_raw = data.get("scan_all_holders")
    if all_raw is True or all_raw is False:
        scan_all_holders = bool(all_raw)
    elif isinstance(all_raw, str):
        scan_all_holders = all_raw.strip().lower() in ("true", "1", "yes", "on")
    else:
        scan_all_holders = False
    max_funded_by_lookups = None
    mf_raw = data.get("max_funded_by_lookups")
    if mf_raw is not None:
        try:
            max_funded_by_lookups = max(5, min(int(mf_raw), 5000))
        except (TypeError, ValueError):
            max_funded_by_lookups = None
    tvl_usd = None
    tvl_raw = data.get("tvl_usd")
    if tvl_raw is not None:
        try:
            tvl_usd = max(0.0, float(tvl_raw))
        except (TypeError, ValueError):
            tvl_usd = None

    inv_dir = ROOT / "investigation"
    inv_path = str(inv_dir)
    if inv_path not in sys.path:
        sys.path.insert(0, inv_path)

    try:
        import onchain_clients as oc  # type: ignore
        import solana_bundle as sb  # type: ignore
    except ImportError as e:
        return jsonify({"error": f"Solana bundle module unavailable: {e}"}), 503

    scan_ref_id = str(uuid.uuid4())
    scan_kind = "token_deep_scan" if scan_all_holders else "token_scan"
    cost = _credit_cost(scan_kind)
    ok_reserve, st_reserve, _ = _reserve_scan_credits(
        user_id,
        amount=cost,
        reason="token_scan_charge",
        ref_type="investigation",
        ref_id=scan_ref_id,
        meta={"scan_kind": scan_kind, "mint": mint, "scan_all_holders": bool(scan_all_holders)},
    )
    if not ok_reserve:
        return _credits_insufficient_response(st_reserve, cost)

    out = None
    try:
        with _bundle_api_lock:
            old_key = getattr(oc, "HELIUS_KEY", "") or ""
            try:
                oc.HELIUS_KEY = api_key.strip()
                out = sb.run_bundle_snapshot(
                    mint,
                    wallet,
                    max_holders=120,
                    max_funded_by_lookups=max_funded_by_lookups if max_funded_by_lookups is not None else 120,
                    scan_all_holders=scan_all_holders,
                    exclude_wallets=exclude_wallets,
                    include_x_intel=include_x_intel,
                )
            finally:
                oc.HELIUS_KEY = old_key
    except Exception as e:
        try:
            _release_scan_credits(user_id, ref_type="investigation", ref_id=scan_ref_id)
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500

    if isinstance(out, dict) and out.get("ok"):
        out = _enrich_solana_bundle_payload(out)
        out = _enrich_solana_bundle_arkham(out)
        out = _attach_solana_security_profile_to_bundle(out, tvl_usd=tvl_usd)
    payload = out if isinstance(out, dict) else {"ok": False, "error": "Unexpected response"}
    if isinstance(payload, dict) and payload.get("ok"):
        ok_finalize, st_final, err_final = _finalize_scan_credits(
            user_id,
            reason="token_scan_charge",
            ref_type="investigation",
            ref_id=scan_ref_id,
            meta={"scan_kind": scan_kind, "mint": mint, "scan_all_holders": bool(scan_all_holders)},
        )
        if not ok_finalize:
            try:
                _release_scan_credits(user_id, ref_type="investigation", ref_id=scan_ref_id)
            except Exception:
                pass
            if err_final == "hold_not_found":
                return _credits_insufficient_response(st_final, cost)
            return jsonify({"error": f"credit_finalize_failed:{err_final or 'unknown'}"}), 500
        payload["credits"] = st_final
        payload["credits_charged"] = cost
        payload["credits_scan_kind"] = scan_kind
        _reward_investigation(user_id, "solana_bundle")
    else:
        try:
            _release_scan_credits(user_id, ref_type="investigation", ref_id=scan_ref_id)
        except Exception:
            pass
    try:
        return jsonify(payload)
    except TypeError:
        return Response(
            json.dumps(payload, default=str),
            mimetype="application/json",
        )


_SOLANA_WATCHLIST_MAX = 100


@app.route("/api/solana/watchlist", methods=["GET", "POST", "PATCH", "OPTIONS"])
@require_auth
def api_solana_watchlist():
    """Per-user SPL mint watchlist for repeat checks and snapshot hooks (Solana Phase 2)."""
    if request.method == "OPTIONS":
        return "", 204
    uid = g.user["id"]
    now = datetime.now(timezone.utc).isoformat()

    if request.method == "GET":
        with _db() as conn:
            rows = conn.execute(
                """
                SELECT id, mint, label, tvl_usd, last_verdict, last_risk_score, last_checked_at, created_at, updated_at
                FROM solana_watchlist
                WHERE user_id = ?
                ORDER BY updated_at DESC
                """,
                (uid,),
            ).fetchall()
        return jsonify({"ok": True, "items": [dict(r) for r in rows]})

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}

    if request.method == "POST":
        mint = _normalize_solana_mint(str(data.get("mint") or ""))[:128]
        if not _is_plausible_solana_mint(mint):
            return jsonify({"error": "Invalid Solana mint (expected base58, typically 32–44 characters)."}), 400
        label = sanitize_text(data.get("label") or "", 200)
        tvl_usd = None
        if data.get("tvl_usd") is not None:
            try:
                tvl_usd = max(0.0, float(data.get("tvl_usd")))
            except (TypeError, ValueError):
                tvl_usd = None
        with _db() as conn:
            exists = conn.execute(
                "SELECT 1 FROM solana_watchlist WHERE user_id = ? AND mint = ?",
                (uid, mint),
            ).fetchone()
            if not exists:
                n = conn.execute(
                    "SELECT COUNT(*) FROM solana_watchlist WHERE user_id = ?",
                    (uid,),
                ).fetchone()[0]
                if int(n or 0) >= _SOLANA_WATCHLIST_MAX:
                    return jsonify({"error": "Watchlist limit reached", "max": _SOLANA_WATCHLIST_MAX}), 400
            conn.execute(
                """
                INSERT INTO solana_watchlist (
                    user_id, mint, label, tvl_usd, last_verdict, last_risk_score, last_checked_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, '', NULL, NULL, ?, ?)
                ON CONFLICT(user_id, mint) DO UPDATE SET
                    label = CASE
                        WHEN TRIM(excluded.label) != '' THEN excluded.label
                        ELSE solana_watchlist.label
                    END,
                    tvl_usd = COALESCE(excluded.tvl_usd, solana_watchlist.tvl_usd),
                    updated_at = excluded.updated_at
                """,
                (uid, mint, label, tvl_usd, now, now),
            )
            row = conn.execute(
                """
                SELECT id, mint, label, tvl_usd, last_verdict, last_risk_score, last_checked_at, created_at, updated_at
                FROM solana_watchlist WHERE user_id = ? AND mint = ?
                """,
                (uid, mint),
            ).fetchone()
        return jsonify({"ok": True, "item": dict(row) if row else None})

    if request.method == "PATCH":
        mint = _normalize_solana_mint(str(data.get("mint") or ""))[:128]
        if not mint:
            return jsonify({"error": "Missing mint"}), 400
        if not _is_plausible_solana_mint(mint):
            return jsonify({"error": "Invalid Solana mint (expected base58, typically 32–44 characters)."}), 400
        verdict = sanitize_text(
            data.get("last_verdict") or data.get("risk_verdict") or "",
            64,
        ).strip()
        score_raw = data.get("last_risk_score")
        if score_raw is None:
            score_raw = data.get("risk_score")
        rs = None
        if score_raw is not None:
            try:
                rs = float(score_raw)
            except (TypeError, ValueError):
                rs = None
        with _db() as conn:
            row0 = conn.execute(
                "SELECT id FROM solana_watchlist WHERE user_id = ? AND mint = ?",
                (uid, mint),
            ).fetchone()
            if not row0:
                return jsonify({"error": "Mint not on watchlist"}), 404
            conn.execute(
                """
                UPDATE solana_watchlist SET
                    last_verdict = ?,
                    last_risk_score = ?,
                    last_checked_at = ?,
                    updated_at = ?
                WHERE user_id = ? AND mint = ?
                """,
                (verdict or "", rs, now, now, uid, mint),
            )
            row = conn.execute(
                """
                SELECT id, mint, label, tvl_usd, last_verdict, last_risk_score, last_checked_at, created_at, updated_at
                FROM solana_watchlist WHERE user_id = ? AND mint = ?
                """,
                (uid, mint),
            ).fetchone()
        return jsonify({"ok": True, "item": dict(row) if row else None})

    return jsonify({"error": "Method not allowed"}), 405


@app.route("/api/solana/watchlist/<int:watch_id>", methods=["DELETE", "OPTIONS"])
@require_auth
def api_solana_watchlist_delete(watch_id: int):
    if request.method == "OPTIONS":
        return "", 204
    uid = g.user["id"]
    with _db() as conn:
        cur = conn.execute(
            "DELETE FROM solana_watchlist WHERE id = ? AND user_id = ?",
            (watch_id, uid),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


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


# ── Credits ───────────────────────────────────────────────────────────────────


@app.route("/api/credits/me", methods=["GET", "OPTIONS"])
@require_auth
def credits_me():
    if request.method == "OPTIONS":
        return "", 204
    uid = g.user["id"]
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cm = _credits_module()
        cm.ensure_user_credits_row(conn, uid)
        state = cm.ensure_daily_credit_state(conn, uid)
        ledger = cm.recent_credit_ledger(conn, uid, limit=20)
        token_bal = float(state.get("token_balance_ui") or 0.0)
        next_grant = cm.daily_grant_total(token_bal)
    return jsonify({
        "mint": DIVERG_HOLDER_MINT,
        "base_daily_credits": cm.base_daily_credits(),
        "tokens_per_step": cm.tokens_per_step(),
        "credits_per_step": cm.credits_per_step(),
        "costs": {
            "web_scan": cm.scan_cost("web_scan"),
            "token_scan": cm.scan_cost("token_scan"),
            "token_deep_scan": cm.scan_cost("token_deep_scan"),
        },
        "state": state,
        "next_daily_grant_total": next_grant,
        "next_reset_at": cm.next_reset_iso(),
        "recent_ledger": ledger,
    })


@app.route("/api/credits/wallet/challenge", methods=["POST", "OPTIONS"])
@require_auth
def credits_wallet_challenge():
    if request.method == "OPTIONS":
        return "", 204
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    wallet = _sanitize_wallet_address(str(data.get("wallet_address") or ""))
    cm = _credits_module()
    if not cm.validate_wallet_address(wallet):
        return jsonify({"error": "Invalid Solana wallet address"}), 400
    uid = g.user["id"]
    now = datetime.now(timezone.utc)
    nonce = secrets.token_hex(16)
    msg = (
        "Diverg wallet link\n"
        f"User: {uid}\n"
        f"Wallet: {wallet}\n"
        f"Nonce: {nonce}\n"
        f"IssuedAt: {now.isoformat()}"
    )
    expires_at = (now + timedelta(seconds=DIVERG_WALLET_CHALLENGE_TTL_SEC)).isoformat()
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO wallet_link_challenges (user_id, wallet_address, nonce, message, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                wallet_address = excluded.wallet_address,
                nonce = excluded.nonce,
                message = excluded.message,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at
            """,
            (uid, wallet, nonce, msg, expires_at, now.isoformat()),
        )
    return jsonify({"wallet_address": wallet, "nonce": nonce, "message": msg, "expires_at": expires_at})


@app.route("/api/credits/wallet/link", methods=["POST", "OPTIONS"])
@require_auth
def credits_wallet_link():
    if request.method == "OPTIONS":
        return "", 204
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    data = request.get_json(silent=True) or {}
    uid = g.user["id"]
    wallet = _sanitize_wallet_address(str(data.get("wallet_address") or ""))
    nonce = sanitize_text(str(data.get("nonce") or ""), 128).strip()
    signature = sanitize_text(str(data.get("signature") or ""), 1024).strip()
    signature_base64 = sanitize_text(str(data.get("signature_base64") or ""), 4096).strip()
    signature_hex = sanitize_text(str(data.get("signature_hex") or ""), 4096).strip()
    signature_bytes = data.get("signature_bytes")
    if not isinstance(signature_bytes, list):
        signature_bytes = None
    cm = _credits_module()
    if not cm.validate_wallet_address(wallet):
        return jsonify({"error": "Invalid Solana wallet address"}), 400
    if not nonce or not (signature or signature_base64 or signature_hex or signature_bytes):
        return jsonify({"error": "Missing nonce/signature"}), 400
    with _db() as conn:
        ch = conn.execute(
            "SELECT wallet_address, nonce, message, expires_at FROM wallet_link_challenges WHERE user_id = ?",
            (uid,),
        ).fetchone()
    if not ch:
        return jsonify({"error": "Challenge not found. Request a new challenge."}), 400
    if str(ch["wallet_address"] or "") != wallet or str(ch["nonce"] or "") != nonce:
        return jsonify({"error": "Challenge mismatch"}), 400
    try:
        expires = datetime.fromisoformat(str(ch["expires_at"]))
    except Exception:
        expires = datetime.now(timezone.utc) - timedelta(seconds=1)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        return jsonify({"error": "Challenge expired. Request a new challenge."}), 400
    msg = str(ch["message"] or "")
    if not _verify_wallet_signature(
        wallet,
        msg,
        signature_b58=signature or None,
        signature_base64=signature_base64 or None,
        signature_hex=signature_hex or None,
        signature_bytes=signature_bytes,
    ):
        return jsonify({"error": "Invalid wallet signature"}), 401

    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = sanitize_text(data.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key
    if not api_key:
        return jsonify({"error": "Helius API key required to verify token holdings."}), 400
    balance_ui, bal_err = _fetch_diverg_holder_balance(wallet, api_key)
    if bal_err:
        return jsonify({"error": f"Failed to fetch token balance: {bal_err}"}), 502

    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cm.ensure_user_credits_row(conn, uid)
        state = cm.refresh_wallet_and_grant(
            conn,
            uid,
            wallet_address=wallet,
            token_balance_ui=balance_ui,
            mark_verified=True,
        )
        conn.execute("DELETE FROM wallet_link_challenges WHERE user_id = ?", (uid,))
        ledger = cm.recent_credit_ledger(conn, uid, limit=20)
    return jsonify({
        "ok": True,
        "mint": DIVERG_HOLDER_MINT,
        "token_balance_ui": balance_ui,
        "state": state,
        "next_daily_grant_total": cm.daily_grant_total(balance_ui),
        "next_reset_at": cm.next_reset_iso(),
        "recent_ledger": ledger,
    })


@app.route("/api/credits/wallet/refresh", methods=["POST", "OPTIONS"])
@require_auth
def credits_wallet_refresh():
    if request.method == "OPTIONS":
        return "", 204
    uid = g.user["id"]
    env_key = (os.environ.get("HELIUS_API_KEY") or "").strip()
    body_key = ""
    if request.is_json:
        body = request.get_json(silent=True) or {}
        body_key = sanitize_text(body.get("helius_api_key") or "", 256).strip()
    api_key = body_key or env_key
    if not api_key:
        return jsonify({"error": "Helius API key required to refresh token holdings."}), 400
    with _db() as conn:
        row = conn.execute("SELECT wallet_address FROM user_credits WHERE user_id = ?", (uid,)).fetchone()
    wallet = str((row["wallet_address"] if row else "") or "").strip()
    if not wallet:
        return jsonify({"error": "No wallet linked"}), 400
    balance_ui, bal_err = _fetch_diverg_holder_balance(wallet, api_key)
    if bal_err:
        return jsonify({"error": f"Failed to fetch token balance: {bal_err}"}), 502
    cm = _credits_module()
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        state = cm.refresh_wallet_and_grant(
            conn,
            uid,
            wallet_address=wallet,
            token_balance_ui=balance_ui,
            mark_verified=False,
        )
        ledger = cm.recent_credit_ledger(conn, uid, limit=20)
    return jsonify({
        "ok": True,
        "mint": DIVERG_HOLDER_MINT,
        "token_balance_ui": balance_ui,
        "state": state,
        "next_daily_grant_total": cm.daily_grant_total(balance_ui),
        "next_reset_at": cm.next_reset_iso(),
        "recent_ledger": ledger,
    })


# ── History endpoints ─────────────────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
@require_auth
def history_list():
    limit = _safe_int(request.args.get("limit"), 50, 1, 200)
    offset = _safe_int(request.args.get("offset"), 0, 0, 999999)
    user_id = g.user["id"]

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
    _audit_log(user["id"], "history.bulk_delete", metadata={"deleted_count": len(deleted_ids)})
    return jsonify({"deleted_count": len(deleted_ids), "deleted_ids": deleted_ids[:500]})


def _safe_report_json(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _read_fp_memory() -> dict:
    try:
        if not FP_MEMORY_PATH.exists():
            return {"version": "v1", "description": "Persistent suppressions for known false-positive patterns.", "rules": []}
        raw = FP_MEMORY_PATH.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            rules = parsed.get("rules")
            if not isinstance(rules, list):
                parsed["rules"] = []
            return parsed
    except Exception:
        pass
    return {"version": "v1", "description": "Persistent suppressions for known false-positive patterns.", "rules": []}


def _write_fp_memory(payload: dict) -> None:
    FP_MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    FP_MEMORY_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


@app.route("/api/analytics/summary", methods=["GET"])
@require_auth
def analytics_summary():
    user_id = g.user["id"]
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
    filtered_total = 0
    proof_bundle_total = 0
    replay_candidate_total = 0
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
        filtered_total += int(rep.get("filtered_out_total") or 0)
        proof_blob = rep.get("proof_bundle") if isinstance(rep.get("proof_bundle"), dict) else {}
        proof_bundle_total += int(proof_blob.get("total_bundles") or 0)
        replay_candidate_total += int(proof_blob.get("replay_candidates") or 0)
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
        "strict_findings_total": sum(severity.values()),
        "filtered_signals_total": filtered_total,
        "proof_bundle_total": proof_bundle_total,
        "proof_replay_candidates": replay_candidate_total,
    })


@app.route("/api/kpi/program", methods=["GET"])
@require_role("owner", "admin", "analyst")
def program_kpi():
    user_id = g.user["id"]
    limit = _safe_int(request.args.get("limit"), 60, 10, 365)
    with _db() as conn:
        rows = conn.execute(
            """SELECT report_json, created_at
               FROM scans WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    scans = [dict(r) for r in rows]
    strict_total = 0
    filtered_total = 0
    verified_total = 0
    replay_candidates = 0
    replay_confirmed = 0
    diag_errors = 0
    for scan in scans:
        report = _safe_report_json(scan.get("report_json"))
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        strict_total += len(findings)
        filtered_total += int(report.get("filtered_out_total") or 0)
        verified_total += sum(1 for f in findings if isinstance(f, dict) and f.get("verified"))
        proof = report.get("proof_bundle") if isinstance(report.get("proof_bundle"), dict) else {}
        replay_candidates += int(proof.get("replay_candidates") or 0)
        diagnostics = report.get("scan_diagnostics") if isinstance(report.get("scan_diagnostics"), list) else []
        diag_errors += sum(1 for d in diagnostics if isinstance(d, dict) and str(d.get("level") or "").lower() == "error")
        for b in (proof.get("bundles") or []):
            if isinstance(b, dict) and b.get("verified"):
                replay_confirmed += 1
    precision = round((verified_total / strict_total), 3) if strict_total else 0.0
    replay_rate = round((replay_confirmed / replay_candidates), 3) if replay_candidates else 0.0
    return jsonify({
        "strategy": {"option": "C", "enterprise_weight": 70, "offensive_weight": 30},
        "window_scans": len(scans),
        "strict_findings": strict_total,
        "filtered_signals": filtered_total,
        "verified_findings": verified_total,
        "strict_precision": precision,
        "replay_candidates": replay_candidates,
        "replay_confirmed": replay_confirmed,
        "replay_confirmation_rate": replay_rate,
        "diagnostic_errors": diag_errors,
        "recommended_review": "weekly",
    })


@app.route("/api/findings", methods=["GET"])
@require_auth
def findings_list():
    user_id = g.user["id"]
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
    user_id = g.user["id"]
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
                           (scan_id, g.user["id"])).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    data = dict(row)
    if data.get("report_json"):
        data["report"] = json.loads(data.pop("report_json"))
    else:
        data.pop("report_json", None)
    data.pop("user_id", None)
    _audit_log(g.user["id"], "history.get", target=scan_id)
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
    _audit_log(user["id"], "history.delete", target=scan_id)
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
                     (label, scan_id, g.user["id"]))
    _audit_log(g.user["id"], "history.patch", target=scan_id, metadata={"label": label})
    return jsonify({"id": scan_id, "label": label})


@app.route("/api/audit/logs", methods=["GET"])
@require_role("owner", "admin")
def audit_logs_list():
    limit = _safe_int(request.args.get("limit"), 100, 1, 500)
    offset = _safe_int(request.args.get("offset"), 0, 0, 1000000)
    org_scope = str(g.user.get("org_id") or "").strip()
    q = """
        SELECT id, user_id, role, org_id, action, target, status, metadata, ip, created_at
        FROM audit_log
        WHERE (? = '' OR org_id = ? OR user_id = ?)
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    with _db() as conn:
        rows = conn.execute(q, (org_scope, org_scope, g.user["id"], limit, offset)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["metadata"] = _safe_report_json(item.get("metadata"))
        items.append(item)
    _audit_log(g.user["id"], "audit.logs.list")
    return jsonify({"total": len(items), "limit": limit, "offset": offset, "items": items})


# ── Stats endpoint ────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@require_auth
def stats():
    user_id = g.user["id"]
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
    arkham_status = _arkham_capabilities(required=True)
    try:
        with _db() as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        pass
    # Optional runtime probe so ops can detect degraded Arkham connectivity quickly.
    if DIVERG_HEALTH_ARKHAM_PROBE:
        try:
            import arkham_intel as ai  # type: ignore
            probe = ai.arkham_runtime_status(requests.Session() if requests else None)
            arkham_status = {
                **arkham_status,
                "runtime_reachable": bool(probe.get("reachable")),
                "runtime_configured": bool(probe.get("configured")),
            }
            if "latency_ms" in probe:
                arkham_status["runtime_latency_ms"] = probe.get("latency_ms")
            if probe.get("error"):
                arkham_status["runtime_error"] = str(probe.get("error"))
        except Exception:
            pass
    return jsonify({
        "status": "ok",
        "service": "diverg-console",
        "version": "2.3",
        "db_path": str(DB_PATH) if not IS_PRODUCTION else "",
        "db_exists": DB_PATH.exists(),
        "users": user_count if not IS_PRODUCTION else None,
        "program_strategy": {"option": "C", "enterprise_weight": 70, "offensive_weight": 30},
        "audit_retention_days": DIVERG_AUDIT_LOG_RETENTION_DAYS,
        "arkham": arkham_status,
    })


# ── Catch-all redirect to login ──────────────────────────────────────────────

@app.route("/")
def root_redirect():
    from flask import redirect
    return redirect("/login")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Diverg Console API")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")))
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    print(f"  Diverg Console  →  http://{args.host}:{args.port}/dashboard/")
    print(f"  Login           →  http://{args.host}:{args.port}/login")
    print(f"  API             →  http://{args.host}:{args.port}/api/health")
    if not DIVERG_JWT_SECRET:
        if IS_PRODUCTION:
            print("  Warning         →  DIVERG_JWT_SECRET not set; new random JWT secret each start (logins invalid after restart).")
        else:
            print("  Note            →  DIVERG_JWT_SECRET not set; dev JWT key stored in data/.jwt_secret (stable across restarts).")
    if DIVERG_REQUIRE_ARKHAM and not (os.environ.get("ARKHAM_API_KEY") or "").strip():
        print("  Fatal           →  ARKHAM_API_KEY is required but missing (DIVERG_REQUIRE_ARKHAM=1).")
        sys.exit(1)
    if not (os.environ.get("ARKHAM_API_KEY") or "").strip():
        print("  Warning         →  ARKHAM_API_KEY not set; token-bundle / some intel endpoints will return 503 until set.")
    _cleanup_old_audit_logs()

    def _port_in_use_hint(exc: OSError) -> None:
        if exc.errno != errno.EADDRINUSE and getattr(exc, "winerror", None) != 10048:
            return
        print("  Fatal           →  That port is already in use (another app is bound there).")
        print("                  →  macOS: System Settings → General → AirPlay Receiver can take port 5000.")
        print("                  →  Try:  PORT=5001 python3 api_server.py   or   python3 api_server.py --port 5001")

    try:
        from waitress import serve
        try:
            w_threads = int(os.environ.get("WAITRESS_THREADS", "16"))
        except ValueError:
            w_threads = 16
        w_threads = max(4, min(w_threads, 32))
        print(f"  Server          →  waitress on {args.host}:{args.port} (threads={w_threads})")
        try:
            serve(app, host=args.host, port=args.port, threads=w_threads, channel_timeout=300)
        except OSError as e:
            _port_in_use_hint(e)
            raise
    except ImportError:
        print("  Server          →  Flask dev (waitress not installed)")
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.server_version = "Diverg"
        WSGIRequestHandler.sys_version = ""
        try:
            app.run(host=args.host, port=args.port, threaded=True)
        except OSError as e:
            _port_in_use_hint(e)
            raise


if __name__ == "__main__":
    main()
