"""
Points, referrals, and leaderboard helpers (SQLite). Used by api_server.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta

# ── Config (env) ───────────────────────────────────────────────────────────


def _int_env(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)).strip())
    except ValueError:
        return default


def points_for_scan_scope(scope: str) -> int:
    env_key = f"DIVERG_POINTS_SCAN_{scope.upper().replace('-', '_')}"
    if (os.environ.get(env_key) or "").strip():
        return _int_env(env_key, 15)
    defaults = {
        "full": 20,
        "quick": 10,
        "crypto": 15,
        "recon": 12,
        "web": 15,
        "api": 15,
        "passive": 10,
        "attack": 18,
    }
    return defaults.get((scope or "full").lower(), 15)


def investigation_delta(reason_key: str) -> int:
    return _int_env(f"DIVERG_POINTS_INV_{reason_key.upper()}", 3)


DAILY_INVESTIGATION_CAP = _int_env("DIVERG_POINTS_DAILY_INVESTIGATION_CAP", 30)

REFERRAL_SIGNUP_REFERRER = _int_env("DIVERG_POINTS_REFERRAL_SIGNUP_REFERRER", 50)
REFERRAL_SIGNUP_REFEREE = _int_env("DIVERG_POINTS_REFERRAL_SIGNUP_REFEREE", 25)
REFERRAL_FIRST_SCAN_REFERRER = _int_env("DIVERG_POINTS_REFERRAL_FIRST_SCAN_REFERRER", 15)

REFERRAL_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_referral_code() -> str:
    return "".join(secrets.choice(REFERRAL_CODE_ALPHABET) for _ in range(8))


def ensure_user_points_row(conn: sqlite3.Connection, user_id: str) -> None:
    row = conn.execute("SELECT 1 FROM user_points WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return
    now = datetime.now(timezone.utc).isoformat()
    for _ in range(32):
        code = generate_referral_code()
        try:
            conn.execute(
                """INSERT INTO user_points (user_id, balance, referral_code, referred_by, updated_at)
                   VALUES (?,?,?,?,?)""",
                (user_id, 0, code, None, now),
            )
            return
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("Could not allocate unique referral_code")


def award_points(
    conn: sqlite3.Connection,
    user_id: str,
    delta: int,
    reason: str,
    ref_type: str | None = None,
    ref_id: str | None = None,
) -> bool:
    if delta == 0:
        return False
    ensure_user_points_row(conn, user_id)
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """INSERT INTO points_ledger (user_id, delta, reason, ref_type, ref_id, created_at)
               VALUES (?,?,?,?,?,?)""",
            (user_id, delta, reason, ref_type, ref_id, now),
        )
    except sqlite3.IntegrityError:
        return False
    conn.execute(
        "UPDATE user_points SET balance = balance + ?, updated_at = ? WHERE user_id = ?",
        (delta, now, user_id),
    )
    return True


def _investigation_points_today(conn: sqlite3.Connection, user_id: str) -> int:
    day = datetime.now(timezone.utc).date().isoformat()
    row = conn.execute(
        """SELECT COALESCE(SUM(delta), 0) FROM points_ledger
           WHERE user_id = ?
             AND substr(created_at, 1, 10) = ?
             AND (reason LIKE 'investigation_%' OR reason = 'poc_simulate')""",
        (user_id, day),
    ).fetchone()
    return int(row[0] or 0)


def try_award_investigation_or_poc(
    conn: sqlite3.Connection,
    user_id: str,
    reason: str,
    delta: int,
) -> bool:
    if delta <= 0:
        return False
    current = _investigation_points_today(conn, user_id)
    if current + delta > DAILY_INVESTIGATION_CAP:
        return False
    ref_id = secrets.token_hex(16)
    return award_points(conn, user_id, delta, reason, ref_type="activity", ref_id=ref_id)


def award_scan_points(conn: sqlite3.Connection, user_id: str, scan_id: str, scope: str) -> None:
    if not user_id:
        return
    ensure_user_points_row(conn, user_id)
    pts = points_for_scan_scope(scope)
    if award_points(conn, user_id, pts, "scan_complete", "scan", scan_id):
        _maybe_referrer_first_scan_bonus(conn, user_id)


def _maybe_referrer_first_scan_bonus(conn: sqlite3.Connection, referee_id: str) -> None:
    row = conn.execute(
        "SELECT referred_by FROM user_points WHERE user_id = ?", (referee_id,)
    ).fetchone()
    if not row or not row[0]:
        return
    referrer_id = row[0]
    if referrer_id == referee_id:
        return
    bonus = REFERRAL_FIRST_SCAN_REFERRER
    if bonus <= 0:
        return
    award_points(
        conn,
        referrer_id,
        bonus,
        "referral_first_scan",
        "referral",
        referee_id,
    )


def normalize_referral_code(raw: str | None) -> str:
    if not raw:
        return ""
    return "".join(c for c in raw.strip().upper() if c in REFERRAL_CODE_ALPHABET)


def lookup_referrer_id(conn: sqlite3.Connection, code: str) -> str | None:
    if not code:
        return None
    row = conn.execute(
        "SELECT user_id FROM user_points WHERE referral_code = ?", (code,)
    ).fetchone()
    return row[0] if row else None


def apply_referral_on_register(
    conn: sqlite3.Connection,
    referee_id: str,
    referral_code: str,
) -> None:
    """Set referred_by and credit signup bonuses (same transaction as user insert)."""
    code = normalize_referral_code(referral_code)
    if not code:
        return
    referrer_id = lookup_referrer_id(conn, code)
    if not referrer_id or referrer_id == referee_id:
        return
    ensure_user_points_row(conn, referee_id)
    cur = conn.execute(
        "SELECT referred_by FROM user_points WHERE user_id = ?", (referee_id,)
    ).fetchone()
    if cur and cur[0]:
        return
    now = datetime.now(timezone.utc).isoformat()
    ins = conn.execute(
        "INSERT OR IGNORE INTO referral_events (referrer_id, referee_id, credited_at) VALUES (?,?,?)",
        (referrer_id, referee_id, now),
    )
    if ins.rowcount == 0:
        return
    conn.execute(
        "UPDATE user_points SET referred_by = ?, updated_at = ? WHERE user_id = ?",
        (referrer_id, now, referee_id),
    )
    if REFERRAL_SIGNUP_REFERRER > 0:
        award_points(
            conn,
            referrer_id,
            REFERRAL_SIGNUP_REFERRER,
            "referral_signup_referrer",
            "referral",
            referee_id,
        )
    if REFERRAL_SIGNUP_REFEREE > 0:
        award_points(
            conn,
            referee_id,
            REFERRAL_SIGNUP_REFEREE,
            "referral_signup_referee",
            "referral",
            referrer_id,
        )


def privacy_display_name(name: str | None, email: str | None) -> str:
    n = (name or "").strip()
    if n:
        return n[:80]
    em = (email or "").strip().lower()
    if not em or "@" not in em:
        return "User"
    local, _, domain = em.partition("@")
    if not local:
        return "User"
    d0 = (domain[:1] or "?").upper()
    return f"{local}@{d0}…"


def leaderboard_since_iso(window: str) -> str | None:
    if window == "all":
        return None
    if window == "30d":
        days = 30
    elif window == "7d":
        days = 7
    else:
        days = 30
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
