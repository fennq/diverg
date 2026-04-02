"""
Points, referrals, and leaderboard helpers (SQLite). Used by api_server.

Security: all credits are server-side only; deltas are clamped and validated;
ledger reasons/refs are sanitized to prevent abuse or oversized rows.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta

# ── Config (env) ───────────────────────────────────────────────────────────

# Hard ceiling for any single award (misconfigured env cannot grant huge scores).
_HARD_MAX_PER_AWARD = 500

# Max length for referral input before normalization (DoS / garbage).
_MAX_REFERRAL_INPUT_LEN = 64

_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REF_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_REF_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")


def _int_env(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)).strip())
    except ValueError:
        return default


def _clamp_config_int(val: int, lo: int, hi: int) -> int:
    return max(lo, min(val, hi))


def max_points_per_award() -> int:
    return _clamp_config_int(_int_env("DIVERG_POINTS_MAX_PER_AWARD", 120), 1, _HARD_MAX_PER_AWARD)


def clamp_award_delta(delta: int) -> int:
    """Non-negative, capped per-award; negative or zero after clamp → caller should skip."""
    if delta < 0:
        return 0
    return min(delta, max_points_per_award())


def _sanitize_reason(reason: str) -> str | None:
    if not reason or not _REASON_RE.match(reason):
        return None
    return reason


def _sanitize_ref_type(ref_type: str | None) -> str | None:
    if ref_type is None:
        return None
    if not _REF_TYPE_RE.match(ref_type):
        return None
    return ref_type


def _sanitize_ref_id(ref_id: str | None) -> str | None:
    if ref_id is None:
        return None
    s = str(ref_id)[:128]
    if not _REF_ID_RE.match(s):
        return None
    return s


def points_for_scan_scope(scope: str) -> int:
    env_key = f"DIVERG_POINTS_SCAN_{scope.upper().replace('-', '_')}"
    if (os.environ.get(env_key) or "").strip():
        return clamp_award_delta(_int_env(env_key, 15))
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
    return clamp_award_delta(defaults.get((scope or "full").lower(), 15))


def investigation_delta(reason_key: str) -> int:
    return clamp_award_delta(_int_env(f"DIVERG_POINTS_INV_{reason_key.upper()}", 3))


def daily_investigation_cap() -> int:
    return _clamp_config_int(_int_env("DIVERG_POINTS_DAILY_INVESTIGATION_CAP", 30), 1, 500)


def referral_signup_referrer() -> int:
    return clamp_award_delta(_int_env("DIVERG_POINTS_REFERRAL_SIGNUP_REFERRER", 50))


def referral_signup_referee() -> int:
    return clamp_award_delta(_int_env("DIVERG_POINTS_REFERRAL_SIGNUP_REFEREE", 25))


def referral_first_scan_referrer() -> int:
    return clamp_award_delta(_int_env("DIVERG_POINTS_REFERRAL_FIRST_SCAN_REFERRER", 15))

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
    reason_s = _sanitize_reason(reason)
    if not reason_s:
        return False
    ref_type_s = _sanitize_ref_type(ref_type)
    if ref_type is not None and ref_type_s is None:
        return False
    ref_id_s = _sanitize_ref_id(ref_id)
    if ref_id is not None and ref_id_s is None:
        return False
    delta = clamp_award_delta(delta)
    if delta <= 0:
        return False
    if not user_id or len(str(user_id)) > 64:
        return False
    ensure_user_points_row(conn, user_id)
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """INSERT INTO points_ledger (user_id, delta, reason, ref_type, ref_id, created_at)
               VALUES (?,?,?,?,?,?)""",
            (user_id, delta, reason_s, ref_type_s, ref_id_s, now),
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
    delta = clamp_award_delta(delta)
    if delta <= 0:
        return False
    current = _investigation_points_today(conn, user_id)
    if current + delta > daily_investigation_cap():
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
    bonus = referral_first_scan_referrer()
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


def points_for_watch_run(scope: str) -> int:
    """Points awarded for each CTM watch run (lower than manual scans)."""
    env_key = f"DIVERG_POINTS_WATCH_{scope.upper().replace('-', '_')}"
    if (os.environ.get(env_key) or "").strip():
        return clamp_award_delta(_int_env(env_key, 5))
    defaults = {
        "full": 8,
        "quick": 4,
        "crypto": 6,
        "recon": 4,
        "web": 6,
        "api": 6,
        "passive": 4,
        "attack": 8,
    }
    return clamp_award_delta(defaults.get((scope or "quick").lower(), 5))


def award_watch_run_points(
    conn: sqlite3.Connection,
    user_id: str,
    run_id: str,
    scope: str,
) -> None:
    """Award points for a CTM watch run. Uses the watch_run ref_type for idempotency."""
    if not user_id:
        return
    ensure_user_points_row(conn, user_id)
    pts = points_for_watch_run(scope)
    award_points(conn, user_id, pts, "watch_run", "watch_run", run_id)


def normalize_referral_code(raw: str | None) -> str:
    if not raw:
        return ""
    s = str(raw).strip()[:_MAX_REFERRAL_INPUT_LEN]
    return "".join(c for c in s.upper() if c in REFERRAL_CODE_ALPHABET)


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
    r_ref = referral_signup_referrer()
    if r_ref > 0:
        award_points(
            conn,
            referrer_id,
            r_ref,
            "referral_signup_referrer",
            "referral",
            referee_id,
        )
    r_fee = referral_signup_referee()
    if r_fee > 0:
        award_points(
            conn,
            referee_id,
            r_fee,
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
