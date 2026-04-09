"""
Daily scan credits ledger for Diverg users.

This module is intentionally separate from dashboard_points.py so referral/points
logic remains untouched while scan billing evolves independently.
"""
from __future__ import annotations

import math
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REF_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_REF_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")
_WALLET_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

DEFAULT_BASE_DAILY_CREDITS = 5.0
DEFAULT_TOKENS_PER_STEP = 100_000.0
DEFAULT_CREDITS_PER_STEP = 20.0

SCAN_COST_WEB = 2.0
SCAN_COST_TOKEN = 2.0
SCAN_COST_TOKEN_DEEP = 3.5


def _float_env(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def base_daily_credits() -> float:
    return max(0.0, min(_float_env("DIVERG_CREDITS_BASE_DAILY", DEFAULT_BASE_DAILY_CREDITS), 10_000.0))


def tokens_per_step() -> float:
    return max(1.0, min(_float_env("DIVERG_CREDITS_TOKENS_PER_STEP", DEFAULT_TOKENS_PER_STEP), 10_000_000_000.0))


def credits_per_step() -> float:
    return max(0.0, min(_float_env("DIVERG_CREDITS_PER_STEP", DEFAULT_CREDITS_PER_STEP), 10_000.0))


def holder_bonus(token_balance_ui: float) -> float:
    bal = max(0.0, float(token_balance_ui or 0.0))
    steps = math.floor(bal / tokens_per_step())
    return float(steps) * credits_per_step()


def daily_grant_total(token_balance_ui: float) -> float:
    return round(base_daily_credits() + holder_bonus(token_balance_ui), 6)


def scan_cost(scan_kind: str) -> float:
    kind = (scan_kind or "").strip().lower()
    if kind == "token_deep_scan":
        return SCAN_COST_TOKEN_DEEP
    if kind == "token_scan":
        return SCAN_COST_TOKEN
    return SCAN_COST_WEB


def utc_day_string(now: datetime | None = None) -> str:
    dt = now or datetime.now(timezone.utc)
    return dt.date().isoformat()


def next_reset_iso(now: datetime | None = None) -> str:
    dt = now or datetime.now(timezone.utc)
    tomorrow = (dt + timedelta(days=1)).date().isoformat()
    return f"{tomorrow}T00:00:00+00:00"


def validate_wallet_address(address: str) -> bool:
    return bool(address and _WALLET_RE.match(address))


def _sanitize_reason(reason: str) -> str | None:
    if not reason:
        return None
    s = str(reason).strip().lower()
    return s if _REASON_RE.match(s) else None


def _sanitize_ref_type(ref_type: str | None) -> str | None:
    if ref_type is None:
        return None
    s = str(ref_type).strip().lower()
    return s if _REF_TYPE_RE.match(s) else None


def _sanitize_ref_id(ref_id: str | None) -> str | None:
    if ref_id is None:
        return None
    s = str(ref_id).strip()[:128]
    return s if _REF_ID_RE.match(s) else None


def _state_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if not row:
        return {}
    remaining = float(row["credits_remaining"] or 0.0)
    locked = float(row["credits_locked"] or 0.0)
    available = max(0.0, remaining - locked)
    return {
        "daily_bucket_date": row["daily_bucket_date"] or utc_day_string(),
        "daily_grant_total": float(row["daily_grant_total"] or 0.0),
        "credits_remaining": remaining,
        "credits_locked": locked,
        "credits_available": available,
        "credits_spent_today": float(row["credits_spent_today"] or 0.0),
        "token_balance_ui": float(row["token_balance_ui"] or 0.0),
        "wallet_address": row["wallet_address"] or "",
        "wallet_verified_at": row["wallet_verified_at"] or "",
    }


def ensure_user_credits_row(conn: sqlite3.Connection, user_id: str) -> None:
    if not user_id:
        return
    now = datetime.now(timezone.utc).isoformat()
    day = utc_day_string()
    grant = daily_grant_total(0.0)
    conn.execute(
        """
        INSERT OR IGNORE INTO user_credits (
            user_id, wallet_address, wallet_verified_at,
            daily_bucket_date, daily_grant_total, credits_remaining, credits_locked, credits_spent_today,
            token_balance_ui, updated_at
        )
        VALUES (?, '', '', ?, ?, ?, 0, 0, 0, ?)
        """,
        (user_id, day, grant, grant, now),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO credit_ledger
            (user_id, delta, reason, ref_type, ref_id, meta_json, created_at)
        VALUES (?, ?, 'daily_grant', 'daily', ?, '{}', ?)
        """,
        (user_id, grant, day, now),
    )


def _recompute_remaining(grant: float, spent: float, locked: float) -> float:
    target = max(0.0, float(grant) - float(spent))
    if target < float(locked):
        target = float(locked)
    return round(target, 6)


def ensure_daily_credit_state(conn: sqlite3.Connection, user_id: str) -> dict[str, Any]:
    ensure_user_credits_row(conn, user_id)
    row = conn.execute("SELECT * FROM user_credits WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        return {}
    today = utc_day_string()
    if str(row["daily_bucket_date"] or "") != today:
        now = datetime.now(timezone.utc).isoformat()
        token_balance = float(row["token_balance_ui"] or 0.0)
        grant = daily_grant_total(token_balance)
        conn.execute(
            """
            UPDATE user_credits
               SET daily_bucket_date = ?,
                   daily_grant_total = ?,
                   credits_remaining = ?,
                   credits_locked = 0,
                   credits_spent_today = 0,
                   updated_at = ?
             WHERE user_id = ?
            """,
            (today, grant, grant, now, user_id),
        )
        conn.execute("DELETE FROM credit_holds WHERE user_id = ?", (user_id,))
        conn.execute(
            """
            INSERT OR IGNORE INTO credit_ledger
                (user_id, delta, reason, ref_type, ref_id, meta_json, created_at)
            VALUES (?, ?, 'daily_grant', 'daily', ?, '{}', ?)
            """,
            (user_id, grant, today, now),
        )
        row = conn.execute("SELECT * FROM user_credits WHERE user_id = ?", (user_id,)).fetchone()
    return _state_dict(row)


def refresh_wallet_and_grant(
    conn: sqlite3.Connection,
    user_id: str,
    *,
    wallet_address: str | None,
    token_balance_ui: float,
    mark_verified: bool = False,
) -> dict[str, Any]:
    st = ensure_daily_credit_state(conn, user_id)
    if not st:
        return {}
    now = datetime.now(timezone.utc).isoformat()
    wa = (wallet_address or "").strip()
    if wa and not validate_wallet_address(wa):
        raise ValueError("Invalid wallet address")
    if not wa:
        wa = ""

    row = conn.execute("SELECT * FROM user_credits WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        return {}

    grant = daily_grant_total(token_balance_ui)
    spent = float(row["credits_spent_today"] or 0.0)
    locked = float(row["credits_locked"] or 0.0)
    remaining = _recompute_remaining(grant, spent, locked)
    verified_at = now if mark_verified and wa else (row["wallet_verified_at"] or "")
    conn.execute(
        """
        UPDATE user_credits
           SET wallet_address = ?,
               wallet_verified_at = ?,
               token_balance_ui = ?,
               daily_grant_total = ?,
               credits_remaining = ?,
               updated_at = ?
         WHERE user_id = ?
        """,
        (wa, verified_at, max(0.0, float(token_balance_ui or 0.0)), grant, remaining, now, user_id),
    )
    row2 = conn.execute("SELECT * FROM user_credits WHERE user_id = ?", (user_id,)).fetchone()
    return _state_dict(row2)


def reserve_credits(
    conn: sqlite3.Connection,
    user_id: str,
    amount: float,
    *,
    reason: str,
    ref_type: str,
    ref_id: str,
    meta_json: str = "{}",
) -> tuple[bool, dict[str, Any], str | None]:
    amount = round(max(0.0, float(amount or 0.0)), 6)
    if amount <= 0:
        return False, {}, "invalid_amount"
    reason_s = _sanitize_reason(reason)
    ref_type_s = _sanitize_ref_type(ref_type)
    ref_id_s = _sanitize_ref_id(ref_id)
    if not reason_s or not ref_type_s or not ref_id_s:
        return False, {}, "invalid_reference"

    ensure_daily_credit_state(conn, user_id)
    existing = conn.execute(
        "SELECT amount FROM credit_holds WHERE user_id = ? AND ref_type = ? AND ref_id = ?",
        (user_id, ref_type_s, ref_id_s),
    ).fetchone()
    if existing:
        state = ensure_daily_credit_state(conn, user_id)
        return True, state, None

    cur = conn.execute(
        """
        UPDATE user_credits
           SET credits_locked = credits_locked + ?, updated_at = ?
         WHERE user_id = ?
           AND (credits_remaining - credits_locked) >= ?
        """,
        (amount, datetime.now(timezone.utc).isoformat(), user_id, amount),
    )
    if cur.rowcount == 0:
        st = ensure_daily_credit_state(conn, user_id)
        return False, st, "insufficient_credits"
    nonce = secrets.token_hex(8)
    conn.execute(
        """
        INSERT INTO credit_holds (user_id, ref_type, ref_id, amount, reason, meta_json, nonce, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, ref_type_s, ref_id_s, amount, reason_s, meta_json[:1000], nonce, datetime.now(timezone.utc).isoformat()),
    )
    st = ensure_daily_credit_state(conn, user_id)
    return True, st, None


def finalize_reserved_credits(
    conn: sqlite3.Connection,
    user_id: str,
    *,
    reason: str,
    ref_type: str,
    ref_id: str,
    meta_json: str = "{}",
) -> tuple[bool, dict[str, Any], str | None]:
    reason_s = _sanitize_reason(reason)
    ref_type_s = _sanitize_ref_type(ref_type)
    ref_id_s = _sanitize_ref_id(ref_id)
    if not reason_s or not ref_type_s or not ref_id_s:
        return False, {}, "invalid_reference"
    ensure_daily_credit_state(conn, user_id)
    hold = conn.execute(
        "SELECT amount FROM credit_holds WHERE user_id = ? AND ref_type = ? AND ref_id = ?",
        (user_id, ref_type_s, ref_id_s),
    ).fetchone()
    if not hold:
        st = ensure_daily_credit_state(conn, user_id)
        return False, st, "hold_not_found"
    amount = round(max(0.0, float(hold["amount"] or 0.0)), 6)
    if amount <= 0:
        release_reserved_credits(conn, user_id, ref_type=ref_type_s, ref_id=ref_id_s)
        st = ensure_daily_credit_state(conn, user_id)
        return False, st, "invalid_hold_amount"

    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            """
            INSERT INTO credit_ledger
                (user_id, delta, reason, ref_type, ref_id, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, -amount, reason_s, ref_type_s, ref_id_s, meta_json[:1000], now),
        )
    except sqlite3.IntegrityError:
        # Idempotent duplicate finalize.
        release_reserved_credits(conn, user_id, ref_type=ref_type_s, ref_id=ref_id_s)
        st = ensure_daily_credit_state(conn, user_id)
        return True, st, None

    conn.execute(
        """
        UPDATE user_credits
           SET credits_spent_today = credits_spent_today + ?,
               credits_locked = CASE WHEN credits_locked >= ? THEN credits_locked - ? ELSE 0 END,
               credits_remaining = CASE WHEN credits_remaining >= ? THEN credits_remaining - ? ELSE 0 END,
               updated_at = ?
         WHERE user_id = ?
        """,
        (amount, amount, amount, amount, amount, now, user_id),
    )
    conn.execute(
        "DELETE FROM credit_holds WHERE user_id = ? AND ref_type = ? AND ref_id = ?",
        (user_id, ref_type_s, ref_id_s),
    )
    st = ensure_daily_credit_state(conn, user_id)
    return True, st, None


def release_reserved_credits(conn: sqlite3.Connection, user_id: str, *, ref_type: str, ref_id: str) -> dict[str, Any]:
    ref_type_s = _sanitize_ref_type(ref_type)
    ref_id_s = _sanitize_ref_id(ref_id)
    if not ref_type_s or not ref_id_s:
        return ensure_daily_credit_state(conn, user_id)
    hold = conn.execute(
        "SELECT amount FROM credit_holds WHERE user_id = ? AND ref_type = ? AND ref_id = ?",
        (user_id, ref_type_s, ref_id_s),
    ).fetchone()
    if not hold:
        return ensure_daily_credit_state(conn, user_id)
    amount = round(max(0.0, float(hold["amount"] or 0.0)), 6)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        UPDATE user_credits
           SET credits_locked = CASE WHEN credits_locked >= ? THEN credits_locked - ? ELSE 0 END,
               updated_at = ?
         WHERE user_id = ?
        """,
        (amount, amount, now, user_id),
    )
    conn.execute(
        "DELETE FROM credit_holds WHERE user_id = ? AND ref_type = ? AND ref_id = ?",
        (user_id, ref_type_s, ref_id_s),
    )
    return ensure_daily_credit_state(conn, user_id)


def recent_credit_ledger(conn: sqlite3.Connection, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
    lim = max(1, min(int(limit), 100))
    rows = conn.execute(
        """
        SELECT delta, reason, ref_type, ref_id, meta_json, created_at
          FROM credit_ledger
         WHERE user_id = ?
         ORDER BY id DESC
         LIMIT ?
        """,
        (user_id, lim),
    ).fetchall()
    return [dict(r) for r in rows]
