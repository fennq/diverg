"""Unit tests for daily credits ledger and scan charge flows."""
from __future__ import annotations

import sqlite3
import unittest

import credits


_CREDITS_SCHEMA = """
CREATE TABLE user_credits (
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
CREATE TABLE credit_ledger (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    delta      REAL NOT NULL,
    reason     TEXT NOT NULL,
    ref_type   TEXT,
    ref_id     TEXT,
    meta_json  TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE credit_holds (
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
CREATE TABLE wallet_link_challenges (
    user_id        TEXT PRIMARY KEY,
    wallet_address TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    message        TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_credit_ledger_idem
  ON credit_ledger (user_id, reason, IFNULL(ref_type,''), ref_id)
  WHERE ref_id IS NOT NULL;
"""


class TestCreditsSystem(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_CREDITS_SCHEMA)
        self.uid = "user-1"

    def tearDown(self) -> None:
        self.conn.close()

    def test_holder_bonus_rounding(self) -> None:
        self.assertEqual(credits.holder_bonus(99_999), 0.0)
        self.assertEqual(credits.holder_bonus(100_000), 20.0)
        self.assertEqual(credits.holder_bonus(300_000), 60.0)
        self.assertEqual(credits.daily_grant_total(300_000), 65.0)

    def test_daily_reset_happens_once_per_bucket(self) -> None:
        credits.ensure_user_credits_row(self.conn, self.uid)
        self.conn.execute(
            "UPDATE user_credits SET daily_bucket_date = ?, token_balance_ui = ? WHERE user_id = ?",
            ("2000-01-01", 300000, self.uid),
        )
        st1 = credits.ensure_daily_credit_state(self.conn, self.uid)
        st2 = credits.ensure_daily_credit_state(self.conn, self.uid)
        self.assertEqual(st1["daily_grant_total"], 65.0)
        self.assertEqual(st2["daily_grant_total"], 65.0)
        self.assertEqual(st1["daily_bucket_date"], st2["daily_bucket_date"])

    def test_reserve_finalize_and_idempotent_hold(self) -> None:
        credits.ensure_daily_credit_state(self.conn, self.uid)
        ok1, st1, err1 = credits.reserve_credits(
            self.conn, self.uid, 2.0, reason="web_scan_charge", ref_type="scan", ref_id="scan-1"
        )
        self.assertTrue(ok1)
        self.assertIsNone(err1)
        self.assertEqual(st1["credits_locked"], 2.0)

        ok2, st2, err2 = credits.reserve_credits(
            self.conn, self.uid, 2.0, reason="web_scan_charge", ref_type="scan", ref_id="scan-1"
        )
        self.assertTrue(ok2)
        self.assertIsNone(err2)
        self.assertEqual(st2["credits_locked"], 2.0)

        ok3, st3, err3 = credits.finalize_reserved_credits(
            self.conn, self.uid, reason="web_scan_charge", ref_type="scan", ref_id="scan-1"
        )
        self.assertTrue(ok3)
        self.assertIsNone(err3)
        self.assertEqual(st3["credits_spent_today"], 2.0)
        self.assertEqual(st3["credits_locked"], 0.0)
        self.assertEqual(st3["credits_remaining"], 3.0)

    def test_insufficient_credits_cannot_overdraw(self) -> None:
        credits.ensure_daily_credit_state(self.conn, self.uid)
        ok1, _st1, _ = credits.reserve_credits(
            self.conn, self.uid, 3.5, reason="token_scan_charge", ref_type="investigation", ref_id="inv-1"
        )
        self.assertTrue(ok1)
        ok2, st2, err2 = credits.reserve_credits(
            self.conn, self.uid, 2.0, reason="web_scan_charge", ref_type="scan", ref_id="scan-2"
        )
        self.assertFalse(ok2)
        self.assertEqual(err2, "insufficient_credits")
        self.assertLess(st2["credits_available"], 2.0)

    def test_wallet_refresh_updates_single_wallet_state(self) -> None:
        credits.ensure_daily_credit_state(self.conn, self.uid)
        wa1 = "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy"
        wa2 = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        st1 = credits.refresh_wallet_and_grant(
            self.conn, self.uid, wallet_address=wa1, token_balance_ui=300000, mark_verified=True
        )
        self.assertEqual(st1["wallet_address"], wa1)
        self.assertEqual(st1["daily_grant_total"], 65.0)
        credits.reserve_credits(
            self.conn, self.uid, 2.0, reason="token_scan_charge", ref_type="investigation", ref_id="inv-2"
        )
        credits.finalize_reserved_credits(
            self.conn, self.uid, reason="token_scan_charge", ref_type="investigation", ref_id="inv-2"
        )
        st2 = credits.refresh_wallet_and_grant(
            self.conn, self.uid, wallet_address=wa2, token_balance_ui=0, mark_verified=True
        )
        self.assertEqual(st2["wallet_address"], wa2)
        self.assertEqual(st2["daily_grant_total"], 5.0)
        self.assertEqual(st2["credits_spent_today"], 2.0)
        self.assertEqual(st2["credits_remaining"], 3.0)


if __name__ == "__main__":
    unittest.main()
