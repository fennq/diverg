"""Unit tests for points ledger hardening (no server required)."""
from __future__ import annotations

import os
import sqlite3
import unittest
from unittest.mock import patch

import dashboard_points as dp

_POINTS_SCHEMA = """
CREATE TABLE user_points (
    user_id TEXT PRIMARY KEY,
    balance INTEGER NOT NULL DEFAULT 0,
    referral_code TEXT UNIQUE,
    referred_by TEXT,
    updated_at TEXT
);
CREATE TABLE points_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL,
    ref_type TEXT,
    ref_id TEXT,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_points_ledger_idem
    ON points_ledger (user_id, reason, IFNULL(ref_type,''), ref_id)
    WHERE ref_id IS NOT NULL;
CREATE TABLE referral_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id TEXT NOT NULL,
    referee_id TEXT NOT NULL UNIQUE,
    credited_at TEXT NOT NULL
);
"""


class TestDashboardPointsSecurity(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_POINTS_SCHEMA)

    def tearDown(self):
        self.conn.close()

    def test_negative_delta_rejected(self):
        dp.ensure_user_points_row(self.conn, "u1")
        ok = dp.award_points(self.conn, "u1", -100, "scan_complete", "scan", "550e8400-e29b-41d4-a716-446655440000")
        self.assertFalse(ok)
        bal = self.conn.execute("SELECT balance FROM user_points WHERE user_id=?", ("u1",)).fetchone()[0]
        self.assertEqual(bal, 0)

    def test_invalid_reason_rejected(self):
        dp.ensure_user_points_row(self.conn, "u1")
        ok = dp.award_points(self.conn, "u1", 10, "Scan_Complete", "scan", "550e8400-e29b-41d4-a716-446655440000")
        self.assertFalse(ok)

    def test_invalid_ref_id_rejected(self):
        dp.ensure_user_points_row(self.conn, "u1")
        ok = dp.award_points(self.conn, "u1", 10, "scan_complete", "scan", "../../etc/passwd")
        self.assertFalse(ok)

    def test_scan_idempotent(self):
        sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        dp.ensure_user_points_row(self.conn, "u1")
        self.assertTrue(dp.award_points(self.conn, "u1", 10, "scan_complete", "scan", sid))
        self.assertFalse(dp.award_points(self.conn, "u1", 10, "scan_complete", "scan", sid))
        bal = self.conn.execute("SELECT balance FROM user_points WHERE user_id=?", ("u1",)).fetchone()[0]
        self.assertEqual(bal, 10)

    def test_daily_investigation_cap(self):
        with patch.dict(os.environ, {"DIVERG_POINTS_DAILY_INVESTIGATION_CAP": "5", "DIVERG_POINTS_INV_BLOCKCHAIN": "2"}):
            dp.ensure_user_points_row(self.conn, "u1")
            self.assertTrue(dp.try_award_investigation_or_poc(self.conn, "u1", "investigation_blockchain", dp.investigation_delta("blockchain")))
            self.assertTrue(dp.try_award_investigation_or_poc(self.conn, "u1", "investigation_blockchain", dp.investigation_delta("blockchain")))
            self.assertFalse(dp.try_award_investigation_or_poc(self.conn, "u1", "investigation_blockchain", dp.investigation_delta("blockchain")))
        bal = self.conn.execute("SELECT balance FROM user_points WHERE user_id=?", ("u1",)).fetchone()[0]
        self.assertEqual(bal, 4)

    def test_referral_self_blocked(self):
        dp.ensure_user_points_row(self.conn, "same")
        code = self.conn.execute("SELECT referral_code FROM user_points WHERE user_id=?", ("same",)).fetchone()[0]
        dp.apply_referral_on_register(self.conn, "same", code)
        ref = self.conn.execute("SELECT referred_by FROM user_points WHERE user_id=?", ("same",)).fetchone()[0]
        self.assertIsNone(ref)

    def test_normalize_referral_truncation(self):
        long_garbage = "A" * 500 + "B" * 500
        out = dp.normalize_referral_code(long_garbage)
        self.assertLessEqual(len(out), 64)

    def test_max_per_award_clamp(self):
        with patch.dict(os.environ, {"DIVERG_POINTS_MAX_PER_AWARD": "7"}):
            self.assertEqual(dp.clamp_award_delta(999), 7)
            self.assertEqual(dp.clamp_award_delta(-1), 0)


if __name__ == "__main__":
    unittest.main()
