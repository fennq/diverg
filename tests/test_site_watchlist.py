"""Tests for per-user site watchlist, last-scan sync, and alert stub audit."""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def test_canonical_site_watchlist_url() -> None:
    import api_server as srv

    d, n = srv._canonical_site_watchlist_url("Example.com/foo/")
    assert "example.com" in d.lower()
    assert "/foo" in d
    assert n == srv._normalize_target_for_diff(d)

    d2, n2 = srv._canonical_site_watchlist_url("https://a.example.com")
    assert d2.startswith("https://")
    assert n2 == srv._normalize_target_for_diff(d2)


def test_bump_site_watchlist_updates_row() -> None:
    import api_server as srv

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(srv.SCHEMA)
    now = "2026-01-01T00:00:00+00:00"
    conn.execute(
        """INSERT INTO site_watchlist (
            user_id, target_norm, display_url, label, alert_pref,
            last_scan_id, last_scanned_at, last_risk_score, last_risk_verdict, last_critical, last_high,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'off', NULL, NULL, NULL, '', 0, 0, ?, ?)""",
        ("u1", "https://t.example", "https://t.example", "t1", now, now),
    )
    conn.commit()
    result = {
        "target_url": "https://t.example",
        "scanned_at": "2026-01-02T12:00:00+00:00",
        "risk_score": 72.5,
        "risk_verdict": "Fair",
        "findings": [
            {"severity": "Critical", "title": "x"},
            {"severity": "High", "title": "y"},
            {"severity": "High", "title": "z"},
        ],
    }
    srv._bump_site_watchlist_for_scan(conn, "u1", "scan-abc", result)
    conn.commit()
    row = conn.execute("SELECT * FROM site_watchlist WHERE user_id = ?", ("u1",)).fetchone()
    assert row["last_scan_id"] == "scan-abc"
    assert row["last_risk_verdict"] == "Fair"
    assert abs(float(row["last_risk_score"]) - 72.5) < 0.01
    assert row["last_critical"] == 1
    assert row["last_high"] == 2


def test_bump_site_watchlist_stub_audits(monkeypatch: pytest.MonkeyPatch) -> None:
    import api_server as srv

    audit_calls: list[tuple] = []

    def _fake_audit(uid: str, action: str, **kwargs) -> None:
        audit_calls.append((uid, action, kwargs))

    monkeypatch.setattr(srv, "_audit_log", _fake_audit)

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(srv.SCHEMA)
    now = "2026-01-01T00:00:00+00:00"
    conn.execute(
        """INSERT INTO site_watchlist (
            user_id, target_norm, display_url, label, alert_pref,
            last_scan_id, last_scanned_at, last_risk_score, last_risk_verdict, last_critical, last_high,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'stub', NULL, NULL, NULL, '', 0, 0, ?, ?)""",
        ("u2", "https://stub.example", "https://stub.example", "s", now, now),
    )
    conn.commit()
    result = {
        "target_url": "https://stub.example",
        "scanned_at": "2026-01-03T00:00:00+00:00",
        "risk_verdict": "Poor",
        "risk_score": 40,
        "findings": [],
    }
    srv._bump_site_watchlist_for_scan(conn, "u2", "scan-stub", result)
    conn.commit()
    assert len(audit_calls) == 1
    assert audit_calls[0][0] == "u2"
    assert audit_calls[0][1] == "site_watchlist.alert_stub"
    meta = audit_calls[0][2].get("metadata") or {}
    assert meta.get("scan_id") == "scan-stub"
