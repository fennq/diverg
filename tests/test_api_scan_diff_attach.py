"""Tests for api_server scan diff attachment, scope-aware baseline, and verification_summary."""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def test_build_scan_diff_verification_summary_first_run() -> None:
    import api_server as srv

    d = {
        "current_total": 3,
        "new_count": 3,
        "fixed_count": 0,
        "regressed_count": 0,
        "improved_count": 0,
        "fixed_findings": [],
    }
    vs = srv._build_scan_diff_verification_summary(
        d, has_baseline=False, baseline_meta={"current_scope": "full"},
    )
    assert vs["strict_baseline_total"] == 0
    assert vs["strict_current_total"] == 3
    assert vs["verified_fixed_count"] == 0
    assert "baseline" in vs["one_line"].lower()


def test_build_scan_diff_verification_summary_with_fixed_verified() -> None:
    import api_server as srv

    d = {
        "baseline_total": 2,
        "current_total": 1,
        "new_count": 0,
        "fixed_count": 1,
        "regressed_count": 0,
        "improved_count": 0,
        "fixed_findings": [{"title": "X", "verified": True, "severity": "High"}],
    }
    vs = srv._build_scan_diff_verification_summary(
        d,
        has_baseline=True,
        baseline_meta={"baseline_scope_match": True, "baseline_scope": "full", "current_scope": "full"},
    )
    assert vs["strict_baseline_total"] == 2
    assert vs["verified_fixed_count"] == 1
    assert "no longer present" in vs["one_line"].lower()


def test_build_scan_diff_verification_summary_scope_mismatch_note() -> None:
    import api_server as srv

    d = {
        "baseline_total": 1,
        "current_total": 1,
        "new_count": 0,
        "fixed_count": 0,
        "regressed_count": 0,
        "improved_count": 0,
        "fixed_findings": [],
    }
    vs = srv._build_scan_diff_verification_summary(
        d,
        has_baseline=True,
        baseline_meta={
            "baseline_scope_match": False,
            "baseline_scope": "quick",
            "current_scope": "full",
        },
    )
    assert vs["baseline_scope_match"] is False
    assert "quick" in vs["one_line"]
    assert "full" in vs["one_line"]


def test_scan_diff_new_fixed_improved_regressed() -> None:
    import api_server as srv

    prev = {
        "scanned_at": "2026-01-01T00:00:00Z",
        "findings": [
            {
                "title": "A",
                "category": "c1",
                "source": "s1",
                "url": "https://x.com/a",
                "severity": "High",
            },
            {
                "title": "B",
                "category": "c2",
                "source": "s2",
                "url": "https://x.com/b",
                "severity": "Medium",
            },
        ],
    }
    curr = {
        "scanned_at": "2026-01-02T00:00:00Z",
        "findings": [
            {
                "title": "A",
                "category": "c1",
                "source": "s1",
                "url": "https://x.com/a",
                "severity": "Critical",
            },
            {
                "title": "C",
                "category": "c3",
                "source": "s3",
                "url": "https://x.com/c",
                "severity": "Low",
            },
        ],
    }
    diff = srv._scan_diff(prev, curr)
    assert diff["new_count"] == 1
    assert diff["fixed_count"] == 1
    assert (diff["improved_count"] + diff["regressed_count"]) >= 1


def test_attach_scan_diff_picks_same_scope_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    import api_server as srv

    full_report = {
        "target_url": "https://example.com",
        "scanned_at": "t1",
        "findings": [{"title": "OldFull", "category": "c", "source": "s", "url": "https://example.com/x", "severity": "High"}],
    }
    quick_report = {
        "target_url": "https://example.com/",
        "scanned_at": "t0",
        "findings": [{"title": "OldQuick", "category": "c", "source": "s", "url": "https://example.com/q", "severity": "Low"}],
    }

    rows = [
        {"report_json": json.dumps(full_report), "target_url": "https://example.com", "scope": "full"},
        {"report_json": json.dumps(quick_report), "target_url": "https://example.com", "scope": "quick"},
    ]

    class _Row:
        def __init__(self, d):
            self._d = d

        def __getitem__(self, k):
            return self._d[k]

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, *args, **kwargs):
            return self

        def fetchall(self):
            return [_Row(r) for r in rows]

    monkeypatch.setattr(srv, "_db", lambda: _Conn())

    current = {
        "target_url": "https://example.com",
        "scanned_at": "t2",
        "findings": [],
    }
    out = srv._attach_scan_diff(dict(current), str(uuid.uuid4()), scope="full")
    diff = out["scan_diff"]
    assert diff.get("has_baseline") is True
    assert diff["verification_summary"]["baseline_scope_match"] is True
    assert diff["fixed_count"] == 1
    fixed_titles = [f.get("title") for f in (diff.get("fixed_findings") or [])]
    assert "OldFull" in fixed_titles
    assert "OldQuick" not in fixed_titles
