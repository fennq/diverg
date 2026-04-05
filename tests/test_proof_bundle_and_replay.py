"""Tests for proof bundle construction and replay verifier."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import orchestrator  # noqa: E402


def test_build_proof_bundle_keeps_only_high_quality_rows() -> None:
    findings = [
        {
            "title": "Confirmed SQLi",
            "severity": "High",
            "url": "https://example.com/a",
            "proof": "POST payload returned SQL syntax error with stack trace",
            "confidence": "high",
            "verified": True,
            "source": "web_vulns",
        },
        {
            "title": "Weak row",
            "severity": "Medium",
            "url": "https://example.com/b",
            "proof": "",
            "confidence": "low",
            "verified": False,
            "source": "analysis",
        },
    ]
    bundle = orchestrator.build_proof_bundle(findings)
    assert bundle["version"] == "v1"
    assert bundle["total_bundles"] == 1
    assert bundle["replay_candidates"] == 1
    assert bundle["bundles"][0]["title"] == "Confirmed SQLi"


def test_replay_verify_finding_non_replayable_without_url() -> None:
    out = orchestrator.replay_verify_finding({"title": "No URL"}, timeout_sec=2)
    assert out["ok"] is False
    assert out["status"] == "not_replayable"
