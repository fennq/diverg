"""Regression tests for strict-positive finding filtering."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import orchestrator  # noqa: E402


def _mk(
    title: str,
    *,
    severity: str = "High",
    evidence: str = "Request payload returned 500 with SQL syntax error.",
    category: str = "Injection",
    finding_type: str = "vulnerability",
    finding_confidence: str | None = "confirmed",
    status: str | None = None,
) -> dict:
    row = {
        "title": title,
        "severity": severity,
        "url": "https://example.com/test",
        "category": category,
        "evidence": evidence,
        "impact": "Impact",
        "remediation": "Fix",
        "finding_type": finding_type,
        "_source_skill": "web_vulns",
    }
    if finding_confidence:
        row["finding_confidence"] = finding_confidence
    if status:
        row["status"] = status
    return row


def test_strict_filter_excludes_heuristic_and_pass_rows() -> None:
    normalized = orchestrator.finalize_api_findings(
        [
            _mk("Blind SQL Injection [LIKELY]", finding_confidence="likely", evidence="[Needs manual verification] suspect"),
            _mk("HTTP header: Strict-Transport-Security — pass", finding_type="positive", status="pass"),
            _mk("Validated SQL injection", finding_confidence="confirmed"),
        ]
    )
    kept, dropped, breakdown = orchestrator.filter_strict_positive_findings(normalized)
    assert [f["title"] for f in kept] == ["Validated SQL injection"]
    assert dropped == 2
    assert breakdown.get("heuristic_marker", 0) == 1
    assert breakdown.get("non_vulnerability_type", 0) == 1 or breakdown.get("pass_status", 0) == 1


def test_strict_filter_requires_real_proof_text() -> None:
    normalized = orchestrator.finalize_api_findings(
        [
            _mk("Confirmed finding without proof", evidence="See source output.", finding_confidence="confirmed"),
            _mk("Confirmed finding with proof", evidence="POST request returned 500 with stack trace and payload echo.", finding_confidence="confirmed"),
        ]
    )
    kept, dropped, breakdown = orchestrator.filter_strict_positive_findings(normalized)
    assert [f["title"] for f in kept] == ["Confirmed finding with proof"]
    assert dropped == 1
    assert breakdown.get("insufficient_proof", 0) == 1


def test_strict_filter_repeatability_same_input_same_output() -> None:
    sample = orchestrator.finalize_api_findings(
        [
            _mk("Confirmed A", finding_confidence="confirmed"),
            _mk("Possible B [POSSIBLE]", finding_confidence="possible", evidence="[Needs manual verification] check"),
            _mk("Confirmed C", finding_confidence="confirmed"),
        ]
    )
    kept_1, dropped_1, breakdown_1 = orchestrator.filter_strict_positive_findings(sample)
    kept_2, dropped_2, breakdown_2 = orchestrator.filter_strict_positive_findings(sample)
    assert [f["title"] for f in kept_1] == [f["title"] for f in kept_2]
    assert dropped_1 == dropped_2
    assert breakdown_1 == breakdown_2


def test_strict_filter_enforces_replay_gate_for_high_critical() -> None:
    findings = orchestrator.finalize_api_findings(
        [
            _mk(
                "Critical SQLi",
                severity="Critical",
                evidence="payload caused sql error and stack trace in response body",
                finding_confidence="confirmed",
            )
        ]
    )

    def _replay_fail(_f, timeout_sec=6):
        return {"ok": False, "status": "replay_failed", "reason": "timeout"}

    gated, stats = orchestrator.enforce_replay_gate(findings, replay_fn=_replay_fail)
    assert stats["replay_checked"] == 1
    assert stats["replay_downgraded"] == 1
    assert gated[0]["verified"] is False
    assert str(gated[0].get("finding_confidence") or "").lower() == "possible"


def test_fp_memory_suppression_filters_matching_findings() -> None:
    findings = orchestrator.finalize_api_findings(
        [
            _mk("Known noisy title", category="Business Logic / Concurrency", finding_confidence="confirmed"),
            _mk("Real confirmed issue", category="Injection", finding_confidence="confirmed"),
        ]
    )
    for f in findings:
        if f["title"] == "Known noisy title":
            f["source"] = "race_condition"
            f["_source_skill"] = "race_condition"
    kept, dropped, breakdown = orchestrator.filter_strict_positive_findings(
        findings,
        fp_suppressions=[
            {
                "active": True,
                "title_contains": "known noisy title",
                "category_contains": "business logic / concurrency",
                "source_equals": "race_condition",
            }
        ],
    )
    assert [f["title"] for f in kept] == ["Real confirmed issue"]
    assert dropped == 1
    assert breakdown.get("fp_memory_match", 0) == 1


def test_medium_consensus_gate_downgrades_unstable_medium() -> None:
    findings = orchestrator.finalize_api_findings(
        [
            _mk(
                "HTTP header: Strict-Transport-Security — misconfigured",
                severity="Medium",
                category="Transport and Browser Security",
                evidence="Header appeared misconfigured in one sample.",
                finding_confidence="confirmed",
            )
        ]
    )

    def _always_false(_f, attempts=2):
        return False

    gated, stats = orchestrator.enforce_medium_consensus_gate(findings, checker=_always_false)
    assert stats["medium_checked"] == 1
    assert stats["medium_downgraded"] == 1
    assert str(gated[0].get("finding_confidence") or "").lower() == "possible"
    assert gated[0].get("verified") is False
