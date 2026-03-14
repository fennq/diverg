"""
Fact-only and accuracy tests for Diverg.

Ensures we only report what we have evidence for:
- Skills return valid JSON with expected shapes; no invented counts or fields.
- format_scan_results only uses data present in the payload (no hallucination).
- Empty or error responses are not presented as success.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Project root and skills for import x_search, web_search
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills"))
os.chdir(ROOT)
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "test")
os.environ.setdefault("OPENAI_API_KEY", "test")


def test_x_search_empty_query_returns_zero_results() -> None:
    """Empty query must yield result_count 0 and source 'none' — no fabricated hits."""
    import x_search
    out = x_search.run("", max_results=10)
    data = json.loads(out)
    assert "result_count" in data
    assert data["result_count"] == 0
    assert data.get("source") in ("none", None) or data["source"] == "none"
    assert "results" in data
    assert isinstance(data["results"], list)
    assert len(data["results"]) == 0


def test_x_search_valid_json_shape() -> None:
    """X search output must have required keys; results must have author_username, text, url when present."""
    import x_search
    # Any query; we only check shape of response
    out = x_search.run("test wallet 7xK9mN2p", max_results=5)
    data = json.loads(out)
    assert "result_count" in data
    assert "results" in data
    assert isinstance(data["results"], list)
    for r in data["results"]:
        assert "author_username" in r
        assert "text" in r or "url" in r  # at least one
        # url when present should be x.com pattern
        url = r.get("url", "")
        if url:
            assert "x.com" in url or "twitter.com" in url


def test_web_search_empty_query_returns_empty_results() -> None:
    """Web search with empty query must return result_count 0 and empty results list."""
    import web_search
    out = web_search.run("", max_results=10)
    data = json.loads(out)
    assert "result_count" in data
    assert data["result_count"] == 0
    assert "results" in data
    assert isinstance(data["results"], list)
    assert len(data["results"]) == 0


def test_web_search_valid_json_shape() -> None:
    """Web search output must have query, result_count, results; each result title/snippet/url."""
    import web_search
    out = web_search.run("solana wallet", max_results=5)
    data = json.loads(out)
    assert "query" in data
    assert "result_count" in data
    assert "results" in data
    assert isinstance(data["results"], list)
    for r in data["results"]:
        assert isinstance(r, dict)
        # allowed keys from skill
        assert any(k in r for k in ("title", "snippet", "url"))


def test_format_scan_results_blockchain_no_invention() -> None:
    """format_scan_results must not show verdict/red_flags when they are absent in payload."""
    from bot import format_scan_results
    # Payload without verdict or red_flags
    raw = json.dumps({
        "target_url": "https://post-rug.local",
        "platform_type": "unknown",
        "chain": "solana",
        "on_chain_used": False,
        "crime_report": {"summary": "No API key."},
        "findings": [],
    })
    text = format_scan_results("blockchain_investigation", raw, "0xabc")
    # Must not contain a fabricated verdict line
    assert "*Verdict:*" not in text or "No API key" in text or "skipped" in text.lower()
    # Must state on-chain skipped when on_chain_used is False
    assert "skipped" in text.lower() or "no API key" in text.lower()


def test_format_scan_results_blockchain_verdict_only_when_present() -> None:
    """When crime_report has verdict, it appears; when it doesn't, it must not be invented."""
    from bot import format_scan_results
    raw_with_verdict = json.dumps({
        "target_url": "https://example.com",
        "platform_type": "launchpad",
        "chain": "solana",
        "on_chain_used": True,
        "crime_report": {
            "verdict": "Moderate risk: concentrated holders.",
            "red_flags": ["Top 10 hold 60%"],
        },
        "flow_graph": {"nodes": [{"id": "a"}], "edges": []},
    })
    text = format_scan_results("blockchain_investigation", raw_with_verdict, "7xK9...")
    assert "Moderate risk" in text
    assert "Top 10 hold" in text
    raw_no_verdict = json.dumps({
        "target_url": "https://example.com",
        "platform_type": "unknown",
        "chain": "solana",
        "on_chain_used": False,
        "crime_report": {},
    })
    text2 = format_scan_results("blockchain_investigation", raw_no_verdict, "7xK9...")
    # Must not invent a verdict when crime_report has no verdict
    assert "*Verdict:*" not in text2


def test_format_scan_results_x_search_uses_actual_count() -> None:
    """X search summary must use result_count from data, not a made-up number."""
    from bot import format_scan_results
    raw = json.dumps({
        "source": "x_api",
        "query": "7xK9",
        "result_count": 3,
        "results": [
            {"tweet_id": "1", "text": "t1", "author_username": "u1", "url": "https://x.com/u1/status/1"},
            {"tweet_id": "2", "text": "t2", "author_username": "u2", "url": "https://x.com/u2/status/2"},
            {"tweet_id": "3", "text": "t3", "author_username": "u3", "url": "https://x.com/u3/status/3"},
        ],
    })
    text = format_scan_results("x_search", raw, "7xK9")
    assert "3" in text
    assert "u1" in text or "u2" in text


def test_format_scan_results_web_search_uses_actual_count() -> None:
    """Web search summary must use result_count from data."""
    from bot import format_scan_results
    raw = json.dumps({
        "query": "wallet scam",
        "result_count": 2,
        "results": [
            {"title": "A", "snippet": "s1", "url": "https://a.com"},
            {"title": "B", "snippet": "s2", "url": "https://b.com"},
        ],
    })
    text = format_scan_results("web_search", raw, "wallet")
    assert "2" in text


def test_blockchain_report_error_payload_not_success() -> None:
    """When blockchain skill returns error, format_scan_results must show error, not success."""
    from bot import format_scan_results
    raw = json.dumps({"error": "Solscan API key missing", "findings": []})
    text = format_scan_results("blockchain_investigation", raw, "addr")
    assert "error" in text.lower() or "missing" in text.lower() or "Scan error" in text


def run_all() -> list[str]:
    """Run all test functions; return list of failed test names."""
    tests = [
        test_x_search_empty_query_returns_zero_results,
        test_x_search_valid_json_shape,
        test_web_search_empty_query_returns_empty_results,
        test_web_search_valid_json_shape,
        test_format_scan_results_blockchain_no_invention,
        test_format_scan_results_blockchain_verdict_only_when_present,
        test_format_scan_results_x_search_uses_actual_count,
        test_format_scan_results_web_search_uses_actual_count,
        test_blockchain_report_error_payload_not_success,
    ]
    failed: list[str] = []
    for fn in tests:
        name = fn.__name__
        try:
            fn()
            print(f"[OK] {name}")
        except Exception as e:
            failed.append(name)
            print(f"[FAIL] {name}: {e}")
    return failed


if __name__ == "__main__":
    failed = run_all()
    if failed:
        print(f"\n{len(failed)} test(s) failed: {failed}")
        sys.exit(1)
    print("\nAll fact/accuracy tests passed.")
    sys.exit(0)
