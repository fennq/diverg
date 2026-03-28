"""
Suspicious keywords — scans URL path and fetched page content for crypto scam
patterns (airdrop, connect wallet, free mint) and general phishing patterns
(verify account, urgent action, suspended).

Self-contained, no external API dependencies, fast execution.
Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 12

# ---------------------------------------------------------------------------
# Keyword categories with severity mapping
# ---------------------------------------------------------------------------

HIGH_RISK_KEYWORDS = [
    "connect wallet",
    "approve transaction",
    "claim airdrop",
    "free mint",
    "seed phrase",
    "private key",
    "validate wallet",
]

MEDIUM_RISK_KEYWORDS = [
    "verify your account",
    "suspended",
    "urgent action required",
    "limited time",
    "act now",
    "confirm identity",
]

LOW_RISK_KEYWORDS = [
    "airdrop",
    "giveaway",
    "reward",
    "bonus",
    "whitelist spot",
]

SEVERITY_MAP = {kw: "High" for kw in HIGH_RISK_KEYWORDS}
SEVERITY_MAP.update({kw: "Medium" for kw in MEDIUM_RISK_KEYWORDS})
SEVERITY_MAP.update({kw: "Low" for kw in LOW_RISK_KEYWORDS})

ALL_KEYWORDS = HIGH_RISK_KEYWORDS + MEDIUM_RISK_KEYWORDS + LOW_RISK_KEYWORDS

# Pre-compile patterns (case-insensitive)
KEYWORD_PATTERNS = [(kw, re.compile(re.escape(kw), re.IGNORECASE)) for kw in ALL_KEYWORDS]


def _is_multiword(keyword: str) -> bool:
    return " " in keyword.strip()


def _extract_snippet(text: str, match_start: int, match_end: int, context_chars: int = 80) -> str:
    """Extract a context snippet around the match location."""
    start = max(0, match_start - context_chars)
    end = min(len(text), match_end + context_chars)
    snippet = text[start:end].strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet[:300]


def _scan_text(text: str, source_label: str) -> list[dict]:
    """Scan text for suspicious keywords and return findings."""
    findings = []
    for keyword, pattern in KEYWORD_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        severity = SEVERITY_MAP[keyword]
        multiword = _is_multiword(keyword)
        confidence = "high" if multiword else "medium"
        finding_type = "vulnerability" if severity == "High" else "informational"
        snippet = _extract_snippet(text, match.start(), match.end())
        findings.append({
            "keyword": keyword,
            "title": f"Suspicious keyword: '{keyword}' found in {source_label}",
            "severity": severity,
            "category": "Suspicious Content",
            "finding_type": finding_type,
            "confidence": confidence,
            "evidence": snippet,
            "impact": f"Page contains suspicious keyword '{keyword}' — may indicate phishing, scam, or social engineering.",
            "remediation": "Investigate page intent. Legitimate sites rarely use aggressive urgency or wallet-connect prompts.",
        })
    return findings


def _fetch_page_text(url: str) -> str:
    """Fetch page HTML and extract visible text."""
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        if not resp.ok:
            return ""
        html = resp.text
        # Strip script/style tags, then HTML tags to get visible text
        cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()
    except Exception:
        return ""


def run(target_url: str, scan_type: str = "full") -> str:
    """
    Scan URL path and page content for suspicious/scam keywords.

    target_url: full URL to scan.
    scan_type: scan profile (unused, included for interface consistency).
    """
    parsed = urlparse(target_url)
    url_text = unquote(parsed.path + "?" + parsed.query if parsed.query else parsed.path)

    # Pass 1: URL analysis
    url_findings = _scan_text(url_text, "URL")

    # Pass 2: Content analysis
    page_text = _fetch_page_text(target_url)
    content_findings = _scan_text(page_text, "page content") if page_text else []

    # Dedup: if same keyword found in both URL and content, keep URL match (higher confidence)
    url_keywords = {f["keyword"] for f in url_findings}
    deduped_content = [f for f in content_findings if f["keyword"] not in url_keywords]

    all_findings = url_findings + deduped_content

    # Remove internal 'keyword' key before returning
    for f in all_findings:
        f.pop("keyword", None)

    return json.dumps({
        "target": target_url,
        "findings": all_findings,
        "keywords_scanned": len(ALL_KEYWORDS),
        "matches_found": len(all_findings),
    })
