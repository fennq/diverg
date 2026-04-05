"""
Race condition / concurrency testing — sends simultaneous identical requests to
state-changing endpoints (redeem, apply, checkout, credit, etc.) and detects
double success, duplicate processing, or limit bypass.

Most scanners never test this. Finding "we got 10 credits from 10 concurrent
requests instead of 1" is headline-grade and puts Diverg ahead.

Authorized use only.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order, set_scan_seed

SESSION = get_session()
TIMEOUT = 8
RUN_BUDGET_SEC = 48
CONCURRENT_REQUESTS = 8  # burst size per endpoint

# Path segments that often indicate one-time or state-changing actions (race targets)
RACE_PATH_KEYWORDS = [
    "redeem", "apply", "claim", "use", "submit", "confirm", "complete",
    "checkout", "payment", "pay", "purchase", "order", "place",
    "credit", "coupon", "voucher", "gift", "bonus", "reward",
    "transfer", "withdraw", "deposit", "withdrawal",
    "subscribe", "unsubscribe", "activate", "deactivate",
    "invite", "grant", "revoke", "reset", "consume",
    "trade", "swap", "execute", "fill",
]
SUCCESS_INDICATORS = re.compile(
    r"\b(success|completed|confirmed|accepted|credited|redeemed|applied|thank you|done|ok)\b",
    re.I,
)
# Response body patterns that might indicate a single-use token or id (duplicate = race)
TRANSACTION_PATTERN = re.compile(
    r"(?:transaction_?id|order_?id|confirmation_?id|reference|receipt_?id)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{8,})['\"]?",
    re.I,
)
_HEURISTIC_FINDING_RE = re.compile(r"\[(LIKELY|POSSIBLE|VERIFY)\]", re.IGNORECASE)


@dataclass
class Finding:
    title: str
    severity: str
    url: str
    category: str
    evidence: str
    impact: str
    remediation: str


@dataclass
class RaceConditionReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    endpoints_tested: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _path_looks_like_action(path: str) -> bool:
    p = path.lower()
    return any(kw in p for kw in RACE_PATH_KEYWORDS)


def _one_request(method: str, url: str, **kwargs) -> tuple[int, str, dict]:
    """Single request; returns (status_code, body_snippet, headers_dict)."""
    try:
        r = SESSION.request(method, url, timeout=TIMEOUT, **kwargs)
        return r.status_code, (r.text or "")[:2000], dict(r.headers)
    except requests.RequestException:
        return -1, "", {}


def _burst_requests(url: str, method: str = "POST", data: dict | None = None) -> list[tuple[int, str, dict]]:
    """Fire CONCURRENT_REQUESTS identical requests in parallel."""
    results: list[tuple[int, str, dict]] = []
    kwargs = {}
    if method == "POST" and data:
        kwargs["json"] = data
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as pool:
        futs = [
            pool.submit(_one_request, method, url, **kwargs)
            for _ in range(CONCURRENT_REQUESTS)
        ]
        for f in concurrent.futures.as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                results.append((-1, "", {}))
    return results


def _analyze_burst(
    url: str,
    results: list[tuple[int, str, dict]],
) -> Finding | None:
    """If multiple responses look like success or share same transaction id, return a finding."""
    success_like = 0
    status_200 = 0
    transaction_ids: list[str] = []
    bodies: list[str] = []

    for status, body, _ in results:
        if status == 200 or status == 201:
            status_200 += 1
        if status in (200, 201, 202) and SUCCESS_INDICATORS.search(body):
            success_like += 1
        bodies.append(body)
        for m in TRANSACTION_PATTERN.finditer(body):
            transaction_ids.append(m.group(1))

    # Multiple successes from one logical action
    if success_like >= 2:
        return Finding(
            title="Possible race condition: multiple success responses to concurrent requests [LIKELY]",
            severity="High",
            url=url,
            category="Business Logic / Concurrency",
            evidence=(
                f"[Needs manual verification] Sent {CONCURRENT_REQUESTS} concurrent identical requests. "
                f"{success_like} responses contained success-like content. "
                "Verify that duplicate state changes actually occurred (e.g. double credit, double order)."
            ),
            impact=(
                "Attackers can send concurrent requests to redeem coupons, apply credits, or complete "
                "one-time actions multiple times, leading to financial loss or abuse."
            ),
            remediation=(
                "Use server-side locking (e.g. database row lock, distributed lock) or idempotency keys "
                "for state-changing operations. Reject duplicate requests within a time window."
            ),
        )

    # Same transaction/reference id in multiple responses = duplicate processing
    if len(transaction_ids) >= 2 and len(set(transaction_ids)) < len(transaction_ids):
        return Finding(
            title="Possible race condition: duplicate transaction/order IDs in concurrent responses [LIKELY]",
            severity="High",
            url=url,
            category="Business Logic / Concurrency",
            evidence=(
                f"Sent {CONCURRENT_REQUESTS} concurrent requests. Multiple responses contained "
                "the same transaction/order/reference ID, indicating the action may have been processed more than once."
            ),
            impact="Same as above: double redeem, double credit, or duplicate orders.",
            remediation="Use idempotency keys and server-side locking for one-time or state-changing operations.",
        )

    # Many 200s for an action-like endpoint is suspicious even without success text
    if status_200 >= 3 and _path_looks_like_action(url):
        return Finding(
            title="Possible race condition: multiple 200 responses to concurrent requests [POSSIBLE]",
            severity="Medium",
            url=url,
            category="Business Logic / Concurrency",
            evidence=(
                f"Sent {CONCURRENT_REQUESTS} concurrent identical requests. "
                f"{status_200} returned 200/201. Endpoint path suggests a one-time action (redeem, apply, checkout, etc.). "
                "Verify manually whether the action was applied multiple times."
            ),
            impact="If the action is applied per request without locking, attackers can double-spend or bypass limits.",
            remediation="Enforce idempotency or locking for state-changing endpoints.",
        )

    return None


def _discover_action_urls(base_url: str, run_start: float) -> list[str]:
    """Find URLs that look like action endpoints from the base page (links + common paths)."""
    urls: list[str] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    seen: set[str] = set()

    # Common action paths to probe
    action_paths = [
        "/api/redeem", "/api/coupon/apply", "/api/credit/apply", "/api/rewards/claim",
        "/api/checkout", "/api/orders", "/api/payment", "/api/subscribe",
        "/redeem", "/apply", "/claim", "/checkout", "/payment",
        "/api/v1/redeem", "/api/v1/orders", "/api/v2/checkout",
    ]
    for path in randomize_order(action_paths)[:12]:
        if _over_budget(run_start):
            break
        u = base.rstrip("/") + path
        if u not in seen:
            seen.add(u)
            urls.append(u)

    # From page links
    try:
        r = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return urls
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith("#"):
                continue
            full = urljoin(base_url, href)
            if urlparse(full).netloc != parsed.netloc:
                continue
            if full in seen:
                continue
            if _path_looks_like_action(urlparse(full).path):
                seen.add(full)
                urls.append(full)
    except Exception:
        pass
    return urls[:10]  # cap


def _split_heuristic_findings(findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Move heuristic-only findings to diagnostics."""
    kept: list[Finding] = []
    notes: list[str] = []
    for finding in findings:
        title = str(finding.title or "")
        evidence = str(finding.evidence or "")
        if _HEURISTIC_FINDING_RE.search(title) or evidence.startswith("[Needs manual verification]"):
            notes.append(f"Heuristic race-condition signal filtered: {title} ({finding.url})")
            continue
        kept.append(finding)
    return kept, notes


def run(
    target_url: str,
    scan_type: str = "full",
    endpoints_from_api: list[str] | None = None,
) -> str:
    """
    Run race-condition probing. If endpoints_from_api is provided (e.g. from API discovery),
    filter to those that look like actions; otherwise discover from base URL.
    """
    set_scan_seed(target_url)
    report = RaceConditionReport(target_url=target_url)
    run_start = time.time()
    url = target_url if target_url.startswith("http") else f"https://{target_url}"

    candidates: list[str] = []
    if endpoints_from_api:
        for ep in endpoints_from_api[:15]:
            if _over_budget(run_start):
                break
            if _path_looks_like_action(ep):
                candidates.append(ep)
    if not candidates:
        candidates = _discover_action_urls(url, run_start)

    for candidate in candidates:
        if _over_budget(run_start) or report.findings:
            break
        report.endpoints_tested += 1
        # Prefer POST for action-like endpoints; fallback GET
        for method in ("POST", "GET"):
            if _over_budget(run_start):
                break
            results = _burst_requests(candidate, method=method, data={"confirm": "1"} if method == "POST" else None)
            finding = _analyze_burst(candidate, results)
            if finding:
                report.findings.append(finding)
                break

    report.findings, heuristic_notes = _split_heuristic_findings(report.findings)
    report.errors.extend(heuristic_notes[:12])
    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
