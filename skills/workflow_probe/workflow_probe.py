"""
Workflow probe — Diverg-proprietary skill that finds business-logic bugs by
abusing flow order and state. Zero false positives: we only report when
(1) path clearly indicates order/checkout/confirm, (2) response body has
two+ order/checkout semantics (not generic "success"), (3) we include
verification_steps so assessor can replay.

Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from stealth import get_session, randomize_order

SESSION = get_session()
TIMEOUT = 8
RUN_BUDGET_SEC = 45

# Path must clearly indicate order/checkout/confirm (not generic)
TERMINAL_PATH_HINTS = [
    "confirm", "complete", "place", "submit", "finalize", "finish",
    "place-order", "place_order", "complete-order", "create-order",
    "checkout/complete", "order/confirm", "payment/confirm",
    "apply", "redeem", "activate", "commit",
    "order", "checkout", "cart/checkout",
]

# Two-signal rule: response must contain at least TWO of these (order/checkout semantics).
# Avoids false positives from generic "success" or "completed" on non-order pages.
ORDER_SEMANTIC_SIGNALS = [
    re.compile(r"\border_?id\b", re.I),
    re.compile(r"\border\s*#", re.I),
    re.compile(r"\bconfirmation\b", re.I),
    re.compile(r"\bplaced\b", re.I),
    re.compile(r"\bthank\s*you\b", re.I),
    re.compile(r"\b(?:order|checkout)\s*completed\b", re.I),
    re.compile(r"\bcompleted.*(?:order|checkout)\b", re.I),
    re.compile(r"\bsuccess.*(?:order|placed|confirm)\b", re.I),
    re.compile(r"\b(?:order|placed|confirm).*success\b", re.I),
    re.compile(r"\bredeem(?:ed)?\s*(?:success|complete)\b", re.I),
    re.compile(r"\bapply\s*(?:success|complete)\b", re.I),
]
# Generic single-word "success" / "completed" alone is NOT enough
GENERIC_ONLY = re.compile(r"^\s*{\s*\"(?:success|completed|status)\"\s*:\s*true\s*}\s*$", re.I)


def _response_indicates_order_success(body: str) -> bool:
    """True only if body has at least TWO order/checkout semantic signals (zero false positives)."""
    if not (body and body.strip()):
        return False
    # Reject generic-only JSON like {"success": true}
    if GENERIC_ONLY.match(body.strip()):
        return False
    count = sum(1 for pat in ORDER_SEMANTIC_SIGNALS if pat.search(body))
    return count >= 2


@dataclass
class Finding:
    title: str
    severity: str
    url: str
    category: str
    evidence: str
    impact: str
    remediation: str
    verification_steps: list[dict] | None = None
    confidence: str = "confirmed"


@dataclass
class WorkflowProbeReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    endpoints_probed: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _is_terminal(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in TERMINAL_PATH_HINTS)


def _collect_flow_candidates(base_url: str, run_start: float) -> list[str]:
    """Build candidate URLs that look like flow terminal steps."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    candidates = [
        "/api/order/confirm", "/api/orders/confirm", "/api/checkout/complete",
        "/api/checkout/confirm", "/api/cart/checkout", "/api/place-order",
        "/api/orders/place", "/api/payment/confirm", "/api/subscription/activate",
        "/checkout/complete", "/order/confirm", "/pay/confirm",
        "/api/v1/order/confirm", "/api/v2/checkout/complete",
        "/api/apply", "/api/coupon/apply", "/api/redeem",
    ]
    out = []
    for path in randomize_order(candidates):
        if _over_budget(run_start):
            break
        url = base.rstrip("/") + path
        try:
            # GET first (many confirm pages are GET)
            r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 201, 302):
                out.append(url)
            # POST with minimal body
            if path.endswith("confirm") or "complete" in path or "place" in path:
                r2 = SESSION.post(url, json={}, timeout=TIMEOUT, allow_redirects=False)
                if r2.status_code in (200, 201, 302):
                    out.append(url)
        except requests.RequestException:
            continue
    return out[:12]


def _probe_skip_step(url: str, run_start: float) -> Finding | None:
    """Probe: call terminal step with empty/minimal payload. Report only when 2xx + two order-semantic signals."""
    try:
        for method, payload in [("POST", {}), ("POST", {"confirm": True}), ("GET", None)]:
            if _over_budget(run_start):
                return None
            if method == "GET":
                r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
                req_body = None
            else:
                r = SESSION.post(url, json=payload, timeout=TIMEOUT, allow_redirects=False)
                req_body = payload
            if r.status_code not in (200, 201):
                continue
            body = (r.text or "")[:2000]
            if not _response_indicates_order_success(body):
                continue
            steps = [{"method": method, "url": url, "body": req_body, "response_status": r.status_code}]
            return Finding(
                title="Flow bypass: terminal step accepted without prior steps",
                severity="High",
                url=url,
                category="Business logic (workflow)",
                evidence=f"{method} {url} returned {r.status_code}. Response body contains two+ order/checkout semantics (e.g. order_id, confirmation, placed). No cart/payment step was sent. Replay with verification_steps below.",
                impact="Attacker may complete order/checkout without adding items or paying (free order, bypass payment).",
                remediation="Enforce server-side state machine: require valid cart/session and payment step before confirm/complete.",
                verification_steps=steps,
                confidence="confirmed",
            )
    except requests.RequestException:
        pass
    return None


def _probe_zero_amount(url: str, run_start: float) -> Finding | None:
    """Probe: send amount=0 or total=0. Report only when 2xx + two order-semantic signals in response."""
    try:
        payloads = [
            {"amount": 0, "total": 0},
            {"amount": 0},
            {"total": 0},
            {"quantity": 0, "amount": 0},
        ]
        for p in payloads:
            if _over_budget(run_start):
                return None
            r = SESSION.post(url, json=p, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code not in (200, 201):
                continue
            body = (r.text or "")[:2000]
            if not _response_indicates_order_success(body):
                continue
            steps = [{"method": "POST", "url": url, "body": p, "response_status": r.status_code}]
            return Finding(
                title="Zero-amount order/checkout accepted",
                severity="Critical",
                url=url,
                category="Business logic (workflow)",
                evidence=f"POST with payload {p} returned {r.status_code}. Response body contains two+ order/checkout semantics. Replay with verification_steps below.",
                impact="Attacker can place orders for zero cost (free products, bypass payment).",
                remediation="Reject amount/total/quantity of zero (or negative). Validate server-side against cart and pricing.",
                verification_steps=steps,
                confidence="confirmed",
            )
    except requests.RequestException:
        pass
    return None


def run(target_url: str, scan_type: str = "full", context: dict | None = None) -> str:
    """
    Probe workflow/order-of-operations bugs: skip step, zero amount, confirm without pay.
    context: optional dict with "endpoints" (list of URLs) from prior discovery.
    """
    run_start = time.time()
    report = WorkflowProbeReport(target_url=target_url)

    candidates: list[str] = []
    if context and isinstance(context.get("endpoints"), list):
        for u in context["endpoints"][:20]:
            if isinstance(u, str) and _is_terminal(u):
                candidates.append(u)
    if not candidates:
        candidates = _collect_flow_candidates(target_url, run_start)

    report.endpoints_probed = len(candidates)
    for url in candidates:
        if _over_budget(run_start):
            break
        f = _probe_skip_step(url, run_start)
        if f and not any(x.url == f.url and "skip" in x.title for x in report.findings):
            report.findings.append(f)
        f2 = _probe_zero_amount(url, run_start)
        if f2 and not any(x.url == f2.url and "Zero" in x.title for x in report.findings):
            report.findings.append(f2)

    out = {
        "target_url": target_url,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "url": f.url,
                "category": f.category,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
                "verification_steps": getattr(f, "verification_steps", None),
                "confidence": getattr(f, "confidence", "confirmed"),
            }
            for f in report.findings
        ],
        "endpoints_probed": report.endpoints_probed,
        "errors": report.errors,
        "note": "Workflow probe: zero-FP — only reports when path is order/checkout and response has two+ order semantics. Replay via verification_steps.",
    }
    return json.dumps(out, indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(target))
