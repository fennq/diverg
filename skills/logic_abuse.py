"""
Logic / numeric abuse skill — APT-style Upgrade 3.
Finds "think like an attacker" bugs: amount/quantity/limit/offset accepted with
0, -1, MAX_INT, NaN, Infinity; overflow or rounding; bounds bypass.

- Probes endpoints (from built-in list or client_surface extracted_endpoints) with
  numeric and bounds param sets.
- Reports CONFIRMED when server returns success-like response for tampered value;
  POSSIBLE when status/body suggests different code path or crash.

Authorized use only.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order

SESSION = get_session()
TIMEOUT = 6
RUN_BUDGET_SEC = 45
MAX_ENDPOINTS = 12
MAX_REQUESTS_PER_ENDPOINT = 14  # cap total requests per URL

# Param names that control amount, quantity, or bounds
AMOUNT_PARAMS = [
    "amount", "quantity", "qty", "total", "price", "sum", "balance", "value", "size", "count",
    "credit", "debit", "points", "fee", "tip", "tax", "discount", "subtotal", "usd", "eth",
]
LIMIT_PARAMS = ["limit", "offset", "per_page", "page_size", "max", "take", "top", "first"]
NUMERIC_PROBES = [
    0, -1, 1,
    999999, 2147483647, 2147483648, 999999999999,
    0.0001, 1e10, 1e20,
]
NUMERIC_STR_PROBES = ["0", "-1", "1", "999999", "2147483647", "NaN", "Infinity", "1e308"]
BOUNDS_PROBES = [-1, 0, 1, 999999, 2147483647]

SUCCESS_INDICATOR = re.compile(
    r"\b(success|completed|confirmed|ok|true|placed|created|accepted|processed)\b",
    re.I,
)
# Response suggests list/array (for limit abuse)
LIST_INDICATOR = re.compile(r"\[\s*\{|\"items\"\s*:\s*\[|\"data\"\s*:\s*\[|\"results\"\s*:\s*\[", re.I)


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
class LogicAbuseReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    endpoints_probed: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _body_fp(text: str) -> str:
    raw = (text or "")[:3500]
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]


def _baseline_for_url(session: requests.Session, url: str, run_start: float) -> dict | None:
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
        if _over_budget(run_start):
            return None
        return {
            "status": r.status_code,
            "fp": _body_fp(r.text),
            "len": len(r.text or ""),
        }
    except requests.RequestException:
        return None


def _success_in_response(r: requests.Response) -> bool:
    body = (r.text or "").lower()
    ct = (r.headers.get("Content-Type") or "").lower()
    if "application/json" in ct or (r.text or "").lstrip().startswith("{"):
        return bool(SUCCESS_INDICATOR.search(body))
    if len(r.text or "") > 14000:
        return False
    return bool(SUCCESS_INDICATOR.search(body))


def _tamper_not_benign(r: requests.Response, baseline: dict | None) -> bool:
    """Avoid flagging identical marketing pages when only a query param changes."""
    if not baseline:
        return True
    if r.status_code != baseline.get("status"):
        return True
    if r.status_code in (200, 201) and _body_fp(r.text) != baseline.get("fp"):
        return True
    return False


def _collect_endpoints(base_url: str, extracted_endpoints: list[str] | None, run_start: float) -> list[str]:
    """Build full URLs to probe. Prefer extracted_endpoints; else use built-in paths."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    urls: list[str] = []
    if extracted_endpoints:
        for path in extracted_endpoints[:MAX_ENDPOINTS]:
            path = path if path.startswith("/") else "/" + path
            u = base.rstrip("/") + path
            if u not in urls:
                urls.append(u)
    if not urls:
        # Built-in: financial and list-style API paths
        paths = [
            "/api/orders", "/api/order", "/api/trades", "/api/positions", "/api/wallet", "/api/balance",
            "/api/checkout", "/api/payment", "/api/refund", "/api/cart", "/api/quote", "/api/swap",
            "/api/history", "/api/activity", "/api/export", "/api/users", "/api/list", "/api/items",
            "/api/v1/orders", "/api/v2/orders", "/api/me", "/api/portfolio", "/api/coupon/apply",
        ]
        for path in randomize_order(paths)[:MAX_ENDPOINTS]:
            if _over_budget(run_start):
                break
            u = base.rstrip("/") + path
            if u not in urls:
                urls.append(u)
    return urls[:MAX_ENDPOINTS]


def _probe_numeric(
    url: str,
    param: str,
    value: object,
    run_start: float,
    session: requests.Session,
    baseline: dict | None,
) -> Finding | None:
    """Send one param tampering; return finding if success-like or unexpected."""
    try:
        parsed = urlparse(url)
        # GET
        params = dict(parse_qs(parsed.query))
        params[param] = [str(value)]
        qs = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=qs))
        r = session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
        if _over_budget(run_start):
            return None
        if r.status_code in (200, 201) and _success_in_response(r) and _tamper_not_benign(r, baseline):
            return Finding(
                title=f"Logic/numeric: Server accepted {param}={value} with success-like response [CONFIRMED]",
                severity="High",
                url=test_url,
                category="Logic / Numeric Abuse",
                evidence=f"GET {param}={value} returned {r.status_code} and success indicator (baseline-filtered). Server may not validate numeric bounds.",
                impact="Attackers may complete actions with zero/negative/large values (free order, overflow, or DoS).",
                remediation="Validate all amount/quantity/limit server-side; reject out-of-range and non-numeric values.",
            )
        # POST JSON
        payload = {param: value}
        r = session.post(url, json=payload, timeout=TIMEOUT, allow_redirects=False)
        if _over_budget(run_start):
            return None
        if r.status_code in (200, 201) and _success_in_response(r) and _tamper_not_benign(r, baseline):
            return Finding(
                title=f"Logic/numeric: Server accepted POST JSON {param}={value} with success-like response [CONFIRMED]",
                severity="High",
                url=url,
                category="Logic / Numeric Abuse",
                evidence=f"POST JSON {param}={value} returned {r.status_code} and success indicator.",
                impact="Same as above: zero/negative/large values accepted.",
                remediation="Validate all numeric fields server-side; enforce min/max and type.",
            )
        # POST form-urlencoded (common for older APIs)
        r = session.post(
            url,
            data={param: str(value)},
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if _over_budget(run_start):
            return None
        if r.status_code in (200, 201) and _success_in_response(r) and _tamper_not_benign(r, baseline):
            return Finding(
                title=f"Logic/numeric: Server accepted POST form {param}={value} with success-like response [CONFIRMED]",
                severity="High",
                url=url,
                category="Logic / Numeric Abuse",
                evidence=f"POST form {param}={value} returned {r.status_code} and success indicator.",
                impact="Same as above: zero/negative/large values accepted via form body.",
                remediation="Validate all numeric fields server-side; enforce min/max and type.",
            )
    except requests.RequestException:
        pass
    return None


def _probe_bounds(
    url: str,
    param: str,
    value: int,
    run_start: float,
    session: requests.Session,
    baseline: dict | None,
) -> Finding | None:
    """Probe limit/offset; report if we get 200 with very large limit (possible data dump)."""
    try:
        parsed = urlparse(url)
        params = dict(parse_qs(parsed.query))
        params[param] = [str(value)]
        qs = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=qs))
        r = session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
        if _over_budget(run_start):
            return None
        if r.status_code != 200 or value < 1000:
            return None
        # Large limit returned 200 — check if response looks like a list
        body = r.text or ""
        blen = len(body)
        base_len = int((baseline or {}).get("len") or 0)
        if baseline and base_len > 400 and blen <= int(base_len * 1.08):
            return None
        if LIST_INDICATOR.search(body) and blen > 500:
            return Finding(
                title=f"Logic/bounds: Large {param}={value} returned 200 with list-like body [POSSIBLE]",
                severity="Medium",
                url=test_url,
                category="Logic / Numeric Abuse",
                evidence=f"GET {param}={value} returned 200 and array/list-like content ({blen} bytes). Server may not cap limit.",
                impact="Attackers could request very large limits and export more data than intended.",
                remediation="Enforce maximum limit and offset server-side (e.g. cap at 100).",
            )
    except requests.RequestException:
        pass
    return None


def run(
    target_url: str,
    scan_type: str = "full",
    extracted_endpoints: list[str] | None = None,
    client_surface_json: str | None = None,
) -> str:
    report = LogicAbuseReport(target_url=target_url)
    run_start = time.time()
    session = SESSION

    if client_surface_json and not extracted_endpoints:
        try:
            data = json.loads(client_surface_json)
            extracted_endpoints = data.get("extracted_endpoints") or []
        except Exception:
            extracted_endpoints = []

    urls = _collect_endpoints(target_url, extracted_endpoints, run_start)
    report.endpoints_probed = len(urls)
    seen_evidence: set[str] = set()
    requests_per_url: dict[str, int] = {}

    for url in randomize_order(urls):
        if _over_budget(run_start):
            break
        requests_per_url[url] = requests_per_url.get(url, 0)
        if requests_per_url[url] >= MAX_REQUESTS_PER_ENDPOINT:
            continue
        baseline = _baseline_for_url(session, url, run_start)
        # Amount-style params (fewer probes per param)
        for param in AMOUNT_PARAMS[:6]:
            if requests_per_url[url] >= MAX_REQUESTS_PER_ENDPOINT or _over_budget(run_start):
                break
            for val in NUMERIC_PROBES[:5]:
                f = _probe_numeric(url, param, val, run_start, session, baseline)
                requests_per_url[url] = requests_per_url.get(url, 0) + 1
                if f and f.evidence not in seen_evidence:
                    seen_evidence.add(f.evidence)
                    report.findings.append(f)
                    break
        # Limit/offset (one param per URL to save time)
        for param in LIMIT_PARAMS[:2]:
            if requests_per_url[url] >= MAX_REQUESTS_PER_ENDPOINT or _over_budget(run_start):
                break
            for val in BOUNDS_PROBES:
                f = _probe_bounds(url, param, val, run_start, session, baseline)
                requests_per_url[url] = requests_per_url.get(url, 0) + 1
                if f and f.evidence not in seen_evidence:
                    seen_evidence.add(f.evidence)
                    report.findings.append(f)
                    break

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url))
