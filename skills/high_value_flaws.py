"""
High-value flaws skill — finds the small, high-impact issues that lead to
real breaches, data exposure, and financial loss: IDOR, leaked secrets in
frontend assets, and business-logic / payment tampering.

Authorized use only. Report only verified or clearly evidenced findings.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order

SESSION = get_session()
TIMEOUT = 6
RUN_BUDGET_SEC = 50

# Patterns that indicate sensitive/secret data in responses (redact in evidence)
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS_ACCESS_KEY"),
    (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.I), "API_KEY"),
    (re.compile(r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', re.I), "SECRET"),
    (re.compile(r'(sk_live_[a-zA-Z0-9]{24,})'), "STRIPE_SECRET_KEY"),
    (re.compile(r'(ghp_[a-zA-Z0-9]{36})'), "GITHUB_TOKEN"),
    (re.compile(r'(?:token|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', re.I), "TOKEN"),
    (re.compile(r'["\']([0-9a-f]{32,})["\']'), "HASH_OR_TOKEN"),
    (re.compile(r'(https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\'<>]*)'), "INTERNAL_URL"),
]

# URL path/param names that often hold object IDs (IDOR targets), including crypto/trading
IDOR_PARAM_NAMES = {
    "id", "uid", "user_id", "userId", "account_id", "order_id", "invoice_id",
    "doc", "document", "file", "report", "customer_id", "cart_id", "payment_id",
    "transaction_id", "subscription_id", "booking_id", "ticket_id", "msg_id",
    "pk", "key", "ref", "token",
    "wallet_id", "wallet_address", "address", "public_key", "solana_address", "wallet",
    "position_id", "trade_id", "fill_id", "portfolio_id",
    "referral_id", "affiliate_id", "webhook_id", "export_id",
    "invite_id", "invite_token", "member_id", "team_id", "org_id",
}


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
class HighValueReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _redact_secret(match: re.Match, label: str) -> str:
    g = match.group(1) if match.lastindex else match.group(0)
    if len(g) > 12:
        return f"{label}:{g[:4]}...{g[-4:]}"
    return f"{label}:(redacted)"


def scan_secrets_in_assets(base_url: str, run_start: float) -> list[Finding]:
    """Scan main page and linked JS/CSS for leaked secrets and internal URLs."""
    findings: list[Finding] = []
    try:
        resp = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return findings
        text = resp.text
        urls_to_scan = [("page", base_url, text)]

        # Collect script/link hrefs (same-origin only)
        parsed_base = urlparse(base_url)
        domain = parsed_base.netloc
        soup = None
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            pass
        if soup:
            for tag, attr in [("script", "src"), ("link", "href")]:
                for el in soup.find_all(tag, **{attr: True})[:8]:
                    href = el.get(attr, "")
                    if not href or href.startswith("data:"):
                        continue
                    abs_url = urljoin(base_url, href)
                    if urlparse(abs_url).netloc != domain:
                        continue
                    try:
                        r2 = SESSION.get(abs_url, timeout=TIMEOUT, allow_redirects=True)
                        if _over_budget(run_start):
                            return findings
                        urls_to_scan.append((attr, abs_url, r2.text[:50000]))
                    except requests.RequestException:
                        continue

        for source_label, url, content in urls_to_scan:
            if _over_budget(run_start):
                break
            for pattern, label in SECRET_PATTERNS:
                for m in pattern.finditer(content):
                    redacted = _redact_secret(m, label)
                    findings.append(Finding(
                        title=f"Possible secret/credential exposure in {source_label} [VERIFY]",
                        severity="Critical" if "KEY" in label or "SECRET" in label else "High",
                        url=url,
                        category="Sensitive Data Exposure",
                        evidence=f"Pattern: {redacted}. Source: {source_label}. Verify manually; do not expose in reports.",
                        impact="Leaked credentials can lead to account takeover, data breach, or financial loss.",
                        remediation="Remove secrets from client-side code. Use backend-only keys and env vars.",
                    ))
                    return findings  # One finding per run to avoid noise; verify first
    except requests.RequestException:
        pass
    return findings


def _looks_like_id(value: str) -> bool:
    if not value:
        return False
    if value.isdigit() and len(value) <= 12:
        return True
    if re.match(r"^[0-9a-fA-F\-]{32,36}$", value):  # UUID-like
        return True
    return False


# Keys that indicate user-specific data; if two responses have same keys but different values here = IDOR proof
IDOR_USER_KEYS = frozenset({
    "email", "name", "username", "user_name", "full_name", "first_name", "last_name",
    "user_id", "userId", "account_id", "customer_id", "phone", "address", "avatar",
    "role", "permissions", "balance", "credit", "order_id", "invoice_id",
    "wallet", "wallet_address", "wallet_id", "public_key", "solana_address",
    "position_id", "trade_id", "positions", "pnl",
    "trade_history", "order_history", "activity", "referral", "affiliate",
})


def _prove_idor_distinct_data(baseline_text: str, altered_text: str) -> tuple[bool, str]:
    """
    If both responses are JSON with same structure but different values for user-specific
    keys, return (True, proof_string). Otherwise (False, "").
    """
    try:
        a = json.loads(baseline_text)
        b = json.loads(altered_text)
    except (json.JSONDecodeError, TypeError):
        return False, ""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False, ""
    # Normalize to single object if response is list (e.g. [{"id":1,"email":"..."}])
    if isinstance(a, list) and len(a) >= 1 and isinstance(a[0], dict):
        a = a[0]
    if isinstance(b, list) and len(b) >= 1 and isinstance(b[0], dict):
        b = b[0]
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False, ""

    def _flatten(d: dict, prefix: str = "") -> dict:
        out: dict = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            else:
                out[key.lower()] = v
        return out

    flat_a = _flatten(a)
    flat_b = _flatten(b)
    differing_user_keys: list[str] = []
    for key in flat_a:
        if key.split(".")[-1] in IDOR_USER_KEYS or any(uk in key for uk in IDOR_USER_KEYS):
            if key in flat_b and flat_a[key] != flat_b[key]:
                va, vb = str(flat_a[key])[:30], str(flat_b[key])[:30]
                differing_user_keys.append(f"{key}: '{va}' vs '{vb}'")
    if differing_user_keys:
        return True, "Proof: distinct user data — " + "; ".join(differing_user_keys[:3])
    return False, ""


def probe_idor(url: str, run_start: float) -> list[Finding]:
    """Probe for IDOR: alter ID-like params and compare response."""
    findings: list[Finding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path = parsed.path or ""

    # Path segment IDs (e.g. /api/order/123)
    path_ids = re.findall(r"/(\d{2,})", path)
    if not path_ids and not params:
        return findings

    # Build baseline
    try:
        baseline = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
        base_status = baseline.status_code
        base_len = len(baseline.text)
    except requests.RequestException:
        return findings

    # Test path ID increment (e.g. /order/123 -> /order/124)
    for id_val in path_ids[:2]:  # Max 2 path IDs to stay under budget
        if _over_budget(run_start):
            break
        try:
            new_id = str(int(id_val) + 1) if id_val.isdigit() else id_val
            new_path = re.sub(r"/" + re.escape(id_val) + r"(?=/|$)", f"/{new_id}", path, count=1)
            test_url = urlunparse(parsed._replace(path=new_path))
            r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and base_status in (401, 403) and len(r.text) > 100:
                findings.append(Finding(
                    title="Possible IDOR via path segment [UNCONFIRMED]",
                    severity="Critical",
                    url=test_url,
                    category="OWASP-A01 Broken Access Control",
                    evidence=f"Baseline {url} returned {base_status}; altered ID returned 200. Compare responses manually to confirm data of another user.",
                    impact="Attacker may access other users' data (orders, profiles, documents) by changing IDs.",
                    remediation="Enforce authorization per resource. Validate that the authenticated user owns the requested resource ID.",
                ))
                return findings
            if r.status_code == 200 and base_status == 200 and abs(len(r.text) - base_len) > 200:
                proved, proof_str = _prove_idor_distinct_data(baseline.text, r.text)
                if proved:
                    findings.append(Finding(
                        title="IDOR via path segment [CONFIRMED]",
                        severity="Critical",
                        url=test_url,
                        category="OWASP-A01 Broken Access Control",
                        evidence=f"{proof_str} Response length: {base_len} vs {len(r.text)}.",
                        impact="Attacker can access other users' data (orders, profiles, documents) by changing the path ID.",
                        remediation="Enforce authorization per resource. Validate that the authenticated user owns the requested resource ID.",
                    ))
                else:
                    findings.append(Finding(
                        title="Possible IDOR (different response length) via path [UNCONFIRMED]",
                        severity="High",
                        url=test_url,
                        category="OWASP-A01 Broken Access Control",
                        evidence=f"Altered path ID; response length changed ({base_len} -> {len(r.text)}). Verify if other user's data is returned.",
                        impact="May allow access to other users' records by enumerating or guessing IDs.",
                        remediation="Enforce authorization per resource. Use unpredictable IDs (UUIDs) and still authorize.",
                    ))
                return findings
        except (requests.RequestException, ValueError):
            continue

    # Query param IDs
    for pname, pvals in list(params.items())[:3]:
        if _over_budget(run_start) or pname.lower() not in IDOR_PARAM_NAMES:
            continue
        val = pvals[0] if pvals else ""
        if not _looks_like_id(val):
            continue
        try:
            new_val = str(int(val) + 1) if val.isdigit() else val
            new_params = {k: (v if k != pname else [new_val]) for k, v in params.items()}
            test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and base_status in (401, 403):
                findings.append(Finding(
                    title=f"Possible IDOR via parameter '{pname}' [UNCONFIRMED]",
                    severity="Critical",
                    url=test_url,
                    category="OWASP-A01 Broken Access Control",
                    evidence=f"Baseline returned {base_status}; altered {pname} returned 200. Confirm if other user's data is returned.",
                    impact="Attacker may read or modify other users' data by changing the parameter.",
                    remediation="Authorize per resource; validate resource ownership for the current user.",
                ))
                return findings
            if r.status_code == 200 and base_status == 200 and abs(len(r.text) - base_len) > 100:
                proved, proof_str = _prove_idor_distinct_data(baseline.text, r.text)
                if proved:
                    findings.append(Finding(
                        title=f"IDOR via parameter '{pname}' [CONFIRMED]",
                        severity="Critical",
                        url=test_url,
                        category="OWASP-A01 Broken Access Control",
                        evidence=f"{proof_str} Parameter {pname} altered; distinct user data returned.",
                        impact="Attacker can read other users' data by changing the parameter.",
                        remediation="Authorize per resource; validate resource ownership for the current user.",
                    ))
                    return findings
        except (requests.RequestException, ValueError):
            continue
    return findings


def scan_idor(base_url: str, run_start: float) -> list[Finding]:
    """Discover ID-like URLs from page and probe for IDOR."""
    findings: list[Finding] = []
    try:
        resp = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return findings
        # Collect links that look like they have IDs
        soup = None
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            pass
        if not soup:
            return findings
        seen: set[str] = set()
        for a in soup.find_all("a", href=True):
            if _over_budget(run_start):
                break
            href = a["href"]
            abs_url = urljoin(base_url, href)
            if urlparse(abs_url).netloc != urlparse(base_url).netloc:
                continue
            if abs_url in seen:
                continue
            if re.search(r"/\d{2,}(/|$)|[\?&](id|uid|order_id|user_id)=[\d\w\-]+", abs_url):
                seen.add(abs_url)
                findings.extend(probe_idor(abs_url, run_start))
                if findings:
                    return findings
    except requests.RequestException:
        pass
    return findings


# Path/param keywords that suggest payment or order logic (including crypto/trading)
BUSINESS_LOGIC_KEYWORDS = ["order", "cart", "payment", "checkout", "invoice", "subscription", "purchase", "amount", "total", "price", "quantity", "trade", "swap", "position", "wallet", "balance", "orderbook", "fill", "history", "activity", "export", "webhook", "slippage", "referral", "market", "quote"]
BUSINESS_PROBE_PARAMS = [
    ("amount", "0"),
    ("amount", "0.01"),
    ("total", "0"),
    ("price", "0"),
    ("quantity", "-1"),
    ("quantity", "0"),
    ("discount", "100"),
    ("coupon", "FREE100"),
]


def scan_business_logic(base_url: str, run_start: float) -> list[Finding]:
    """Probe endpoints that look like order/payment for logic flaws."""
    findings: list[Finding] = []
    try:
        resp = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return findings
        path_lower = urlparse(base_url).path.lower()
        if not any(kw in path_lower for kw in BUSINESS_LOGIC_KEYWORDS):
            return findings
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        for param_name, probe_value in randomize_order(BUSINESS_PROBE_PARAMS)[:4]:
            if _over_budget(run_start):
                break
            new_params = dict(params)
            new_params[param_name] = [probe_value]
            test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            try:
                r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                if r.status_code != 200:
                    continue
                body_lower = (r.text or "").lower()
                # Heuristic: success indicators with zero/negative amount
                if ("success" in body_lower or "confirmed" in body_lower or "thank you" in body_lower) and probe_value in ("0", "-1", "0.01"):
                    findings.append(Finding(
                        title=f"Possible business logic flaw: '{param_name}' accepted as {probe_value} [VERIFY]",
                        severity="Critical",
                        url=test_url,
                        category="Business Logic",
                        evidence=f"Request with {param_name}={probe_value} returned 200 and success-like content. Confirm if order/total was actually modified.",
                        impact="Attackers could manipulate prices, quantities, or discounts leading to financial loss.",
                        remediation="Validate and enforce business rules server-side. Never trust client-supplied amount, price, or quantity.",
                    ))
                    return findings
            except requests.RequestException:
                continue
    except requests.RequestException:
        pass
    return findings


def run(target_url: str, scan_type: str = "full") -> str:
    report = HighValueReport(target_url=target_url)
    run_start = time.time()
    url = target_url if target_url.startswith("http") else f"https://{target_url}"

    if scan_type in ("full", "secrets"):
        report.findings.extend(scan_secrets_in_assets(url, run_start))
    if scan_type in ("full", "idor") and not report.findings and not _over_budget(run_start):
        report.findings.extend(scan_idor(url, run_start))
    if scan_type in ("full", "business") and not report.findings and not _over_budget(run_start):
        report.findings.extend(scan_business_logic(url, run_start))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
