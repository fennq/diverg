"""
Data leak risks — finds the small exposures that compound into huge data leaks
for web applications and companies: verbose error disclosure, cache misconfig
on sensitive endpoints, PII/tokens in API responses, and client-side storage
or inline data exposure.

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

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order

SESSION = get_session()
TIMEOUT = 6
RUN_BUDGET_SEC = 50

# Patterns that indicate verbose error / internal disclosure (redact in evidence)
ERROR_DISCLOSURE = [
    re.compile(r"(?:at\s+)?[\w\.]+\.(?:py|js|java|php|rb|go)\s*(?::\d+)?", re.I),
    re.compile(r"(?:path|file|directory):\s*[\w\/\.\-\\]+", re.I),
    re.compile(r"(?:stack\s+trace|traceback|exception|error)\s*:", re.I),
    re.compile(r"(?:internal|localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)", re.I),
    re.compile(r"(?:vendor|node_modules|app/|var/www|C:\\|/home/)[\w\/\.\-]*", re.I),
    re.compile(r"(?:postgresql|mysql|mongodb|redis|sqlite)\s*(?:connection|error|query)?", re.I),
]
# Sensitive endpoints that must not be cached (including crypto/trading user data)
SENSITIVE_PATHS = [
    "/api/user", "/api/me", "/api/profile", "/api/account", "/api/users/me",
    "/account", "/dashboard", "/profile", "/user/profile", "/api/session",
    "/api/auth/me", "/api/customer", "/api/admin/me",
    "/api/wallet", "/api/wallet/balance", "/api/positions", "/api/trades", "/api/portfolio",
    "/api/history", "/api/activity", "/api/export", "/api/webhooks", "/api/notifications",
    "/api/health", "/api/ready", "/api/version", "/api/v1/me", "/api/v2/me",
]
# Keys that suggest PII or tokens in JSON (small leak → big leak), including crypto/trading
PII_OR_TOKEN_KEYS = re.compile(
    r'"(?:email|phone|ssn|password|token|apiKey|api_key|access_token|refresh_token|'
    r'credit_card|card_number|last4|address|dob|birth_date|national_id|'
    r'wallet|wallet_address|public_key|solana_address|private_key|balance|positions)"\s*:\s*"([^"]{4,})"',
    re.I,
)
EMAIL_LIKE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
# Client-side: inline state or storage that may contain tokens/PII or wallet data
CLIENT_SIDE_PATTERNS = [
    re.compile(r"localStorage\.setItem\s*\(\s*['\"]?(?:token|auth|user|email|apiKey|wallet|privateKey)['\"]?", re.I),
    re.compile(r"sessionStorage\.(?:setItem|getItem)\s*\(\s*['\"]?(?:token|auth|user|wallet)['\"]?", re.I),
    re.compile(r"window\.__INITIAL_STATE__\s*=\s*\{[^}]*\"(?:user|token|email|auth|wallet|balance)\"\s*:", re.I),
    re.compile(r"__NEXT_DATA__|__NUXT__|__DATA__|window\.__PRELOADED", re.I),
]


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
class DataLeakRisksReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _trigger_verbose_errors(base_url: str, run_start: float) -> list[Finding]:
    """Trigger 500/400 and look for stack traces, paths, internal IPs."""
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    # Requests likely to trigger verbose errors
    probes: list[tuple] = [
        ("GET", f"{base}/api/user/../../../etc/passwd"),
        ("GET", f"{base}/'\"<>"),
        ("POST", base_url, "invalid-json"),
        ("GET", f"{base}/api/{{bad}}"),
    ]
    for item in probes:
        if _over_budget(run_start):
            break
        try:
            if len(item) == 2:
                method, req_url = item[0], item[1]
                r = SESSION.get(req_url, timeout=TIMEOUT) if method == "GET" else SESSION.post(req_url, timeout=TIMEOUT)
            else:
                method, req_url, payload = item[0], item[1], item[2]
                r = SESSION.post(req_url, data="not valid json", headers={"Content-Type": "application/json"}, timeout=TIMEOUT)
            if r.status_code not in (400, 404, 500, 502, 503):
                continue
            text = (r.text or "")[:8000]
            for pattern in ERROR_DISCLOSURE:
                if pattern.search(text):
                    evidence_snippet = text[:400].replace("\n", " ").strip()
                    findings.append(Finding(
                        title="Verbose error or internal path disclosure [CONFIRMED]",
                        severity="Medium",
                        url=req_url,
                        category="Data Leak Risks",
                        evidence=f"Response ({r.status_code}) matched internal/stack/path pattern. Snippet (sanitized): {evidence_snippet[:200]}...",
                        impact="Small disclosure that can become a big leak: attackers learn stack, paths, or internal IPs and chain into further exploitation.",
                        remediation="Return generic error pages in production; disable stack traces and path disclosure; avoid leaking framework or DB names.",
                    ))
                    return findings
        except requests.RequestException:
            continue
    return findings


def _check_cache_on_sensitive(base_url: str, run_start: float) -> list[Finding]:
    """Check that sensitive-looking endpoints send no-store or private cache headers."""
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    for path in randomize_order(SENSITIVE_PATHS)[:8]:
        if _over_budget(run_start):
            break
        url = base.rstrip("/") + path
        try:
            r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code != 200:
                continue
            cache = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()
            if not cache and "no-store" not in pragma and "no-cache" not in pragma:
                # Response might be cached by CDN/browser
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "html" in ct:
                    findings.append(Finding(
                        title="Sensitive endpoint may be cached (missing Cache-Control) [CONFIRMED]",
                        severity="Medium",
                        url=url,
                        category="Data Leak Risks",
                        evidence=f"GET {path} returned 200 with no Cache-Control (or only default). Content-Type: {ct}. Cached responses can leak to other users.",
                        impact="Small misconfig that becomes a big leak: user or session data can appear in shared caches and be served to other users.",
                        remediation="Set Cache-Control: no-store, no-cache, private for all user-specific or sensitive API and page responses.",
                    ))
                    break
        except requests.RequestException:
            continue
    return findings


def _check_pii_or_token_in_response(base_url: str, run_start: float) -> list[Finding]:
    """Check common API paths for PII or token keys in JSON response."""
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    paths = ["/api/me", "/api/user", "/api/profile", "/account", "/api/users/me", "/api/session"]
    for path in paths[:5]:
        if _over_budget(run_start):
            break
        url = base.rstrip("/") + path
        try:
            r = SESSION.get(url, timeout=TIMEOUT)
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            text = json.dumps(data)[:12000]
            if PII_OR_TOKEN_KEYS.search(text) or EMAIL_LIKE.search(text):
                findings.append(Finding(
                    title="PII or token in API response (data leak risk) [VERIFY]",
                    severity="High",
                    url=url,
                    category="Data Leak Risks",
                    evidence=f"Response at {path} contains keys or values that look like email, token, or PII. Confirm if data should be exposed to client.",
                    impact="Little exposure in one endpoint can become a huge leak if combined with cache issues, XSS, or logging.",
                    remediation="Minimize PII in API responses; never return tokens or secrets; use server-side rendering or short-lived tokens only.",
                ))
                return findings
        except requests.RequestException:
            continue
    return findings


def _check_client_side_exposure(base_url: str, run_start: float) -> list[Finding]:
    """Scan main page and inline scripts for token/PII in client-side storage or state."""
    findings: list[Finding] = []
    try:
        r = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start) or r.status_code != 200:
            return findings
        text = (r.text or "")[:100000]
        for pattern in CLIENT_SIDE_PATTERNS:
            if pattern.search(text):
                findings.append(Finding(
                    title="Token or PII in client-side storage / inline state [VERIFY]",
                    severity="Medium",
                    url=base_url,
                    category="Data Leak Risks",
                    evidence="Page or script references localStorage/sessionStorage or inline state with token/auth/user/email keys. Can leak via XSS or shared device.",
                    impact="Small client-side leak can become account takeover or data breach if combined with XSS or cache.",
                    remediation="Avoid storing tokens or PII in localStorage; use httpOnly cookies for session; minimize data in __INITIAL_STATE__ or similar.",
                ))
                return findings
    except requests.RequestException:
        pass
    return findings


def run(target_url: str, scan_type: str = "full") -> str:
    report = DataLeakRisksReport(target_url=target_url)
    run_start = time.time()
    url = target_url if target_url.startswith("http") else f"https://{target_url}"

    if scan_type not in ("full", "data_leak", "leak"):
        return json.dumps(asdict(report), indent=2)

    report.findings.extend(_trigger_verbose_errors(url, run_start))
    if not _over_budget(run_start):
        report.findings.extend(_check_cache_on_sensitive(url, run_start))
    if not _over_budget(run_start):
        report.findings.extend(_check_pii_or_token_in_response(url, run_start))
    if not _over_budget(run_start):
        report.findings.extend(_check_client_side_exposure(url, run_start))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
