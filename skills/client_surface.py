"""
Client-surface / code-intel skill — APT-style upgrade.
Fetches frontend JS, discovers source maps, extracts API shapes and dangerous sinks,
so we find exploit-prone code paths before an attacker does.

- Source map discovery and basic parsing (count of sources).
- API shape extraction: fetch(..., axios.(get|post)(..., /api/... paths from JS.
- Dangerous sinks: eval(, new Function(, innerHTML, document.write, insertAdjacentHTML.
- postMessage usage and localStorage/sessionStorage with sensitive keys.
- Output: findings + extracted_endpoints for downstream tests.

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
TIMEOUT = 8
RUN_BUDGET_SEC = 50
MAX_JS_FILES = 12
MAX_JS_BYTES = 2 * 1024 * 1024  # 2MB per file cap

# Source map URL at end of JS file
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=(.+)", re.I)
SOURCE_MAP_INLINE = re.compile(r"//#\s*sourceMappingURL=data:application/json[^,]*,(.+)", re.I)

# API shape extraction (path-like strings in fetch/axios)
FETCH_URL_RE = re.compile(r"fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
FETCH_TEMPLATE_RE = re.compile(r"fetch\s*\(\s*`([^`]*)`", re.I)
AXIOS_RE = re.compile(r"axios\.(get|post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
API_PATH_RE = re.compile(r"['\"`](/api[^'\"`\s]*)['\"`]", re.I)
ENDPOINT_GENERIC = re.compile(r"['\"`](/(?:api|v1|v2|graphql|rest)[^'\"`\s]*)['\"`]", re.I)

# Dangerous sinks (user-influenced input can reach these)
DANGEROUS_SINKS = [
    (re.compile(r"\beval\s*\(", re.I), "eval()", "High"),
    (re.compile(r"new\s+Function\s*\(", re.I), "new Function()", "High"),
    (re.compile(r"\.innerHTML\s*=", re.I), "innerHTML assignment", "Medium"),
    (re.compile(r"document\.write\s*\(", re.I), "document.write()", "Medium"),
    (re.compile(r"\.insertAdjacentHTML\s*\(", re.I), "insertAdjacentHTML()", "Medium"),
    (re.compile(r"\.outerHTML\s*=", re.I), "outerHTML assignment", "Medium"),
    (re.compile(r"document\.writeln\s*\(", re.I), "document.writeln()", "Medium"),
]
# postMessage (origin validation bugs)
POST_MESSAGE_RE = re.compile(r"postMessage\s*\(|addEventListener\s*\(\s*['\"]message['\"]", re.I)
# Storage with sensitive keys (we only report presence, not value)
STORAGE_SENSITIVE_RE = re.compile(
    r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"`]?(?:token|auth|apiKey|secret|password|wallet|privateKey)['\"`]?",
    re.I,
)
# Third-party fetch/axios URL (full URL, not same-origin) — exfil risk if combined with sensitive data
THIRD_PARTY_FETCH_RE = re.compile(
    r"(?:fetch|axios\.(?:get|post|put|patch))\s*\(\s*['\"]https?://([^/'\"]+)",
    re.I,
)
SENSITIVE_PARAM_IN_SNIPPET = re.compile(
    r"\b(?:email|token|user_id|userId|wallet|password|phone|ssn|privateKey|apiKey|auth)\b",
    re.I,
)
# Crypto-trust: client-side key/seed/signing — high risk for theft or backdoor if abused
CRYPTO_TRUST_PATTERNS = [
    (re.compile(r"\bprivateKey\b|\bprivate_key\b", re.I), "Private key referenced in client"),
    (re.compile(r"\bseedPhrase\b|\bseed_phrase\b|\bmnemonic\b", re.I), "Seed/mnemonic in client"),
    (re.compile(r"\bsignTransaction\b|\bsign_message\b", re.I), "Transaction/message signing in client"),
    (re.compile(r"\brecover\s*\(|\bwallet\.recover\b", re.I), "Wallet recover in client"),
    (re.compile(r"\bapprove\s*\(\s*.*address|\btransfer\s*\(\s*.*to\s*:", re.I), "Approve/transfer to address in client"),
]
VERSION_PATTERNS = [
    (re.compile(r'"next"\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']', re.I), "Next.js"),
    (re.compile(r'"react"\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']', re.I), "React"),
    (re.compile(r'__NEXT_DATA__.*?"buildId"\s*:\s*["\']([^"\']+)["\']', re.I), "Next.js (buildId)"),
    (re.compile(r'next\/v([0-9]+\.[0-9]+\.[0-9]+)', re.I), "Next.js"),
    (re.compile(r'react-dom@([0-9]+\.[0-9]+\.[0-9]+)', re.I), "React"),
    (re.compile(r'"vue"\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']', re.I), "Vue.js"),
    (re.compile(r'angular\.core["\']?\s*[,\s].*?["\']([0-9]+\.[0-9]+\.[0-9]+)["\']', re.I), "Angular"),
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
class ClientSurfaceReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    extracted_endpoints: list[str] = field(default_factory=list)
    detected_versions: list[dict] = field(default_factory=list)  # [{"product": "Next.js", "version": "14.0.0", "source": "js"}]
    source_map_count: int = 0
    js_files_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _collect_js_urls(base_url: str, run_start: float, max_files: int = MAX_JS_FILES) -> list[str]:
    """Get main page and collect same-origin script src URLs (limit max_files)."""
    urls: list[str] = []
    try:
        resp = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start) or resp.status_code != 200:
            return urls
        parsed = urlparse(base_url)
        domain = parsed.netloc
        scheme = parsed.scheme or "https"
        base = f"{scheme}://{domain}"
        text = resp.text
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                if not src or src.startswith("data:"):
                    continue
                full = urljoin(base_url, src)
                if urlparse(full).netloc != domain:
                    continue
                if full not in urls:
                    urls.append(full)
                if len(urls) >= max_files:
                    break
        except Exception:
            pass
    except requests.RequestException:
        pass
    return urls[:max_files]


def _fetch_js_content(url: str, run_start: float) -> str:
    try:
        r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start) or r.status_code != 200:
            return ""
        return (r.text or "")[:MAX_JS_BYTES]
    except requests.RequestException:
        return ""


def _extract_api_paths(js_content: str) -> set[str]:
    """Extract API-like paths from JS (fetch, axios, string literals)."""
    paths: set[str] = set()
    for pattern in (FETCH_URL_RE, AXIOS_RE, API_PATH_RE, ENDPOINT_GENERIC):
        for m in pattern.finditer(js_content):
            if m.lastindex and m.lastindex >= 1:
                p = m.group(2) if m.lastindex >= 2 else m.group(1)
            else:
                p = m.group(1)
            if p and p.startswith("/") and len(p) < 300:
                paths.add(p.split("?")[0].rstrip("/") or "/")
    for m in FETCH_TEMPLATE_RE.finditer(js_content):
        segment = m.group(1)
        for part in re.findall(r"/api[^\s`${}\"]+", segment):
            paths.add(part.split("?")[0].rstrip("/") or "/")
    return paths


def _extract_versions(js_content: str, source_url: str) -> list[dict]:
    """Extract product/version hints from JS for dependency/CVE step."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for pattern, product in VERSION_PATTERNS:
        for m in pattern.finditer(js_content):
            ver = m.group(1).strip() if m.lastindex else ""
            if ver and len(ver) < 50 and (product, ver) not in seen:
                seen.add((product, ver))
                out.append({"product": product, "version": ver, "source": source_url})
    return out


def _check_dangerous_sinks(js_content: str, source_label: str, source_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, name, sev in DANGEROUS_SINKS:
        if pattern.search(js_content):
            findings.append(Finding(
                title=f"Dangerous sink in {source_label}: {name} [VERIFY]",
                severity=sev,
                url=source_url,
                category="Client-Side Security",
                evidence="Pattern matched in JS. If user-controlled data reaches this sink, XSS or code execution is possible.",
                impact="Attackers may achieve XSS or execute script if they control input that flows to this sink.",
                remediation="Avoid eval/new Function with user input. Sanitize and CSP for innerHTML/document.write.",
            ))
            break
    if POST_MESSAGE_RE.search(js_content):
        findings.append(Finding(
            title=f"postMessage / message listener in {source_label} [REVIEW]",
            severity="Low",
            url=source_url,
            category="Client-Side Security",
            evidence="postMessage or addEventListener('message') found. Verify origin validation to prevent cross-origin abuse.",
            impact="Missing origin check can lead to cross-origin data theft or command injection.",
            remediation="Always validate event.origin (allowlist) before processing postMessage.",
        ))
    if STORAGE_SENSITIVE_RE.search(js_content):
        findings.append(Finding(
            title=f"Sensitive key in storage access in {source_label} [REVIEW]",
            severity="Medium",
            url=source_url,
            category="Client-Side Security",
            evidence="localStorage/sessionStorage used with token/auth/apiKey/secret/password/wallet. Verify secrets are not stored in client.",
            impact="Secrets in client storage are readable by any script on the page (XSS) or extensions.",
            remediation="Do not store secrets in localStorage/sessionStorage. Use httpOnly cookies or backend-only storage.",
        ))
    return findings


def _check_third_party_exfil(js_content: str, js_url: str, base_domain: str) -> list[Finding]:
    """Flag when sensitive-looking data may be sent to third-party domains (exfil / data-risk)."""
    findings: list[Finding] = []
    base_domain_clean = base_domain.lower().replace("www.", "").split(":")[0]
    for m in THIRD_PARTY_FETCH_RE.finditer(js_content):
        host = (m.group(1) or "").lower().split(":")[0].replace("www.", "")
        if not host or host == base_domain_clean:
            continue
        # Look in a window around the match for sensitive param names
        start = max(0, m.start() - 300)
        end = min(len(js_content), m.end() + 300)
        window = js_content[start:end]
        if SENSITIVE_PARAM_IN_SNIPPET.search(window):
            findings.append(Finding(
                title="Sensitive-looking data may be sent to third-party domain [REVIEW]",
                severity="Medium",
                url=js_url,
                category="Data Exfiltration Risk",
                evidence=f"fetch/axios to https://{host} with email/token/wallet/user-like params nearby. Verify this is intended and compliant; could enable data theft or misuse.",
                impact="PII or credentials sent to third party could be logged, resold, or abused. We cannot determine intent — verify data flows and contracts.",
                remediation="Audit all outbound requests; ensure third parties are trusted and data handling is compliant. Do not send tokens or PII to untrusted domains.",
            ))
            break
    return findings


def _check_crypto_trust(js_content: str, source_label: str, source_url: str) -> list[Finding]:
    """Flag client-side key/seed/signing patterns — high risk for theft or backdoor if abused."""
    findings: list[Finding] = []
    for pattern, name in CRYPTO_TRUST_PATTERNS:
        if pattern.search(js_content):
            findings.append(Finding(
                title=f"Crypto-trust: {name} in {source_label} [REVIEW]",
                severity="High",
                url=source_url,
                category="Crypto / Trust",
                evidence=f"Pattern matched in client JS. Client-side key handling or signing can enable theft or backdoor if keys are exfiltrated or logic is malicious.",
                impact="If keys or signing are handled in frontend, XSS or a malicious script could drain wallets or sign unauthorized transactions. Verify custody and intent.",
                remediation="Prefer backend signing and key custody. If client-side is required, use hardened enclaves and minimal exposure; audit for exfil paths.",
            ))
            break
    return findings


def _check_source_map(js_content: str, js_url: str, run_start: float) -> tuple[int, list[Finding]]:
    """Return (count of sources in map if fetched, findings list)."""
    findings: list[Finding] = []
    m = SOURCE_MAP_RE.search(js_content)
    if not m:
        return 0, findings
    map_url_raw = m.group(1).strip()
    if map_url_raw.startswith("data:"):
        # Inline source map
        try:
            import base64
            b64 = map_url_raw.split(",", 1)[-1]
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            n = len(data.get("sources", []))
            findings.append(Finding(
                title="Source map exposed inline in JS [INFO]",
                severity="Info",
                url=js_url,
                category="Client-Side Security",
                evidence=f"Inline source map contains {n} source file references. Decompiled code can be used to find logic bugs or hidden endpoints.",
                impact="Attackers can reconstruct original source and find vulnerabilities faster.",
                remediation="Disable source maps in production or restrict access to debug builds.",
            ))
            return n, findings
        except Exception:
            return 0, findings
    map_url = urljoin(js_url, map_url_raw)
    try:
        r = SESSION.get(map_url, timeout=TIMEOUT)
        if _over_budget(run_start) or r.status_code != 200:
            return 0, findings
        data = r.json()
        n = len(data.get("sources", []))
        findings.append(Finding(
            title="Source map publicly accessible [INFO]",
            severity="Info",
            url=map_url,
            category="Client-Side Security",
            evidence=f"Source map at {map_url_raw} returned 200 with {n} sources. Original paths/symbols can be reconstructed.",
            impact="Attackers can recover full source and find logic bugs, hidden APIs, or secrets.",
            remediation="Do not serve .map files in production or protect by auth.",
        ))
        return n, findings
    except Exception:
        return 0, findings


def run(target_url: str, scan_type: str = "full") -> str:
    report = ClientSurfaceReport(target_url=target_url)
    run_start = time.time()
    parsed = urlparse(target_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"

    deep = (scan_type or "").lower() == "deep"
    max_js = 24 if deep else MAX_JS_FILES
    js_urls = _collect_js_urls(target_url, run_start, max_files=max_js)
    report.js_files_scanned = len(js_urls)
    all_endpoints: set[str] = set()
    seen_sink_findings: set[str] = set()

    for js_url in randomize_order(js_urls):
        if _over_budget(run_start):
            break
        content = _fetch_js_content(js_url, run_start)
        if not content:
            continue
        label = "JS"
        if "chunk" in js_url.lower():
            label = "chunk"
        elif "main" in js_url.lower() or "app." in js_url.lower():
            label = "main"
        elif "vendor" in js_url.lower():
            label = "vendor"

        all_endpoints.update(_extract_api_paths(content))
        n_sources, map_findings = _check_source_map(content, js_url, run_start)
        report.source_map_count += 1 if n_sources > 0 else 0
        report.findings.extend(map_findings)
        for d in _extract_versions(content, js_url):
            key = (d["product"], d["version"])
            if not any((x["product"], x["version"]) == key for x in report.detected_versions):
                report.detected_versions.append(d)
        for f in _check_dangerous_sinks(content, label, js_url):
            key = (f.title, js_url)
            if key not in seen_sink_findings:
                seen_sink_findings.add(key)
                report.findings.append(f)
        for f in _check_third_party_exfil(content, js_url, parsed.netloc):
            key = (f.title, js_url)
            if key not in seen_sink_findings:
                seen_sink_findings.add(key)
                report.findings.append(f)
        for f in _check_crypto_trust(content, label, js_url):
            key = (f.title, js_url)
            if key not in seen_sink_findings:
                seen_sink_findings.add(key)
                report.findings.append(f)

    report.extracted_endpoints = sorted(all_endpoints)[:80]
    if report.extracted_endpoints and not any("extracted_endpoints" in f.evidence for f in report.findings):
        report.findings.append(Finding(
            title="API endpoints extracted from client JS [INFO]",
            severity="Info",
            url=target_url,
            category="Client-Side Security",
            evidence=f"Found {len(report.extracted_endpoints)} path-like strings (fetch/axios/literals). Use for targeted API testing. Sample: " + ", ".join(report.extracted_endpoints[:8]),
            impact="Client-known endpoints may not be in server docs; test for auth bypass and parameter abuse.",
            remediation="Ensure API docs and auth coverage match what the frontend actually calls.",
        ))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url))
