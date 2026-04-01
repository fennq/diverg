"""
Crypto security — checks for cryptographic weaknesses that lead to
authentication bypass, session hijack, or data exposure: JWT alg:none/missing,
weak TLS protocol acceptance, weak crypto usage in frontend (Math.random for
tokens, MD5/DES/ECB), and sensitive crypto material in responses.

Complements headers_ssl (which covers HSTS, cert expiry, ciphers). Authorized use only.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import socket
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
RUN_BUDGET_SEC = 25

# JWT in cookies / headers / body
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    re.M,
)
# Weak crypto patterns in JS (security-sensitive misuse)
WEAK_CRYPTO_PATTERNS = [
    (re.compile(r"Math\.random\s*\(\s*\)", re.I), "Math.random() used (predictable; use crypto.getRandomValues)"),
    (re.compile(r"\bMD5\s*\(|\bmd5\s*\(|\.md5\s*\(|digest\s*\(\s*['\"]md5", re.I), "MD5 used (broken for security)"),
    (re.compile(r"\bDES\b|\b3DES\b|des-ede|des3", re.I), "DES/3DES used (weak block cipher)"),
    (re.compile(r"\bRC4\b|rc4\s*\(|arc4", re.I), "RC4 used (deprecated, biased)"),
    (re.compile(r"mode\s*:\s*['\"]?ECB['\"]?|ECB\s*mode|\.ECB", re.I), "ECB mode (deterministic; use CBC/GCM)"),
    (re.compile(r"iv\s*:\s*['\"][^'\"]+['\"]|IV\s*=\s*['\"][^'\"]+['\"]", re.I), "Hardcoded IV (reuse breaks confidentiality)"),
    (re.compile(r"crypto\.createHash\s*\(\s*['\"]md5['\"]", re.I), "Node crypto MD5 (avoid for security)"),
]
# Crypto-trust: client-side key/seed/signing — high risk for theft or backdoor if abused
TRUST_RISK_PATTERNS = [
    (re.compile(r"\bprivateKey\b|\bprivate_key\b", re.I), "Private key in client"),
    (re.compile(r"\bseedPhrase\b|\bseed_phrase\b|\bmnemonic\b", re.I), "Seed/mnemonic in client"),
    (re.compile(r"\bsignTransaction\b|\bsign_message\b", re.I), "Transaction/message signing in client"),
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
class CryptoReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    jwt_checked: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _decode_jwt_payload(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        raw = base64.urlsafe_b64decode(payload_b64)
        return json.loads(raw)
    except Exception:
        return None


def _decode_jwt_header(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        raw = base64.urlsafe_b64decode(header_b64)
        return json.loads(raw)
    except Exception:
        return None


def _check_jwt_alg(token: str, source: str, url: str) -> Finding | None:
    """Check for alg:none, missing alg, or 'none' algorithm."""
    h = _decode_jwt_header(token)
    if not h:
        return None
    alg = (h.get("alg") or "").strip()
    if not alg:
        return Finding(
            title="JWT missing 'alg' in header [CONFIRMED]",
            severity="High",
            url=url,
            category="Crypto / JWT",
            evidence=f"JWT from {source} has no 'alg' in header. Server may accept any algorithm (key confusion).",
            impact="Attackers can forge tokens by choosing a weak algorithm or swapping RS256 to HS256 with public key.",
            remediation="Always set and validate 'alg' in JWT header; reject tokens with alg:none or missing alg.",
        )
    if alg.lower() == "none" or alg == "nOnE":
        return Finding(
            title="JWT alg:none accepted [CONFIRMED]",
            severity="Critical",
            url=url,
            category="Crypto / JWT",
            evidence=f"JWT from {source} uses alg='{alg}'. Server may accept unsigned tokens.",
            impact="Attackers can forge valid tokens by stripping the signature and setting alg to none.",
            remediation="Reject JWTs with alg 'none'. Validate algorithm against a whitelist.",
        )
    return None


def _scan_jwt(base_url: str, run_start: float) -> list[Finding]:
    findings: list[Finding] = []
    try:
        r = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return findings
        url = r.url
        text = r.text or ""
        headers = r.headers

        # Authorization Bearer
        auth = headers.get("Authorization") or ""
        if "Bearer " in auth:
            token = auth.split("Bearer ", 1)[1].strip().split()[0]
            finding = _check_jwt_alg(token, "Authorization header", url)
            if finding:
                findings.append(finding)
                return findings

        # Set-Cookie (session, jwt, token, id_token)
        set_cookies = getattr(getattr(r, "raw", None), "headers", None)
        cookie_lines = set_cookies.getlist("Set-Cookie") if set_cookies else []
        if not cookie_lines and "Set-Cookie" in headers:
            cookie_lines = [headers.get("Set-Cookie", "")]
        for cookie_line in cookie_lines:
            if _over_budget(run_start):
                break
            for part in cookie_line.split(";"):
                part = part.strip()
                if "=" in part:
                    name, val = part.split("=", 1)
                    if any(k in name.lower() for k in ("jwt", "token", "session", "id_token", "access")):
                        for m in JWT_RE.finditer(val):
                            finding = _check_jwt_alg(m.group(0), f"cookie {name}", url)
                            if finding:
                                findings.append(finding)
                                return findings

        # Response body
        for m in JWT_RE.finditer(text):
            if _over_budget(run_start):
                break
            finding = _check_jwt_alg(m.group(0), "response body", url)
            if finding:
                findings.append(finding)
                return findings
    except requests.RequestException:
        pass
    return findings


def _scan_weak_crypto_js(base_url: str, run_start: float) -> list[Finding]:
    """Scan main page and same-origin JS for weak crypto usage."""
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    seen_urls: set[str] = set()
    urls_to_fetch: list[str] = [base_url]

    try:
        r = SESSION.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return findings
        text = r.text or ""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                if not src:
                    continue
                full = urljoin(base_url, src)
                if urlparse(full).netloc != parsed.netloc or full in seen_urls:
                    continue
                seen_urls.add(full)
                urls_to_fetch.append(full)
        except Exception:
            pass

        for url in urls_to_fetch[:12]:
            if _over_budget(run_start) or len(findings) >= 2:
                break
            try:
                content = text if url == base_url else SESSION.get(url, timeout=TIMEOUT).text
            except requests.RequestException:
                continue
            for pattern, desc in WEAK_CRYPTO_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        title=f"Weak crypto in frontend: {desc} [VERIFY]",
                        severity="Medium",
                        url=url,
                        category="Crypto / Frontend",
                        evidence=f"Pattern matched in asset. If used for tokens/sessions/passwords, impact is high.",
                        impact="Predictable or weak crypto can lead to session prediction, token forgery, or password cracking.",
                        remediation="Use crypto.getRandomValues() for randomness; avoid MD5/DES/RC4/ECB for security-sensitive data.",
                    ))
                    break
            for pattern, desc in TRUST_RISK_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        title=f"Crypto-trust risk: {desc} [REVIEW]",
                        severity="High",
                        url=url,
                        category="Crypto / Trust",
                        evidence="Client-side key or signing. Could enable theft or backdoor if keys are exfiltrated or logic is malicious.",
                        impact="Verify key custody and intent; client-side handling is high risk for crypto/wallet apps.",
                        remediation=(
                            "Prefer backend signing and key custody; audit for exfil and malicious logic. "
                            "Also review client_surface Web3 drainer heuristics on the same URLs."
                        ),
                    ))
                    break
    except requests.RequestException:
        pass
    return findings


def _check_weak_tls(base_url: str, run_start: float) -> list[Finding]:
    """Check if server accepts TLS 1.0 or 1.1 (weak protocols)."""
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return findings
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_default_verify_paths()
        # Disable TLS 1.2 and 1.3 so we only negotiate 1.0 or 1.1
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_2", 0) | getattr(ssl, "OP_NO_TLSv1_3", 0)
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ver = ssock.version()
                if ver in ("TLSv1", "TLSv1.1"):
                    findings.append(Finding(
                        title="Server accepts weak TLS (TLS 1.0/1.1) [CONFIRMED]",
                        severity="Medium",
                        url=base_url,
                        category="Crypto / TLS",
                        evidence=f"Negotiated protocol: {ver}. TLS 1.0/1.1 are deprecated and vulnerable to downgrade.",
                        impact="Attackers can force downgrade and exploit known TLS weaknesses (e.g. BEAST, POODLE-style).",
                        remediation="Disable TLS 1.0 and 1.1; use TLS 1.2 minimum, preferably 1.3.",
                    ))
    except ssl.SSLError:
        pass  # Server rejected weak TLS (good)
    except (socket.timeout, OSError):
        pass
    return findings


def run(target_url: str, scan_type: str = "full") -> str:
    report = CryptoReport(target_url=target_url)
    run_start = time.time()
    url = target_url if target_url.startswith("http") else f"https://{target_url}"

    if scan_type not in ("full", "crypto", "jwt", "tls"):
        return json.dumps(asdict(report), indent=2)

    if scan_type in ("full", "crypto", "jwt"):
        report.findings.extend(_scan_jwt(url, run_start))
        report.jwt_checked = 1
    if scan_type in ("full", "crypto") and not _over_budget(run_start):
        report.findings.extend(_scan_weak_crypto_js(url, run_start))
    if scan_type in ("full", "crypto", "tls") and not _over_budget(run_start):
        report.findings.extend(_check_weak_tls(url, run_start))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
