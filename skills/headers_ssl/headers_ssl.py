"""
HTTP security headers and SSL/TLS configuration analysis for authorized
security assessments.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict

RUN_BUDGET_SEC = 25  # finish before bot 120s timeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, str(Path(__file__).parent.parent))
from stealth import get_session
SESSION = get_session()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    header: str
    status: str  # present / missing / misconfigured
    value: Optional[str]
    severity: str
    recommendation: str
    finding_type: str = ""
    context: str = ""


@dataclass
class SSLFinding:
    check: str
    status: str  # pass / warn / fail
    detail: str
    severity: str


@dataclass
class HeadersSSLReport:
    target_url: str
    header_findings: list[HeaderFinding] = field(default_factory=list)
    ssl_findings: list[SSLFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP security header checks
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS.",
        "finding_type": "hardening",
        "context": "If the site already redirects HTTP to HTTPS (common behind Cloudflare/CDN), real risk is lower. HSTS prevents downgrade attacks and is expected on production sites.",
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "recommendation": "Implement a Content-Security-Policy header to mitigate XSS and data injection attacks.",
        "finding_type": "hardening",
        "context": "CSP matters most on sites with user input, forms, or third-party scripts. Static sites benefit less but CSP limits damage from supply-chain compromises.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "finding_type": "hardening",
        "context": "Prevents browsers from guessing content types. Trivial to add and universally recommended. Low real-world risk on most sites.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        "finding_type": "hardening",
        "context": "Real clickjacking risk requires the page to have authenticated actions or sensitive forms. For static or marketing pages this is a best-practice gap, not an active threat.",
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' (legacy browsers) or rely on CSP.",
        "finding_type": "hardening",
        "context": "Deprecated in modern browsers. CSP is the real XSS defense. Only relevant for legacy IE/Edge clients.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
        "finding_type": "hardening",
        "context": "Mainly matters if URLs contain tokens, session IDs, or sensitive paths. Low-risk for public pages with clean URLs.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Add a Permissions-Policy header to restrict browser feature access (camera, mic, geolocation).",
        "finding_type": "hardening",
        "context": "Restricts browser APIs. Low-priority unless the site embeds third-party iframes or scripts that might request device permissions.",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "Low",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context.",
        "finding_type": "hardening",
        "context": "Isolates browsing context from cross-origin windows. Mainly relevant for sites handling sensitive data. Often unnecessary for public or static sites.",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "Low",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent cross-origin resource loading.",
        "finding_type": "hardening",
        "context": "Controls which origins can load this resource. Mainly matters for assets behind auth. Public CDN assets intentionally use cross-origin.",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Reveals web server software and version. Remove or genericize this header.",
    "X-Powered-By": "Reveals backend framework. Remove this header to reduce information leakage.",
    "X-AspNet-Version": "Reveals ASP.NET version. Remove this header.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version. Remove this header.",
}


def check_headers(target_url: str) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    try:
        resp = SESSION.get(target_url, timeout=10, allow_redirects=True)
        headers = resp.headers

        for header_name, meta in SECURITY_HEADERS.items():
            value = headers.get(header_name)
            if value:
                findings.append(HeaderFinding(
                    header=header_name,
                    status="present",
                    value=value,
                    severity="Info",
                    recommendation=f"Header is present: {value}",
                    finding_type="positive",
                    context=meta.get("context", ""),
                ))
            else:
                findings.append(HeaderFinding(
                    header=header_name,
                    status="missing",
                    value=None,
                    severity=meta["severity"],
                    recommendation=meta["recommendation"],
                    finding_type=meta.get("finding_type", "hardening"),
                    context=meta.get("context", ""),
                ))

        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"]
            if "includeSubDomains" not in hsts and "includeSubdomains" not in hsts:
                findings.append(HeaderFinding(
                    header="Strict-Transport-Security",
                    status="misconfigured",
                    value=hsts,
                    severity="Medium",
                    recommendation="Add 'includeSubDomains' directive to HSTS header.",
                ))
            if "max-age" in hsts:
                try:
                    max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        findings.append(HeaderFinding(
                            header="Strict-Transport-Security",
                            status="misconfigured",
                            value=hsts,
                            severity="Low",
                            recommendation=f"HSTS max-age is {max_age}s ({max_age // 86400} days). Recommend at least 31536000 (1 year).",
                        ))
                except (ValueError, IndexError):
                    pass

        for header_name, warning in DANGEROUS_HEADERS.items():
            value = headers.get(header_name)
            if value:
                findings.append(HeaderFinding(
                    header=header_name,
                    status="present",
                    value=value,
                    severity="Low",
                    recommendation=warning,
                ))

        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "Secure" not in cookies:
                findings.append(HeaderFinding(
                    header="Set-Cookie",
                    status="misconfigured",
                    value="Missing Secure flag",
                    severity="Medium",
                    recommendation="Add the 'Secure' flag to all cookies to prevent transmission over HTTP.",
                ))
            if "HttpOnly" not in cookies:
                findings.append(HeaderFinding(
                    header="Set-Cookie",
                    status="misconfigured",
                    value="Missing HttpOnly flag",
                    severity="Medium",
                    recommendation="Add the 'HttpOnly' flag to session cookies to prevent JavaScript access.",
                ))

    except requests.RequestException as exc:
        findings.append(HeaderFinding(
            header="CONNECTION",
            status="error",
            value=str(exc),
            severity="Info",
            recommendation="Could not connect to target.",
        ))
    return findings


# ---------------------------------------------------------------------------
# SSL/TLS analysis
# ---------------------------------------------------------------------------

WEAK_PROTOCOLS = {
    ssl.PROTOCOL_TLSv1: "TLSv1.0",
    ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
}


def check_ssl(target_url: str) -> list[SSLFinding]:
    findings: list[SSLFinding] = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append(SSLFinding(
            check="HTTPS",
            status="fail",
            detail="Target is not using HTTPS.",
            severity="High",
        ))
        return findings

    # Certificate analysis
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                protocol_version = ssock.version()
                cipher = ssock.cipher()

                findings.append(SSLFinding(
                    check="Protocol Version",
                    status="pass" if "TLSv1.3" in str(protocol_version) or "TLSv1.2" in str(protocol_version) else "warn",
                    detail=f"Negotiated protocol: {protocol_version}",
                    severity="Info" if "TLSv1.2" in str(protocol_version) or "TLSv1.3" in str(protocol_version) else "High",
                ))

                if cipher:
                    cipher_name, tls_ver, key_bits = cipher
                    findings.append(SSLFinding(
                        check="Cipher Suite",
                        status="pass",
                        detail=f"Cipher: {cipher_name}, Key bits: {key_bits}",
                        severity="Info" if key_bits >= 128 else "High",
                    ))

                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                if days_left < 0:
                    findings.append(SSLFinding(
                        check="Certificate Expiry",
                        status="fail",
                        detail=f"Certificate EXPIRED {abs(days_left)} days ago (expired: {not_after.isoformat()})",
                        severity="Critical",
                    ))
                elif days_left < 30:
                    findings.append(SSLFinding(
                        check="Certificate Expiry",
                        status="warn",
                        detail=f"Certificate expires in {days_left} days ({not_after.isoformat()})",
                        severity="Medium",
                    ))
                else:
                    findings.append(SSLFinding(
                        check="Certificate Expiry",
                        status="pass",
                        detail=f"Certificate valid for {days_left} days (expires: {not_after.isoformat()})",
                        severity="Info",
                    ))

                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                findings.append(SSLFinding(
                    check="Certificate Details",
                    status="pass",
                    detail=f"Subject: {subject}\nIssuer: {issuer}",
                    severity="Info",
                ))

                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    names = san.value.get_values_for_type(x509.DNSName)
                    if hostname not in names and not any(
                        n.startswith("*.") and hostname.endswith(n[1:]) for n in names
                    ):
                        findings.append(SSLFinding(
                            check="Certificate SAN Mismatch",
                            status="warn",
                            detail=f"Hostname '{hostname}' not found in SANs: {', '.join(names)}",
                            severity="Medium",
                        ))
                except x509.ExtensionNotFound:
                    findings.append(SSLFinding(
                        check="Subject Alternative Names",
                        status="warn",
                        detail="No SAN extension found in certificate.",
                        severity="Low",
                    ))

    except ssl.SSLCertVerificationError as exc:
        findings.append(SSLFinding(
            check="Certificate Validation",
            status="fail",
            detail=f"SSL certificate verification failed: {exc}",
            severity="Critical",
        ))
    except (socket.timeout, OSError) as exc:
        findings.append(SSLFinding(
            check="SSL Connection",
            status="fail",
            detail=f"Could not establish SSL connection: {exc}",
            severity="High",
        ))

    # Check for weak protocol support
    for proto_const, proto_name in WEAK_PROTOCOLS.items():
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    findings.append(SSLFinding(
                        check=f"Weak Protocol: {proto_name}",
                        status="fail",
                        detail=f"Server accepts deprecated {proto_name} connections.",
                        severity="High",
                    ))
        except (ssl.SSLError, OSError, AttributeError):
            findings.append(SSLFinding(
                check=f"Weak Protocol: {proto_name}",
                status="pass",
                detail=f"Server correctly rejects {proto_name}.",
                severity="Info",
            ))

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(target_url: str, scan_type: str = "full") -> str:
    report = HeadersSSLReport(target_url=target_url)
    run_start = time.time()

    if scan_type in ("full", "headers", "quick") and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            report.header_findings = check_headers(target_url)
        except Exception as exc:
            report.errors.append(f"Header analysis error: {exc}")

    if scan_type in ("full", "ssl", "quick") and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            report.ssl_findings = check_ssl(target_url)
        except Exception as exc:
            report.errors.append(f"SSL analysis error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(target, st))
