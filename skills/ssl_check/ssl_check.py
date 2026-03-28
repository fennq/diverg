"""
SSL certificate validity risk signal.

Verifies HTTPS usage and checks certificate validity, expiry, issuer trust,
and hostname match. Returns structured findings compatible with the Diverg
scanning pipeline plus a dedicated ``ssl_risk_signal`` summary.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

RUN_BUDGET_SEC = 58


# ---------------------------------------------------------------------------
# Risk signal builder
# ---------------------------------------------------------------------------

def _build_risk_signal(
    *,
    valid: bool,
    days_until_expiry: int | None,
    issuer: str,
    hostname_match: bool,
    protocol: str | None,
    error: str | None = None,
) -> dict[str, Any]:
    """Return a single structured risk signal dict for the SSL check.

    Shape:
        {
            "signal": "ssl_check",
            "value": { ... detail ... },
            "risk": "high" | "medium" | "low",
            "reason": "human-readable explanation"
        }
    """
    reasons: list[str] = []
    risk = "low"

    if error:
        return {
            "signal": "ssl_check",
            "value": {"error": error},
            "risk": "high",
            "reason": f"SSL verification failed: {error}",
        }

    if not valid:
        reasons.append("Certificate is not valid")
        risk = "high"

    if days_until_expiry is not None:
        if days_until_expiry < 0:
            reasons.append(f"Certificate expired {abs(days_until_expiry)} days ago")
            risk = "high"
        elif days_until_expiry < 30:
            reasons.append(f"Certificate expires in {days_until_expiry} days")
            if risk != "high":
                risk = "medium"

    if not hostname_match:
        reasons.append("Certificate hostname mismatch")
        risk = "high"

    if protocol and protocol not in ("TLSv1.2", "TLSv1.3"):
        reasons.append(f"Weak protocol: {protocol}")
        if risk == "low":
            risk = "medium"

    if not reasons:
        reasons.append(
            f"Certificate valid for {days_until_expiry} days, issued by {issuer}"
        )

    return {
        "signal": "ssl_check",
        "value": {
            "valid": valid,
            "days_until_expiry": days_until_expiry,
            "issuer": issuer,
            "hostname_match": hostname_match,
            "protocol": protocol,
        },
        "risk": risk,
        "reason": "; ".join(reasons),
    }


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

def check_ssl(target_url: str) -> tuple[list[dict], dict[str, Any]]:
    """Return ``(findings, risk_signal)`` for *target_url*.

    ``findings`` uses the same shape as ``headers_ssl`` SSL findings so the
    orchestrator can normalize them through the existing pipeline.
    ``risk_signal`` is the dedicated summary dict.
    """
    findings: list[dict] = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "title": "HTTPS not used",
            "severity": "High",
            "url": target_url,
            "category": "Transport Security",
            "evidence": "Target URL uses plain HTTP — traffic is unencrypted.",
            "impact": "All traffic can be intercepted or modified in transit.",
            "remediation": "Serve the site over HTTPS with a valid TLS certificate.",
            "finding_type": "vulnerability",
            "confidence": "high",
        })
        signal = _build_risk_signal(
            valid=False,
            days_until_expiry=None,
            issuer="n/a",
            hostname_match=False,
            protocol=None,
            error="Site does not use HTTPS",
        )
        return findings, signal

    # --- TLS handshake & certificate inspection ---
    valid = True
    days_until_expiry: int | None = None
    issuer_str = ""
    hostname_match = True
    protocol: str | None = None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()

                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                not_after = (
                    cert.not_valid_after_utc
                    if hasattr(cert, "not_valid_after_utc")
                    else cert.not_valid_after.replace(tzinfo=timezone.utc)
                )
                now = datetime.now(timezone.utc)
                days_until_expiry = (not_after - now).days

                issuer_str = cert.issuer.rfc4514_string()

                # Expiry findings
                if days_until_expiry < 0:
                    valid = False
                    findings.append({
                        "title": "SSL certificate expired",
                        "severity": "Critical",
                        "url": target_url,
                        "category": "Transport Security",
                        "evidence": f"Certificate expired {abs(days_until_expiry)} days ago ({not_after.isoformat()})",
                        "impact": "Browsers will block access; users cannot trust the connection.",
                        "remediation": "Renew the SSL certificate immediately.",
                        "finding_type": "vulnerability",
                        "confidence": "high",
                    })
                elif days_until_expiry < 30:
                    findings.append({
                        "title": "SSL certificate expiring soon",
                        "severity": "Medium",
                        "url": target_url,
                        "category": "Transport Security",
                        "evidence": f"Certificate expires in {days_until_expiry} days ({not_after.isoformat()})",
                        "impact": "Certificate may lapse if not renewed promptly.",
                        "remediation": "Renew the SSL certificate before expiry.",
                        "finding_type": "vulnerability",
                        "confidence": "high",
                    })

                # Hostname match
                try:
                    san = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    names = san.value.get_values_for_type(x509.DNSName)
                    if hostname not in names and not any(
                        n.startswith("*.") and hostname.endswith(n[1:])
                        for n in names
                    ):
                        hostname_match = False
                        valid = False
                        findings.append({
                            "title": "SSL certificate hostname mismatch",
                            "severity": "High",
                            "url": target_url,
                            "category": "Transport Security",
                            "evidence": f"Hostname '{hostname}' not in SANs: {', '.join(names)}",
                            "impact": "Browsers will show a security warning; connection is not trustworthy.",
                            "remediation": "Obtain a certificate that covers this hostname.",
                            "finding_type": "vulnerability",
                            "confidence": "high",
                        })
                except x509.ExtensionNotFound:
                    hostname_match = False

                # Protocol strength
                if protocol and protocol not in ("TLSv1.2", "TLSv1.3"):
                    findings.append({
                        "title": f"Weak TLS protocol: {protocol}",
                        "severity": "High",
                        "url": target_url,
                        "category": "Transport Security",
                        "evidence": f"Server negotiated {protocol}, which is deprecated.",
                        "impact": "Weak protocols are susceptible to known attacks (POODLE, BEAST).",
                        "remediation": "Disable TLS 1.0/1.1 and require TLS 1.2+.",
                        "finding_type": "vulnerability",
                        "confidence": "high",
                    })

    except ssl.SSLCertVerificationError as exc:
        valid = False
        findings.append({
            "title": "SSL certificate verification failed",
            "severity": "Critical",
            "url": target_url,
            "category": "Transport Security",
            "evidence": str(exc),
            "impact": "The certificate is not trusted by the system trust store.",
            "remediation": "Use a certificate signed by a trusted CA.",
            "finding_type": "vulnerability",
            "confidence": "high",
        })
        signal = _build_risk_signal(
            valid=False,
            days_until_expiry=None,
            issuer="unknown",
            hostname_match=False,
            protocol=None,
            error=str(exc),
        )
        return findings, signal

    except (socket.timeout, OSError) as exc:
        findings.append({
            "title": "SSL connection failed",
            "severity": "High",
            "url": target_url,
            "category": "Transport Security",
            "evidence": str(exc),
            "impact": "Could not establish a secure connection to the server.",
            "remediation": "Verify the server is reachable and TLS is configured.",
            "finding_type": "vulnerability",
            "confidence": "high",
        })
        signal = _build_risk_signal(
            valid=False,
            days_until_expiry=None,
            issuer="unknown",
            hostname_match=False,
            protocol=None,
            error=str(exc),
        )
        return findings, signal

    signal = _build_risk_signal(
        valid=valid,
        days_until_expiry=days_until_expiry,
        issuer=issuer_str,
        hostname_match=hostname_match,
        protocol=protocol,
    )
    return findings, signal


# ---------------------------------------------------------------------------
# Skill entry point (matches Diverg skill contract)
# ---------------------------------------------------------------------------

def run(target_url: str, scan_type: str = "full") -> str:
    """Return JSON string with ``findings`` and ``ssl_risk_signal``."""
    findings, signal = check_ssl(target_url)
    return json.dumps({
        "target_url": target_url,
        "findings": findings,
        "ssl_risk_signal": signal,
    }, indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(target))
