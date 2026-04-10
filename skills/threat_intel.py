"""
Threat Intelligence enrichment skill.

Checks discovered IPs, domains, and URLs against free TI feeds:
- AbuseIPDB  (IP reputation; requires ABUSEIPDB_API_KEY, free tier 1000/day)
- URLhaus    (malicious URLs; keyless)
- ThreatFox  (IOCs — domains, IPs; keyless)

Runs as a Phase 2 skill after recon + osint provide target infrastructure data.
Graceful degradation: feeds without keys are silently skipped.

Authorized use only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 6
RUN_BUDGET_SEC = 30

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_PRIVATE_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


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
class ThreatIntelReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    checked_ips: list[str] = field(default_factory=list)
    checked_domains: list[str] = field(default_factory=list)
    checked_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    feeds_queried: list[str] = field(default_factory=list)


def _is_public_ip(ip: str) -> bool:
    return bool(_IPV4_RE.match(ip) and not _PRIVATE_RE.match(ip))


def _extract_ips_from_recon(recon_json: str) -> list[str]:
    ips: list[str] = []
    try:
        data = json.loads(recon_json)
    except Exception:
        return ips
    for ip in data.get("resolved_ips", []) or []:
        if isinstance(ip, str) and _is_public_ip(ip) and ip not in ips:
            ips.append(ip)
    for sub in data.get("subdomains", []) or []:
        if isinstance(sub, dict):
            ip = sub.get("ip", "")
            if isinstance(ip, str) and _is_public_ip(ip) and ip not in ips:
                ips.append(ip)
    dns_records = data.get("dns_records") or data.get("dns", {})
    if isinstance(dns_records, dict):
        for rtype in ("A", "AAAA"):
            for val in dns_records.get(rtype, []) or []:
                v = str(val).strip()
                if _is_public_ip(v) and v not in ips:
                    ips.append(v)
    return ips[:50]


def _extract_domains_from_osint(osint_json: str) -> list[str]:
    domains: list[str] = []
    try:
        data = json.loads(osint_json)
    except Exception:
        return domains
    for key in ("associated_domains", "domains", "subdomains"):
        for d in data.get(key, []) or []:
            domain = str(d).strip().lower() if isinstance(d, str) else ""
            if not domain:
                if isinstance(d, dict):
                    domain = str(d.get("domain") or d.get("name") or "").strip().lower()
            if domain and "." in domain and domain not in domains:
                domains.append(domain)
    return domains[:50]


def _check_abuseipdb(ip: str, api_key: str) -> Finding | None:
    """Query AbuseIPDB for IP reputation."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        if score < 10 and reports < 3:
            return None

        if score >= 80:
            severity = "High"
        elif score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        country = data.get("countryCode", "")
        isp = (data.get("isp") or "")[:60]
        usage = (data.get("usageType") or "")[:40]
        domain_str = (data.get("domain") or "")[:60]

        return Finding(
            title=f"IP {ip} flagged by AbuseIPDB (confidence: {score}%)",
            severity=severity,
            url=f"https://www.abuseipdb.com/check/{ip}",
            category="Threat Intelligence",
            evidence=(
                f"AbuseIPDB confidence: {score}%, total reports: {reports}. "
                f"ISP: {isp}, country: {country}, usage: {usage}, domain: {domain_str}"
            ),
            impact=(
                "This IP address has been reported for malicious activity. "
                "If it hosts your infrastructure, it may be compromised or co-hosted with malicious actors."
            ),
            remediation=(
                "Investigate the IP's association with your infrastructure. "
                "If it is a third-party host, consider migrating to a reputable provider. "
                "Check for signs of compromise."
            ),
        )
    except Exception:
        return None


def _check_urlhaus(url: str) -> Finding | None:
    """Query URLhaus for known malicious URLs."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        status = data.get("query_status", "")
        if status != "listed" and status != "online":
            return None

        threat = (data.get("threat") or "malware")[:60]
        tags = ", ".join(data.get("tags") or [])[:100]
        date_added = (data.get("date_added") or "")[:20]

        return Finding(
            title=f"URL flagged by URLhaus: {url[:80]}",
            severity="High",
            url=url,
            category="Threat Intelligence",
            evidence=(
                f"URLhaus status: {status}. Threat: {threat}. "
                f"Tags: {tags}. Date added: {date_added}"
            ),
            impact="This URL is associated with malware distribution or malicious activity.",
            remediation=(
                "If this URL is part of your infrastructure, investigate immediately for compromise. "
                "If it is a third-party resource loaded by your site, remove the reference."
            ),
        )
    except Exception:
        return None


def _check_urlhaus_domain(domain: str) -> list[Finding]:
    """Query URLhaus for known malicious URLs on a domain."""
    findings: list[Finding] = []
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return findings
        data = resp.json()
        if data.get("query_status") != "listed" and \
           not (data.get("urls") and len(data.get("urls", [])) > 0):
            return findings

        url_count = int(data.get("url_count", 0) or 0)
        if url_count == 0:
            return findings

        urls_online = data.get("urls_online", 0)

        findings.append(Finding(
            title=f"Domain {domain} has {url_count} URLhaus entries",
            severity="High" if urls_online else "Medium",
            url=f"https://urlhaus.abuse.ch/host/{domain}/",
            category="Threat Intelligence",
            evidence=(
                f"URLhaus: {url_count} malicious URLs associated with {domain}. "
                f"Currently online: {urls_online}"
            ),
            impact="This domain is associated with malware distribution.",
            remediation="Investigate the domain's reputation and consider blocking or migrating.",
        ))
    except Exception:
        pass
    return findings


def _check_threatfox_ip(ip: str) -> Finding | None:
    """Query ThreatFox for IOCs associated with an IP."""
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("query_status") != "ok":
            return None
        iocs = data.get("data") or []
        if not iocs:
            return None

        malware = set()
        threat_types = set()
        for ioc in iocs[:10]:
            mw = (ioc.get("malware") or "")[:40]
            tt = (ioc.get("threat_type") or "")[:30]
            if mw:
                malware.add(mw)
            if tt:
                threat_types.add(tt)

        return Finding(
            title=f"IP {ip} found in ThreatFox IOC database",
            severity="High",
            url=f"https://threatfox.abuse.ch/browse/?search=ioc%3A{ip}",
            category="Threat Intelligence",
            evidence=(
                f"ThreatFox: {len(iocs)} IOC(s) associated with {ip}. "
                f"Malware: {', '.join(list(malware)[:5]) or 'unknown'}. "
                f"Threat types: {', '.join(list(threat_types)[:5]) or 'unknown'}"
            ),
            impact="This IP has been linked to known malware or threat campaigns.",
            remediation="Investigate infrastructure ties to this IP. Consider blocking if external.",
        )
    except Exception:
        return None


def _check_threatfox_domain(domain: str) -> Finding | None:
    """Query ThreatFox for IOCs associated with a domain."""
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("query_status") != "ok":
            return None
        iocs = data.get("data") or []
        if not iocs:
            return None

        malware = set()
        for ioc in iocs[:10]:
            mw = (ioc.get("malware") or "")[:40]
            if mw:
                malware.add(mw)

        return Finding(
            title=f"Domain {domain} found in ThreatFox IOC database",
            severity="High",
            url=f"https://threatfox.abuse.ch/browse/?search=ioc%3A{domain}",
            category="Threat Intelligence",
            evidence=(
                f"ThreatFox: {len(iocs)} IOC(s) for {domain}. "
                f"Malware: {', '.join(list(malware)[:5]) or 'unknown'}"
            ),
            impact="This domain has been linked to malware or C2 infrastructure.",
            remediation="Investigate and consider blocking or migrating services from this domain.",
        )
    except Exception:
        return None


def run(
    target_url: str,
    scan_type: str = "full",
    recon_json: Optional[str] = None,
    osint_json: Optional[str] = None,
) -> str:
    report = ThreatIntelReport(target_url=target_url)
    run_start = time.time()

    abuseipdb_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()

    ips = _extract_ips_from_recon(recon_json) if recon_json else []
    domains = _extract_domains_from_osint(osint_json) if osint_json else []

    target_domain = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
    if target_domain and target_domain not in domains:
        domains.insert(0, target_domain)

    report.checked_ips = ips
    report.checked_domains = domains

    if abuseipdb_key:
        report.feeds_queried.append("abuseipdb")
        for ip in ips:
            if time.time() - run_start > RUN_BUDGET_SEC:
                break
            finding = _check_abuseipdb(ip, abuseipdb_key)
            if finding:
                report.findings.append(finding)

    report.feeds_queried.append("urlhaus")
    for domain in domains[:20]:
        if time.time() - run_start > RUN_BUDGET_SEC:
            break
        findings = _check_urlhaus_domain(domain)
        report.findings.extend(findings)

    report.feeds_queried.append("threatfox")
    for ip in ips[:15]:
        if time.time() - run_start > RUN_BUDGET_SEC:
            break
        finding = _check_threatfox_ip(ip)
        if finding:
            report.findings.append(finding)

    for domain in domains[:15]:
        if time.time() - run_start > RUN_BUDGET_SEC:
            break
        finding = _check_threatfox_domain(domain)
        if finding:
            report.findings.append(finding)

    if not report.findings:
        report.findings.append(Finding(
            title="No threat intelligence hits",
            severity="Info",
            url=target_url,
            category="Threat Intelligence",
            evidence=(
                f"Checked {len(ips)} IP(s) and {len(domains)} domain(s) against "
                f"{', '.join(report.feeds_queried)}. No matches found."
            ),
            impact="No known threats associated with the target's infrastructure.",
            remediation="Continue periodic monitoring.",
        ))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url))
