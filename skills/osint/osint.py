"""
OSINT (Open-Source Intelligence) gathering skill — WHOIS lookups, DNS
record enumeration, email pattern discovery, Wayback Machine history,
certificate transparency subdomain harvesting, Google dork generation,
technology & infrastructure fingerprinting, social media discovery,
and data breach exposure checks.
"""

from __future__ import annotations

import json
import re
import smtplib
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import dns.resolver
import requests
import whois

sys.path.insert(0, str(Path(__file__).parent.parent))
from stealth import get_session
SESSION = get_session()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WHOISInfo:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    org: Optional[str] = None
    registrant_name: Optional[str] = None  # registrant / name from WHOIS for owner research
    country: Optional[str] = None
    emails: list[str] = field(default_factory=list)
    dnssec: Optional[str] = None


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0


@dataclass
class EmailPattern:
    pattern: str
    source: str
    confidence: str  # high / medium / low


@dataclass
class WaybackSnapshot:
    url: str
    timestamp: str
    status_code: Optional[str] = None
    category: Optional[str] = None


@dataclass
class SubdomainEntry:
    subdomain: str
    source: str


@dataclass
class GoogleDork:
    query: str
    category: str
    description: str


@dataclass
class TechInfraInfo:
    ip_addresses: list[str] = field(default_factory=list)
    reverse_dns: dict[str, str] = field(default_factory=dict)
    asn_info: Optional[str] = None
    cdn_detected: Optional[str] = None
    cdn_indicators: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    spf_analysis: Optional[str] = None
    dkim_records: dict[str, str] = field(default_factory=dict)
    dmarc_record: Optional[str] = None
    dmarc_analysis: Optional[str] = None
    mx_records: list[dict[str, str]] = field(default_factory=list)
    email_provider: Optional[str] = None
    server_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class SocialMediaProfile:
    platform: str
    url: str
    exists: bool
    status_code: Optional[int] = None


@dataclass
class BreachInfo:
    source: str
    status: str
    details: Optional[str] = None


@dataclass
class OSINTReport:
    target: str
    whois_info: Optional[WHOISInfo] = None
    dns_records: list[DNSRecord] = field(default_factory=list)
    email_patterns: list[EmailPattern] = field(default_factory=list)
    wayback_snapshots: list[WaybackSnapshot] = field(default_factory=list)
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    google_dorks: list[GoogleDork] = field(default_factory=list)
    tech_infra: Optional[TechInfraInfo] = None
    social_media: list[SocialMediaProfile] = field(default_factory=list)
    breach_info: list[BreachInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# WHOIS lookup
# ---------------------------------------------------------------------------

def _safe_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        return str(val[0]) if val else None
    return str(val)


def lookup_whois(domain: str) -> WHOISInfo:
    w = whois.whois(domain)
    emails = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
    ns = w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else [])
    ns = [n.lower() for n in ns if n]
    registrant_name = _safe_str(getattr(w, "name", None))
    if not registrant_name and hasattr(w, "contacts") and isinstance(w.contacts, dict):
        reg = w.contacts.get("registrant") or w.contacts.get("owner")
        if isinstance(reg, dict) and reg.get("name"):
            registrant_name = _safe_str(reg["name"])

    return WHOISInfo(
        domain=domain,
        registrar=_safe_str(w.registrar),
        creation_date=_safe_str(w.creation_date),
        expiration_date=_safe_str(w.expiration_date),
        name_servers=ns,
        org=_safe_str(w.org),
        registrant_name=registrant_name,
        country=_safe_str(w.country),
        emails=emails,
        dnssec=_safe_str(w.dnssec),
    )


# ---------------------------------------------------------------------------
# DNS enumeration
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR"]


def enumerate_dns(domain: str) -> list[DNSRecord]:
    records: list[DNSRecord] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                records.append(DNSRecord(
                    record_type=rtype,
                    name=domain,
                    value=rdata.to_text(),
                    ttl=answers.rrset.ttl if answers.rrset else 0,
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.NoRootSOA):
            continue

    # Zone transfer attempt (usually blocked but worth checking)
    try:
        ns_answers = resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_host = str(ns).rstrip(".")
            try:
                import dns.zone
                import dns.query
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(DNSRecord(
                                record_type=f"AXFR-{dns.rdatatype.to_text(rdataset.rdtype)}",
                                name=f"{name}.{domain}",
                                value=rdata.to_text(),
                            ))
            except Exception:
                pass
    except Exception:
        pass

    return records


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh) subdomain harvesting
# ---------------------------------------------------------------------------

CRT_SH_URL = "https://crt.sh/"


def harvest_subdomains_crtsh(domain: str) -> list[SubdomainEntry]:
    """Query crt.sh certificate transparency logs for all subdomains."""
    entries: list[SubdomainEntry] = []
    seen: set[str] = set()

    try:
        resp = SESSION.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30,
        )
        if resp.status_code != 200:
            return entries

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return entries

        for cert in data:
            name_value = cert.get("name_value", "")
            for line in name_value.split("\n"):
                sub = line.strip().lower()
                sub = sub.lstrip("*.")
                if not sub or not sub.endswith(f".{domain}") and sub != domain:
                    continue
                if sub not in seen:
                    seen.add(sub)
                    entries.append(SubdomainEntry(subdomain=sub, source="crt.sh"))

            common_name = cert.get("common_name", "").strip().lower().lstrip("*.")
            if common_name and (common_name.endswith(f".{domain}") or common_name == domain):
                if common_name not in seen:
                    seen.add(common_name)
                    entries.append(SubdomainEntry(subdomain=common_name, source="crt.sh"))

    except requests.RequestException:
        pass

    entries.sort(key=lambda e: e.subdomain)
    return entries


# ---------------------------------------------------------------------------
# Google Dork Generator
# ---------------------------------------------------------------------------

def generate_google_dorks(domain: str) -> list[GoogleDork]:
    """Generate 50+ categorized Google dork queries for a target domain."""
    dorks: list[GoogleDork] = []

    file_exposure = [
        (f"site:{domain} filetype:sql", "SQL database dumps"),
        (f"site:{domain} filetype:env", "Environment variable files"),
        (f"site:{domain} filetype:log", "Log files"),
        (f"site:{domain} filetype:conf", "Configuration files"),
        (f"site:{domain} filetype:bak", "Backup files"),
        (f"site:{domain} filetype:xml", "XML data files"),
        (f"site:{domain} filetype:json", "JSON data files"),
        (f"site:{domain} filetype:yml", "YAML configuration files"),
        (f"site:{domain} filetype:yaml", "YAML configuration files"),
        (f"site:{domain} filetype:csv", "CSV data exports"),
        (f"site:{domain} filetype:txt", "Plain text files"),
        (f"site:{domain} filetype:cfg", "Configuration files"),
        (f"site:{domain} filetype:ini", "INI configuration files"),
        (f"site:{domain} filetype:key", "Private key files"),
        (f"site:{domain} filetype:pem", "PEM certificate/key files"),
        (f"site:{domain} filetype:crt", "Certificate files"),
        (f'"{domain}" filetype:pdf', "PDF documents"),
        (f'"{domain}" filetype:doc OR filetype:docx', "Word documents"),
        (f'"{domain}" filetype:xls OR filetype:xlsx', "Excel spreadsheets"),
        (f'"{domain}" filetype:ppt OR filetype:pptx', "PowerPoint presentations"),
        (f"site:{domain} filetype:swp", "Vim swap files"),
        (f"site:{domain} filetype:old", "Old backup files"),
        (f"site:{domain} filetype:tar OR filetype:gz OR filetype:zip", "Archive files"),
    ]
    for query, desc in file_exposure:
        dorks.append(GoogleDork(query=query, category="file_exposure", description=desc))

    admin_access = [
        (f"site:{domain} inurl:admin", "Admin pages"),
        (f"site:{domain} inurl:login", "Login pages"),
        (f"site:{domain} inurl:signin", "Sign-in pages"),
        (f"site:{domain} inurl:config", "Configuration endpoints"),
        (f"site:{domain} inurl:dashboard", "Dashboard pages"),
        (f"site:{domain} inurl:panel", "Control panel pages"),
        (f"site:{domain} inurl:manage", "Management interfaces"),
        (f"site:{domain} inurl:cpanel", "cPanel access"),
        (f"site:{domain} inurl:phpmyadmin", "phpMyAdmin interface"),
        (f"site:{domain} inurl:wp-admin", "WordPress admin"),
        (f"site:{domain} inurl:wp-content", "WordPress content directories"),
        (f"site:{domain} inurl:wp-login", "WordPress login"),
        (f'site:{domain} intitle:"index of"', "Directory listings"),
        (f'site:{domain} intitle:"dashboard"', "Dashboard pages by title"),
        (f"site:{domain} ext:php intitle:phpinfo", "PHP info pages"),
        (f'site:{domain} inurl:setup OR inurl:install', "Setup/install pages"),
    ]
    for query, desc in admin_access:
        dorks.append(GoogleDork(query=query, category="admin_access", description=desc))

    sensitive_data = [
        (f'site:{domain} intext:"password"', "Pages mentioning passwords"),
        (f'site:{domain} intext:"username"', "Pages mentioning usernames"),
        (f'site:{domain} intext:"api_key"', "Pages with API keys"),
        (f'site:{domain} intext:"secret"', "Pages mentioning secrets"),
        (f'site:{domain} intext:"token"', "Pages with tokens"),
        (f'site:{domain} intext:"private key"', "Pages with private keys"),
        (f'site:{domain} intext:"access_token"', "Pages with access tokens"),
        (f'site:{domain} intext:"client_secret"', "Pages with client secrets"),
        (f'site:{domain} intext:"aws_access_key"', "AWS access key exposure"),
        (f'site:{domain} intext:"AKIA"', "AWS key IDs (AKIA prefix)"),
        (f'site:{domain} intext:"ssh-rsa"', "SSH key exposure"),
        (f'site:{domain} intext:"BEGIN RSA PRIVATE KEY"', "RSA private key exposure"),
        (f'site:{domain} intext:"DB_PASSWORD"', "Database password exposure"),
        (f'site:{domain} intext:"connectionString"', "Database connection strings"),
    ]
    for query, desc in sensitive_data:
        dorks.append(GoogleDork(query=query, category="sensitive_data", description=desc))

    api_debug = [
        (f"site:{domain} inurl:api", "API endpoints"),
        (f"site:{domain} inurl:debug", "Debug pages"),
        (f"site:{domain} inurl:test", "Test pages"),
        (f"site:{domain} inurl:staging", "Staging environments"),
        (f"site:{domain} inurl:dev", "Development endpoints"),
        (f"site:{domain} inurl:swagger", "Swagger API documentation"),
        (f"site:{domain} inurl:graphql", "GraphQL endpoints"),
        (f"site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3", "Versioned API endpoints"),
        (f'site:{domain} inurl:".git"', "Exposed .git directories"),
        (f"site:{domain} inurl:.env", "Exposed .env files"),
        (f'site:{domain} intitle:"error" OR intitle:"exception"', "Error/exception pages"),
        (f"site:{domain} inurl:trace OR inurl:stacktrace", "Stack trace exposure"),
    ]
    for query, desc in api_debug:
        dorks.append(GoogleDork(query=query, category="api_debug", description=desc))

    external_presence = [
        (f'"{domain}" site:pastebin.com', "Pastebin mentions"),
        (f'"{domain}" site:github.com', "GitHub mentions"),
        (f'"{domain}" site:gitlab.com', "GitLab mentions"),
        (f'"{domain}" site:trello.com', "Trello board mentions"),
        (f'"{domain}" site:jira.atlassian.net', "Jira mentions"),
        (f'"{domain}" site:stackoverflow.com', "StackOverflow mentions"),
        (f'"@{domain}"', "Email address harvesting"),
        (f'inurl:"{domain}" -site:{domain}', "External references to domain"),
        (f'"{domain}" site:shodan.io', "Shodan references"),
        (f'"{domain}" site:censys.io', "Censys references"),
        (f'"{domain}" "password" OR "credentials"', "Leaked credentials mentioning domain"),
        (f'"{domain}" site:archive.org', "Internet Archive references"),
    ]
    for query, desc in external_presence:
        dorks.append(GoogleDork(query=query, category="external_presence", description=desc))

    return dorks


# ---------------------------------------------------------------------------
# Technology & Infrastructure OSINT
# ---------------------------------------------------------------------------

CDN_CNAME_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "cloudfront.net": "Amazon CloudFront",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "edgecast": "Edgecast/Verizon",
    "azureedge.net": "Azure CDN",
    "cdn.cloudflare.net": "Cloudflare",
    "sucuri": "Sucuri WAF",
    "incapsula": "Imperva/Incapsula",
    "stackpath": "StackPath",
    "maxcdn": "MaxCDN/StackPath",
    "awsglobalaccelerator": "AWS Global Accelerator",
}

CDN_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-sucuri-id": "Sucuri WAF",
    "x-cdn": None,  # generic CDN header
    "x-iinfo": "Imperva/Incapsula",
    "x-edge-ip": None,
    "server": None,  # checked separately for known CDN values
}

DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "k1", "k2",
    "mail", "dkim", "s1", "s2", "mx", "email", "smtpapi",
    "mandrill", "ses", "cm", "pm", "mailjet",
]

MX_PROVIDER_MAP = {
    "google": "Google Workspace",
    "gmail": "Google Workspace",
    "googlemail": "Google Workspace",
    "outlook": "Microsoft 365",
    "microsoft": "Microsoft 365",
    "protonmail": "ProtonMail",
    "protonmail.ch": "ProtonMail",
    "zoho": "Zoho Mail",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "pphosted": "Proofpoint",
    "messagelabs": "Broadcom/Symantec",
    "emailsecurity": "Email Security Gateway",
    "secureserver.net": "GoDaddy",
    "yahoodns": "Yahoo Mail",
    "icloud": "Apple iCloud Mail",
    "fastmail": "Fastmail",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "amazonaws": "Amazon SES",
}


def tech_infrastructure_osint(domain: str) -> TechInfraInfo:
    """Gather IP, hosting, CDN, email security, and infrastructure data."""
    info = TechInfraInfo()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # --- IP resolution & reverse DNS ---
    try:
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            ip = rdata.to_text()
            info.ip_addresses.append(ip)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                info.reverse_dns[ip] = hostname
            except (socket.herror, socket.gaierror, OSError):
                info.reverse_dns[ip] = "N/A"
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "AAAA")
        for rdata in answers:
            info.ip_addresses.append(rdata.to_text())
    except Exception:
        pass

    # --- ASN lookup via DNS (Team Cymru service) ---
    if info.ip_addresses:
        ip = info.ip_addresses[0]
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                reversed_ip = ".".join(reversed(parts))
                asn_query = f"{reversed_ip}.origin.asn.cymru.com"
                asn_answers = resolver.resolve(asn_query, "TXT")
                for rdata in asn_answers:
                    info.asn_info = rdata.to_text().strip('"')
                    break
        except Exception:
            pass

    # --- CDN detection via CNAME chain ---
    try:
        cname_answers = resolver.resolve(domain, "CNAME")
        for rdata in cname_answers:
            cname_val = rdata.to_text().lower()
            for sig, cdn_name in CDN_CNAME_SIGNATURES.items():
                if sig in cname_val:
                    info.cdn_detected = cdn_name
                    info.cdn_indicators.append(f"CNAME: {cname_val}")
                    break
    except Exception:
        pass

    # --- CDN detection via HTTP headers ---
    try:
        resp = SESSION.get(f"https://{domain}", timeout=10, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        info.server_headers = dict(resp.headers)

        for header_name, cdn_name in CDN_HEADER_SIGNATURES.items():
            if header_name in headers_lower:
                if cdn_name:
                    if not info.cdn_detected:
                        info.cdn_detected = cdn_name
                    info.cdn_indicators.append(f"Header {header_name}: {headers_lower[header_name]}")
                elif header_name == "server":
                    server_val = headers_lower["server"].lower()
                    if "cloudflare" in server_val:
                        info.cdn_detected = info.cdn_detected or "Cloudflare"
                        info.cdn_indicators.append(f"Server: {headers_lower['server']}")
                    elif "akamai" in server_val or "akamaighost" in server_val:
                        info.cdn_detected = info.cdn_detected or "Akamai"
                        info.cdn_indicators.append(f"Server: {headers_lower['server']}")
                else:
                    info.cdn_indicators.append(f"Header present: {header_name}")
    except requests.RequestException:
        pass

    # --- SPF record analysis ---
    try:
        txt_records = resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                info.spf_record = txt
                if "-all" in txt:
                    info.spf_analysis = "STRICT: Hard fail (-all) — unauthorized senders are rejected"
                elif "~all" in txt:
                    info.spf_analysis = "SOFTFAIL: Soft fail (~all) — unauthorized senders marked but accepted"
                elif "?all" in txt:
                    info.spf_analysis = "NEUTRAL: Neutral (?all) — no policy on unauthorized senders"
                elif "+all" in txt:
                    info.spf_analysis = "OPEN: Pass all (+all) — DANGEROUS, anyone can send as this domain"
                else:
                    info.spf_analysis = "SPF record found but no explicit all mechanism"
                break
    except Exception:
        pass

    # --- DKIM selector brute-force ---
    for selector in DKIM_SELECTORS:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in dkim_answers:
                txt = rdata.to_text().strip('"')
                if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
                    info.dkim_records[selector] = txt[:200]
                    break
        except Exception:
            continue

    # --- DMARC record analysis ---
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                info.dmarc_record = txt
                policy_match = re.search(r"p=(\w+)", txt)
                if policy_match:
                    policy = policy_match.group(1).lower()
                    policy_desc = {
                        "none": "MONITOR ONLY: No action on failures (p=none)",
                        "quarantine": "QUARANTINE: Failing messages sent to spam (p=quarantine)",
                        "reject": "STRICT: Failing messages rejected (p=reject)",
                    }
                    info.dmarc_analysis = policy_desc.get(policy, f"Policy: p={policy}")
                else:
                    info.dmarc_analysis = "DMARC record found but no explicit policy"
                break
    except Exception:
        pass

    # --- MX record intelligence ---
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for mx in mx_answers:
            mx_host = str(mx.exchange).rstrip(".").lower()
            priority = mx.preference
            provider = "Unknown"
            for key, name in MX_PROVIDER_MAP.items():
                if key in mx_host:
                    provider = name
                    break
            info.mx_records.append({
                "host": mx_host,
                "priority": str(priority),
                "provider": provider,
            })
            if not info.email_provider and provider != "Unknown":
                info.email_provider = provider
    except Exception:
        pass

    return info


# ---------------------------------------------------------------------------
# Email pattern discovery (expanded)
# ---------------------------------------------------------------------------

COMMON_EMAIL_PATTERNS = [
    "{first}.{last}",
    "{first}{last}",
    "{f}{last}",
    "{first}_{last}",
    "{first}",
    "{last}.{first}",
]

COMMON_EMAIL_PREFIXES = [
    "info", "admin", "support", "contact", "help", "sales", "security",
    "abuse", "webmaster", "postmaster", "noreply", "team", "hello",
    "office", "press", "media", "hr", "jobs", "careers", "billing",
    "accounts", "legal", "privacy", "compliance", "ceo", "cto", "cfo",
    "dev", "engineering", "ops", "marketing", "feedback", "newsletter",
    "service", "customerservice", "it", "sysadmin", "root", "hostmaster",
]


def discover_emails(domain: str) -> list[EmailPattern]:
    patterns: list[EmailPattern] = []

    # Check security.txt for contact emails
    for prefix in ["https://", "http://"]:
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                resp = SESSION.get(f"{prefix}{domain}{path}", timeout=8)
                if resp.status_code == 200:
                    found = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', resp.text)
                    for email in found:
                        patterns.append(EmailPattern(
                            pattern=email,
                            source=f"{prefix}{domain}{path}",
                            confidence="high",
                        ))
            except requests.RequestException:
                continue

    # Check DNS TXT/SPF records for email infrastructure hints
    try:
        resolver = dns.resolver.Resolver()
        txt_records = resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt = rdata.to_text().strip('"')
            if "include:" in txt or "v=spf1" in txt:
                if "google" in txt.lower():
                    patterns.append(EmailPattern(
                        pattern="Google Workspace (Gmail)",
                        source="SPF record",
                        confidence="high",
                    ))
                elif "outlook" in txt.lower() or "microsoft" in txt.lower():
                    patterns.append(EmailPattern(
                        pattern="Microsoft 365 (Outlook)",
                        source="SPF record",
                        confidence="high",
                    ))
                elif "zoho" in txt.lower():
                    patterns.append(EmailPattern(
                        pattern="Zoho Mail",
                        source="SPF record",
                        confidence="high",
                    ))
    except Exception:
        pass

    # Check MX records for email provider identification
    try:
        resolver = dns.resolver.Resolver()
        mx_records = resolver.resolve(domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).lower()
            if "google" in mx_host or "gmail" in mx_host:
                patterns.append(EmailPattern(pattern="Google Workspace", source=f"MX: {mx_host}", confidence="high"))
            elif "outlook" in mx_host or "microsoft" in mx_host:
                patterns.append(EmailPattern(pattern="Microsoft 365", source=f"MX: {mx_host}", confidence="high"))
            elif "protonmail" in mx_host:
                patterns.append(EmailPattern(pattern="ProtonMail", source=f"MX: {mx_host}", confidence="high"))
    except Exception:
        pass

    for fmt in COMMON_EMAIL_PATTERNS:
        patterns.append(EmailPattern(
            pattern=f"{fmt}@{domain}",
            source="common pattern",
            confidence="low",
        ))

    # Generate all common prefix emails
    for prefix in COMMON_EMAIL_PREFIXES:
        patterns.append(EmailPattern(
            pattern=f"{prefix}@{domain}",
            source="common role address",
            confidence="medium",
        ))

    # --- SMTP verification (best effort) ---
    mx_host = _get_primary_mx(domain)
    if mx_host:
        catch_all = _check_catch_all(mx_host, domain)
        if catch_all is True:
            patterns.append(EmailPattern(
                pattern="CATCH-ALL DETECTED",
                source=f"SMTP: {mx_host}",
                confidence="high",
            ))
        elif catch_all is False:
            verified = _smtp_verify_addresses(mx_host, domain)
            for addr, status in verified.items():
                patterns.append(EmailPattern(
                    pattern=addr,
                    source=f"SMTP verify ({status})",
                    confidence="high" if status == "valid" else "low",
                ))

    return patterns


def _get_primary_mx(domain: str) -> Optional[str]:
    """Resolve the highest-priority MX host for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        mx_answers = resolver.resolve(domain, "MX")
        mx_list = [(mx.preference, str(mx.exchange).rstrip(".")) for mx in mx_answers]
        mx_list.sort(key=lambda x: x[0])
        return mx_list[0][1] if mx_list else None
    except Exception:
        return None


def _smtp_connect(mx_host: str, timeout: int = 10) -> Optional[smtplib.SMTP]:
    """Connect to an MX host, returning the SMTP object or None."""
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        smtp.connect(mx_host, 25)
        smtp.ehlo_or_helo_if_needed()
        return smtp
    except Exception:
        return None


def _check_catch_all(mx_host: str, domain: str) -> Optional[bool]:
    """
    Test for catch-all configuration by probing a guaranteed-invalid address.
    Returns True (catch-all), False (selective), or None (inconclusive).
    """
    smtp = _smtp_connect(mx_host)
    if not smtp:
        return None
    try:
        bogus = f"zz__nonexistent__test__{int(time.time())}@{domain}"
        code, _ = smtp.mail("")
        if code >= 400:
            return None
        code, _ = smtp.rcpt(bogus)
        return code < 400
    except Exception:
        return None
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def _smtp_verify_addresses(mx_host: str, domain: str, max_checks: int = 10) -> dict[str, str]:
    """
    Probe a subset of common role addresses via RCPT TO.
    Returns {address: "valid"|"rejected"} for checked addresses.
    """
    results: dict[str, str] = {}
    check_prefixes = COMMON_EMAIL_PREFIXES[:max_checks]
    smtp = _smtp_connect(mx_host)
    if not smtp:
        return results
    try:
        for prefix in check_prefixes:
            addr = f"{prefix}@{domain}"
            try:
                code, _ = smtp.mail("")
                if code >= 400:
                    break
                code, _ = smtp.rcpt(addr)
                results[addr] = "valid" if code < 400 else "rejected"
                smtp.rset()
            except smtplib.SMTPServerDisconnected:
                break
            except Exception:
                continue
    finally:
        try:
            smtp.quit()
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Social Media & Public Presence Discovery
# ---------------------------------------------------------------------------

def _build_social_urls(name: str) -> list[tuple[str, str]]:
    """Build (platform, url) pairs for a given company/brand name."""
    return [
        ("GitHub", f"https://github.com/{name}"),
        ("GitHub Org", f"https://github.com/orgs/{name}"),
        ("LinkedIn", f"https://www.linkedin.com/company/{name}"),
        ("Twitter/X", f"https://x.com/{name}"),
        ("Twitter", f"https://twitter.com/{name}"),
        ("Facebook", f"https://www.facebook.com/{name}"),
        ("Instagram", f"https://www.instagram.com/{name}"),
        ("YouTube @", f"https://www.youtube.com/@{name}"),
        ("YouTube /c/", f"https://www.youtube.com/c/{name}"),
        ("Reddit /r/", f"https://www.reddit.com/r/{name}"),
        ("Reddit /user/", f"https://www.reddit.com/user/{name}"),
        ("Crunchbase", f"https://www.crunchbase.com/organization/{name}"),
        ("Glassdoor", f"https://www.glassdoor.com/Overview/Working-at-{name}-EI_IE.htm"),
        ("TrustPilot", f"https://www.trustpilot.com/review/{name}.com"),
        ("Medium", f"https://medium.com/@{name}"),
        ("Pinterest", f"https://www.pinterest.com/{name}"),
        ("TikTok", f"https://www.tiktok.com/@{name}"),
        ("Mastodon (search)", f"https://mastodon.social/@{name}"),
    ]


def discover_social_media(domain: str) -> list[SocialMediaProfile]:
    """Check social media platforms for presence of the brand/domain."""
    name = domain.split(".")[0]
    profiles: list[SocialMediaProfile] = []

    for platform, url in _build_social_urls(name):
        try:
            resp = SESSION.head(url, timeout=10, allow_redirects=True)
            exists = resp.status_code < 400
            profiles.append(SocialMediaProfile(
                platform=platform,
                url=url,
                exists=exists,
                status_code=resp.status_code,
            ))
        except requests.RequestException:
            profiles.append(SocialMediaProfile(
                platform=platform,
                url=url,
                exists=False,
                status_code=None,
            ))

    return profiles


# ---------------------------------------------------------------------------
# Data Breach Check
# ---------------------------------------------------------------------------

def check_data_breaches(domain: str) -> list[BreachInfo]:
    """Check public breach databases and paste sites for domain exposure."""
    results: list[BreachInfo] = []

    # --- Have I Been Pwned (public domain search, no API key) ---
    try:
        resp = SESSION.get(
            f"https://haveibeenpwned.com/api/v2/breaches?domain={domain}",
            timeout=15,
        )
        if resp.status_code == 200:
            try:
                breaches = resp.json()
                if breaches:
                    names = [b.get("Name", "Unknown") for b in breaches[:20]]
                    results.append(BreachInfo(
                        source="HaveIBeenPwned",
                        status="EXPOSED",
                        details=f"Domain found in {len(breaches)} breach(es): {', '.join(names)}",
                    ))
                else:
                    results.append(BreachInfo(
                        source="HaveIBeenPwned",
                        status="CLEAN",
                        details="No breaches found for this domain",
                    ))
            except (ValueError, json.JSONDecodeError):
                results.append(BreachInfo(
                    source="HaveIBeenPwned",
                    status="UNKNOWN",
                    details="Response could not be parsed",
                ))
        elif resp.status_code == 404:
            results.append(BreachInfo(
                source="HaveIBeenPwned",
                status="CLEAN",
                details="No breaches found for this domain",
            ))
        elif resp.status_code == 429:
            results.append(BreachInfo(
                source="HaveIBeenPwned",
                status="RATE_LIMITED",
                details="Rate limited — try again later",
            ))
        else:
            results.append(BreachInfo(
                source="HaveIBeenPwned",
                status="UNAVAILABLE",
                details=f"HTTP {resp.status_code}",
            ))
    except requests.RequestException as exc:
        results.append(BreachInfo(
            source="HaveIBeenPwned",
            status="ERROR",
            details=str(exc),
        ))

    # --- IntelX (public search hint) ---
    try:
        resp = SESSION.get(
            f"https://intelx.io/?s={domain}",
            timeout=10,
        )
        if resp.status_code == 200:
            results.append(BreachInfo(
                source="IntelX",
                status="CHECK_MANUALLY",
                details=f"https://intelx.io/?s={domain}",
            ))
    except requests.RequestException:
        results.append(BreachInfo(
            source="IntelX",
            status="UNAVAILABLE",
            details="Could not reach IntelX",
        ))

    # --- Dehashed-style indicator (public search page) ---
    try:
        resp = SESSION.get(
            f"https://dehashed.com/search?query={domain}",
            timeout=10,
        )
        if resp.status_code == 200:
            results.append(BreachInfo(
                source="Dehashed",
                status="CHECK_MANUALLY",
                details=f"https://dehashed.com/search?query={domain}",
            ))
        else:
            results.append(BreachInfo(
                source="Dehashed",
                status="UNAVAILABLE",
                details=f"HTTP {resp.status_code}",
            ))
    except requests.RequestException:
        results.append(BreachInfo(
            source="Dehashed",
            status="UNAVAILABLE",
            details="Could not reach Dehashed",
        ))

    # --- Pastebin search via Google dork (generate the link) ---
    results.append(BreachInfo(
        source="Pastebin (Google)",
        status="CHECK_MANUALLY",
        details=f'https://www.google.com/search?q=site:pastebin.com+"{domain}"',
    ))

    # --- Leak-Lookup public search ---
    try:
        resp = SESSION.get(
            f"https://leak-lookup.com/search?query={domain}&type=domain",
            timeout=10,
        )
        if resp.status_code == 200:
            results.append(BreachInfo(
                source="Leak-Lookup",
                status="CHECK_MANUALLY",
                details=f"https://leak-lookup.com/search?query={domain}&type=domain",
            ))
    except requests.RequestException:
        results.append(BreachInfo(
            source="Leak-Lookup",
            status="UNAVAILABLE",
            details="Could not reach Leak-Lookup",
        ))

    # --- SecurityTrails (public page) ---
    results.append(BreachInfo(
        source="SecurityTrails",
        status="CHECK_MANUALLY",
        details=f"https://securitytrails.com/domain/{domain}",
    ))

    return results


# ---------------------------------------------------------------------------
# Wayback Machine (enhanced)
# ---------------------------------------------------------------------------

WAYBACK_API = "https://web.archive.org/cdx/search/cdx"

INTERESTING_PATH_PATTERNS = [
    (re.compile(r"(admin|login|signin|auth|dashboard|panel|manage|control)", re.I), "admin_or_auth"),
    (re.compile(r"(api|graphql|rest|v[0-9]+|swagger|openapi)", re.I), "api_endpoint"),
    (re.compile(r"\.(env|cfg|conf|ini|yml|yaml|json|xml|sql|bak|old|log|key|pem)$", re.I), "config_or_data"),
    (re.compile(r"(debug|test|staging|dev|phpinfo|trace|status)", re.I), "debug_or_test"),
    (re.compile(r"(upload|backup|dump|export|import|migrate)", re.I), "backup_or_migration"),
    (re.compile(r"(wp-admin|wp-login|wp-content|wp-includes)", re.I), "wordpress"),
    (re.compile(r"(phpmyadmin|adminer|cpanel|webmail)", re.I), "management_tool"),
    (re.compile(r"\.(zip|tar|gz|rar|7z|sql\.gz|db)$", re.I), "archive_or_db"),
    (re.compile(r"(password|secret|token|credential|key)", re.I), "sensitive_keyword"),
    (re.compile(r"(robots\.txt|sitemap\.xml|\.htaccess|\.git|\.svn)", re.I), "metadata_or_vcs"),
]


def _categorize_url(url: str) -> Optional[str]:
    """Return a category if the URL path matches interesting patterns."""
    for pattern, category in INTERESTING_PATH_PATTERNS:
        if pattern.search(url):
            return category
    return None


def query_wayback(domain: str, limit: int = 200) -> list[WaybackSnapshot]:
    """
    Retrieve Wayback Machine snapshots. Fetches up to `limit` unique URLs,
    then categorizes interesting historical pages.
    """
    snapshots: list[WaybackSnapshot] = []
    seen_urls: set[str] = set()

    try:
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "limit": limit,
            "fl": "timestamp,original,statuscode",
            "collapse": "urlkey",
            "filter": "statuscode:200",
        }
        resp = SESSION.get(WAYBACK_API, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                timestamp, original, status = row[0], row[1], row[2]
                if original in seen_urls:
                    continue
                seen_urls.add(original)
                category = _categorize_url(original)
                snapshots.append(WaybackSnapshot(
                    url=f"https://web.archive.org/web/{timestamp}/{original}",
                    timestamp=timestamp,
                    status_code=status,
                    category=category,
                ))
    except (requests.RequestException, ValueError, IndexError):
        pass

    # Second pass: pages that existed but were later removed (410/404 in newer crawls)
    try:
        params_removed = {
            "url": f"{domain}/*",
            "output": "json",
            "limit": 50,
            "fl": "timestamp,original,statuscode",
            "collapse": "urlkey",
            "filter": "statuscode:404",
        }
        resp = SESSION.get(WAYBACK_API, params=params_removed, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                timestamp, original, status = row[0], row[1], row[2]
                if original in seen_urls:
                    continue
                seen_urls.add(original)
                category = _categorize_url(original)
                if category:
                    snapshots.append(WaybackSnapshot(
                        url=f"https://web.archive.org/web/{timestamp}/{original}",
                        timestamp=timestamp,
                        status_code=f"{status} (removed)",
                        category=f"REMOVED-{category}",
                    ))
    except (requests.RequestException, ValueError, IndexError):
        pass

    return snapshots


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

RUN_BUDGET_SEC = 25  # finish before bot 120s timeout


def run(target: str, scan_type: str = "full") -> str:
    import concurrent.futures

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    report = OSINTReport(target=domain)

    tasks = {
        "whois":      ("whois_info",       lambda: lookup_whois(domain)),
        "dns":        ("dns_records",       lambda: enumerate_dns(domain)),
        "subdomains": ("subdomains",        lambda: harvest_subdomains_crtsh(domain)),
        "emails":     ("email_patterns",    lambda: discover_emails(domain)),
        "dorks":      ("google_dorks",      lambda: generate_google_dorks(domain)),
        "tech":       ("tech_infra",        lambda: tech_infrastructure_osint(domain)),
        "social":     ("social_media",      lambda: discover_social_media(domain)),
        "breaches":   ("breach_info",       lambda: check_data_breaches(domain)),
        "wayback":    ("wayback_snapshots", lambda: query_wayback(domain)),
    }

    to_run = {k: v for k, v in tasks.items() if scan_type in ("full", k)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(to_run))) as pool:
        futures = {pool.submit(fn): (key, attr) for key, (attr, fn) in to_run.items()}
        for future in concurrent.futures.as_completed(futures, timeout=RUN_BUDGET_SEC):
            key, attr = futures[future]
            try:
                setattr(report, attr, future.result(timeout=2))
            except Exception as exc:
                report.errors.append(f"{key} error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
