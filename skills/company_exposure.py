"""
Company exposure discovery skill for authorized assessments.

Focuses on broader company-facing risk surfaces that are often more valuable than
commodity injection issues:
  - admin and management interfaces
  - identity and SSO metadata / auth surfaces
  - debug, docs, and observability endpoints
  - export, backup, and report paths
  - storage / file-serving paths
  - support and helpdesk portals
  - staging / preview / demo environments
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order

SESSION = get_session()
TIMEOUT = 3
SCAN_BUDGET = 12  # aggressive cap; partial results are fine
SIGNAL_STATUSES = {200, 206, 301, 302, 401, 403}


@dataclass
class Surface:
    category: str
    label: str
    url: str
    status_code: int
    exposure_type: str
    platform: str = ""
    notes: str = ""
    content_length: int = 0


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
class CompanyExposureReport:
    target_url: str
    surfaces: list[Surface] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


CATEGORY_PATHS: dict[str, list[tuple[str, str]]] = {
    "admin": [
        ("/admin", "Admin panel"),
        ("/administrator", "Administrator console"),
        ("/dashboard", "Dashboard"),
        ("/manage", "Management interface"),
        ("/console", "Operations console"),
        ("/backoffice", "Backoffice"),
    ],
    "identity": [
        ("/login", "Login surface"),
        ("/sso", "SSO portal"),
        ("/oauth/authorize", "OAuth authorize endpoint"),
        ("/.well-known/openid-configuration", "OpenID configuration"),
        ("/.well-known/jwks.json", "JWKS metadata"),
        ("/auth/realms/master", "Identity realm"),
    ],
    "debug": [
        ("/debug", "Debug endpoint"),
        ("/__debug__/", "Framework debug toolbar"),
        ("/debug/pprof", "pprof root"),
        ("/actuator", "Actuator root"),
        ("/actuator/env", "Actuator env"),
        ("/trace.axd", "Trace endpoint"),
    ],
    "docs": [
        ("/swagger", "Swagger UI"),
        ("/swagger-ui.html", "Swagger UI HTML"),
        ("/openapi.json", "OpenAPI spec"),
        ("/v3/api-docs", "API docs"),
        ("/redoc", "ReDoc"),
        ("/graphql/schema", "GraphQL schema"),
    ],
    "observability": [
        ("/metrics", "Metrics endpoint"),
        ("/actuator/prometheus", "Prometheus metrics"),
        ("/health", "Health endpoint"),
        ("/status", "Status endpoint"),
        ("/grafana", "Grafana"),
        ("/kibana", "Kibana"),
    ],
    "exports": [
        ("/export.csv", "CSV export"),
        ("/export.json", "JSON export"),
        ("/reports", "Reports interface"),
        ("/download", "Download endpoint"),
        ("/backup.zip", "Backup archive"),
        ("/backup.sql", "Database backup"),
    ],
    "storage": [
        ("/uploads/", "Uploads directory"),
        ("/files/", "Files directory"),
        ("/media/", "Media directory"),
        ("/assets/", "Assets directory"),
        ("/storage/", "Storage directory"),
        ("/downloads/", "Downloads directory"),
    ],
    "support": [
        ("/support", "Support portal"),
        ("/helpdesk", "Helpdesk"),
        ("/tickets", "Ticket system"),
        ("/servicedesk", "Service desk"),
        ("/contact", "Contact portal"),
        ("/intercom", "Intercom surface"),
    ],
    "staging": [
        ("/staging", "Staging environment"),
        ("/stage", "Stage environment"),
        ("/demo", "Demo environment"),
        ("/preview", "Preview environment"),
        ("/sandbox", "Sandbox environment"),
        ("/test", "Test environment"),
    ],
}

SCAN_GROUPS = {
    "operational": ["admin", "identity", "debug", "docs", "observability"],
    "business": ["exports", "storage", "support", "staging"],
}

PLATFORM_SIGNATURES: dict[str, tuple[str, ...]] = {
    "Grafana": ("grafana", "grafana-app", "public/build/grafana", "x-grafana"),
    "Kibana": ("kibana", "elastic", "kbn-name", "kbn-version"),
    "Jenkins": ("jenkins", "x-jenkins", "adjuncts", "jenkins-agent-protocols"),
    "Jira": ("jira", "atlassian", "ajs-version-number", "jira service management"),
    "Confluence": ("confluence", "atlassian", "confluence-content", "wiki"),
    "GitLab": ("gitlab", "x-gitlab", "gitlab-page"),
    "Keycloak": ("keycloak", "/auth/realms/", "keycloak.js"),
    "Okta": ("okta", "oktacdn", "okta-signin"),
    "Auth0": ("auth0", "cdn.auth0.com", "auth0-spa-js"),
    "Prometheus": ("prometheus", "go_gc_duration_seconds", "promhttp"),
    "Zendesk": ("zendesk", "zdassets", "help center"),
    "Freshdesk": ("freshdesk", "freshservice", "freshworks"),
    "Intercom": ("intercom", "intercom-messenger", "js.intercomcdn.com"),
    "Sentry": ("sentry", "sentry_key", "sentry-trace"),
}

ALTERNATE_HOSTS: list[tuple[str, str, str]] = [
    ("admin", "admin", "Admin host"),
    ("manage", "admin", "Management host"),
    ("auth", "identity", "Identity host"),
    ("login", "identity", "Login host"),
    ("sso", "identity", "SSO host"),
    ("grafana", "observability", "Grafana host"),
    ("kibana", "observability", "Kibana host"),
    ("monitor", "observability", "Monitoring host"),
    ("status", "observability", "Status host"),
    ("jenkins", "debug", "Jenkins host"),
    ("jira", "support", "Jira host"),
    ("confluence", "support", "Confluence host"),
    ("help", "support", "Help host"),
    ("support", "support", "Support host"),
    ("staging", "staging", "Staging host"),
    ("preview", "staging", "Preview host"),
    ("demo", "staging", "Demo host"),
    ("sandbox", "staging", "Sandbox host"),
]

DEBUG_MARKERS = ("actuator", "heapdump", "threaddump", "pprof", "debug toolbar", "prometheus", "grafana", "kibana")
DOC_MARKERS = ("swagger", "openapi", "redoc", "api docs", "graphql")
SUPPORT_MARKERS = ("zendesk", "freshdesk", "jira service", "help center", "ticket", "support")
STAGING_MARKERS = ("staging", "preview", "sandbox", "demo", "uat", "test environment")
ATTACHMENT_TYPES = (
    "application/zip",
    "application/octet-stream",
    "application/x-gzip",
    "application/sql",
    "text/csv",
)


def _budget_expired(started_at: float, budget_sec: float) -> bool:
    return (time.time() - started_at) > budget_sec


def _select_categories(scan_type: str) -> list[str]:
    if scan_type == "full":
        return list(CATEGORY_PATHS.keys())
    if scan_type == "quick":
        return list(SCAN_GROUPS["operational"])
    if scan_type in SCAN_GROUPS:
        return SCAN_GROUPS[scan_type]
    if scan_type in CATEGORY_PATHS:
        return [scan_type]
    return list(CATEGORY_PATHS.keys())


def _probe(url: str):
    try:
        return SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None


def _body_excerpt(resp: requests.Response) -> str:
    text = resp.text[:400].replace("\n", " ").strip()
    return text[:180]


def _looks_like_directory_listing(text: str) -> bool:
    body = text.lower()
    return any(
        marker in body
        for marker in ("index of /", "directory listing", "parent directory", "<title>index of")
    )


def _detect_platform(resp: requests.Response) -> str:
    header_blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    body = resp.text[:5000].lower()
    hay = f"{header_blob}\n{body}"
    for platform, markers in PLATFORM_SIGNATURES.items():
        if any(marker.lower() in hay for marker in markers):
            return platform
    return ""


def _guess_base_domain(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname
    if len(parts[-1]) == 2 and len(parts[-2]) <= 3 and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _build_alternate_host_urls(target_url: str) -> list[tuple[str, str, str, str]]:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.hostname:
        return []

    base_domain = _guess_base_domain(parsed.hostname)
    port = f":{parsed.port}" if parsed.port else ""
    urls: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for subdomain, category, label in ALTERNATE_HOSTS:
        host = f"{subdomain}.{base_domain}"
        alt_url = f"{parsed.scheme}://{host}{port}/"
        if alt_url in seen or host == parsed.hostname:
            continue
        seen.add(alt_url)
        urls.append((category, label, alt_url, host))
    return urls


def _classify_exposure(category: str, path: str, resp: requests.Response) -> tuple[str, str, str]:
    status = resp.status_code
    content_type = resp.headers.get("Content-Type", "").lower()
    body = resp.text[:4000].lower()
    location = resp.headers.get("Location", "")
    platform = _detect_platform(resp)

    if status in (301, 302):
        note = f"Redirects to {location or 'another location'}"
        if platform:
            note += f" | Platform: {platform}"
        return "redirected", note, platform
    if status in (401, 403):
        note = f"Surface exists but returned {status}"
        if platform:
            note += f" | Platform: {platform}"
        return "restricted", note, platform

    if category == "admin":
        note = "Admin or management route returned content"
    elif category == "identity":
        if "openid-configuration" in path or "jwks" in path:
            note = "Identity metadata is publicly reachable"
            exposure_type = "metadata"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Identity-related route returned content"
    elif category in {"debug", "observability"}:
        if any(marker in body for marker in DEBUG_MARKERS):
            note = "Debug or observability markers detected in response body"
            exposure_type = "operational"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Operational endpoint returned content"
    elif category == "docs":
        if any(marker in body for marker in DOC_MARKERS) or "json" in content_type:
            note = "Documentation or schema markers detected"
            exposure_type = "schema"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Documentation-style route returned content"
    elif category == "exports":
        if any(t in content_type for t in ATTACHMENT_TYPES) or "attachment" in resp.headers.get("Content-Disposition", "").lower():
            note = "Downloadable export or backup content type detected"
            exposure_type = "download"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Export/report path returned content"
    elif category == "storage":
        if _looks_like_directory_listing(body):
            note = "Directory listing style response detected"
            exposure_type = "listing"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Storage or file path returned content"
    elif category == "support":
        if any(marker in body for marker in SUPPORT_MARKERS):
            note = "Support/helpdesk markers detected"
            exposure_type = "portal"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Support-related path returned content"
    elif category == "staging":
        if any(marker in body for marker in STAGING_MARKERS):
            note = "Staging/demo markers detected"
            exposure_type = "staging"
            if platform:
                note += f" | Platform: {platform}"
            return exposure_type, note, platform
        note = "Alternate environment path returned content"
    else:
        note = "Path returned content"

    if platform:
        note += f" | Platform: {platform}"
    return "public", note, platform


def _finding_for_surface(
    category: str,
    label: str,
    url: str,
    resp: requests.Response,
    exposure_type: str,
    note: str,
    platform: str = "",
) -> Finding | None:
    status = resp.status_code
    content_type = resp.headers.get("Content-Type", "")
    evidence = f"Status: {status} | Type: {content_type or 'unknown'} | Note: {note}"
    body_preview = _body_excerpt(resp)
    if body_preview:
        evidence += f" | Body: {body_preview}"
    platform_prefix = f"{platform} " if platform else ""

    if category == "admin" and status == 200:
        return Finding(
            title=f"Publicly reachable {platform_prefix}admin or management surface".strip(),
            severity="High",
            url=url,
            category="Operational Exposure",
            evidence=evidence,
            impact="Internet-facing admin surfaces increase the chance of unauthorized access attempts, credential attacks, and sensitive workflow exposure.",
            remediation="Restrict admin interfaces behind strong authentication, IP allowlists, VPN, or zero-trust access controls.",
        )
    if category in {"debug", "observability"} and status == 200:
        return Finding(
            title=f"{platform_prefix}operational or debug endpoint reachable from the internet".strip().capitalize(),
            severity="High" if exposure_type == "operational" else "Medium",
            url=url,
            category="Operational Exposure",
            evidence=evidence,
            impact="Debug and observability endpoints can reveal internal configuration, process data, metrics, and implementation details valuable to attackers.",
            remediation="Remove public exposure from debug and telemetry endpoints or place them behind authenticated internal-only access.",
        )
    if category == "docs" and status == 200:
        return Finding(
            title=f"Public {platform_prefix}API documentation or schema exposure".strip(),
            severity="Medium" if exposure_type == "public" else "High",
            url=url,
            category="Operational Exposure",
            evidence=evidence,
            impact="Exposed API docs and schema definitions can accelerate endpoint mapping, parameter discovery, and targeting of sensitive business functions.",
            remediation="Limit API documentation to authenticated users, internal networks, or non-production environments.",
        )
    if category == "exports" and status in (200, 206):
        return Finding(
            title=f"{platform_prefix}export, report, or backup path returned content".strip().capitalize(),
            severity="Critical" if exposure_type == "download" else "High",
            url=url,
            category="Data Exposure",
            evidence=evidence,
            impact="Downloadable exports or backups may directly expose business records, internal data structure, or operational artifacts.",
            remediation="Remove public access to backup and export paths, require strong authorization, and store generated artifacts outside web-accessible locations.",
        )
    if category == "storage" and status == 200:
        return Finding(
            title=f"Public {platform_prefix}file or storage path reachable".strip(),
            severity="High" if exposure_type == "listing" else "Medium",
            url=url,
            category="Data Exposure",
            evidence=evidence,
            impact="Public file and storage paths can expose uploaded content, internal artifacts, or indexing that helps attackers enumerate sensitive data.",
            remediation="Disable directory listing, enforce access controls for private content, and separate public assets from sensitive storage.",
        )
    if category == "staging" and status == 200:
        return Finding(
            title=f"Potential {platform_prefix}staging, preview, or demo surface reachable".strip(),
            severity="High" if exposure_type == "staging" else "Medium",
            url=url,
            category="Operational Exposure",
            evidence=evidence,
            impact="Alternate environments often have weaker controls, test data, or unfinished code paths that create easier entry points than production.",
            remediation="Protect non-production environments with the same access standards as production or remove public exposure entirely.",
        )
    if category == "support" and status == 200:
        return Finding(
            title=f"Public {platform_prefix}support or collaboration surface reachable".strip(),
            severity="Medium" if exposure_type == "portal" else "Low",
            url=url,
            category="Operational Exposure",
            evidence=evidence,
            impact="Support and collaboration portals can expose internal workflows, tickets, user identifiers, and business context valuable for follow-on attacks.",
            remediation="Review whether support and collaboration surfaces should be public, and reduce exposed metadata, indexing, and unauthenticated content.",
        )
    if category == "identity" and status == 200 and exposure_type != "metadata":
        return Finding(
            title=f"{platform_prefix}identity or SSO surface publicly reachable".strip().capitalize(),
            severity="Medium",
            url=url,
            category="Authentication",
            evidence=evidence,
            impact="Public identity surfaces concentrate login, federation, and account-recovery flows that deserve priority hardening and monitoring.",
            remediation="Review exposed identity routes, harden federation settings, and monitor them closely for brute-force, enumeration, and token abuse.",
        )
    if category == "identity" and exposure_type == "metadata" and status == 200:
        return Finding(
            title=f"Public {platform_prefix}identity metadata exposure".strip(),
            severity="Medium",
            url=url,
            category="Authentication",
            evidence=evidence,
            impact="Public identity metadata can improve reconnaissance against login, federation, and token-verification surfaces.",
            remediation="Limit unnecessary identity metadata exposure and confirm no sensitive tenant or realm details are unintentionally disclosed.",
        )
    return None


def _record_surface(
    report: CompanyExposureReport,
    category: str,
    label: str,
    url: str,
    resp: requests.Response,
    exposure_type: str,
    note: str,
    platform: str = "",
):
    content_length = len(resp.content) if resp.content else int(resp.headers.get("Content-Length") or 0)
    report.surfaces.append(
        Surface(
            category=category,
            label=label,
            url=url,
            status_code=resp.status_code,
            exposure_type=exposure_type,
            platform=platform,
            notes=note,
            content_length=content_length,
        )
    )
    finding = _finding_for_surface(category, label, url, resp, exposure_type, note, platform)
    if finding:
        report.findings.append(finding)


def scan_company_exposure(target_url: str, scan_type: str = "full") -> CompanyExposureReport:
    report = CompanyExposureReport(target_url=target_url)
    started_at = time.time()
    budget_sec = float(7 if scan_type == "quick" else SCAN_BUDGET)

    categories = _select_categories(scan_type)
    seen_urls: set[str] = set()
    for category in categories:
        for path, label in randomize_order(CATEGORY_PATHS[category]):
            if _budget_expired(started_at, budget_sec):
                report.errors.append(f"Budget expired before completing category: {category}")
                return report

            url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            if url in seen_urls:
                continue
            seen_urls.add(url)

            resp = _probe(url)
            if not resp or resp.status_code not in SIGNAL_STATUSES:
                continue

            exposure_type, note, platform = _classify_exposure(category, path, resp)
            _record_surface(report, category, label, url, resp, exposure_type, note, platform)

    if scan_type in {"full", "operational", "business", "staging", "support", "observability", "identity", "admin"}:
        for category, label, alt_url, host in _build_alternate_host_urls(target_url):
            if _budget_expired(started_at, budget_sec):
                report.errors.append("Budget expired before completing alternate-host probing")
                break
            resp = _probe(alt_url)
            if not resp or resp.status_code not in SIGNAL_STATUSES:
                continue
            exposure_type, note, platform = _classify_exposure(category, "/", resp)
            note = f"{note} | Alternate host: {host}"
            _record_surface(report, category, label, alt_url, resp, exposure_type, note, platform)

    _tag_likely_spa_findings(report)
    return report


def _tag_likely_spa_findings(report: CompanyExposureReport) -> None:
    """If many 200 responses share the same content length, tag findings as possible SPA (verify if real backend)."""
    lengths = [s.content_length for s in report.surfaces if s.status_code == 200 and s.content_length > 0]
    if len(lengths) < 4:
        return
    most_common = Counter(lengths).most_common(1)[0]
    common_length, count = most_common
    if count < 4:
        return
    url_to_length = {s.url: s.content_length for s in report.surfaces if s.status_code == 200}
    spa_note = " [Possible SPA: same response size as many other paths — verify if real backend.]"
    for f in report.findings:
        if f.url in url_to_length and url_to_length[f.url] == common_length:
            f.evidence += spa_note


def run(target_url: str, scan_type: str = "full") -> str:
    try:
        report = scan_company_exposure(target_url, scan_type=scan_type)
        return json.dumps(asdict(report), indent=2)
    except Exception as exc:
        return json.dumps({
            "target_url": target_url,
            "surfaces": [],
            "findings": [],
            "errors": [str(exc)],
        }, indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(target, st))
