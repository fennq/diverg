"""
Dependency / CVE audit skill — APT-style upgrade (Upgrade 2 + 5).
Collects product/version from headers, JS/CDN patterns, and optional
client_surface (or recon) output, checks against a curated CVE watchlist
AND live OSV.dev, and reports known CVEs with fix versions and CVSS.

Also detects end-of-life (EOL) frameworks missing security patches.

Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 6
RUN_BUDGET_SEC = 40
WATCHLIST_PATH = Path(__file__).parent / "cve_watchlist.json"

# Header patterns: Server, X-Powered-By
HEADER_VERSION_RE = [
    (re.compile(r"Next\.?js(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "Next.js"),
    (re.compile(r"Express(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "Express"),
    (re.compile(r"React(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "React"),
    (re.compile(r"nginx(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "nginx"),
    (re.compile(r"Apache(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "Apache"),
    (re.compile(r"PHP(?:/?\s*([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "PHP"),
    (re.compile(r"WordPress(?:/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))?", re.I), "WordPress"),
    (re.compile(r"Django(?:/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))?", re.I), "Django"),
    (re.compile(r"node\.?js(?:/?\s*v?([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "Node.js"),
    (re.compile(r"Tomcat(?:/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))?", re.I), "Tomcat"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"Varnish(?:\s+([0-9]+\.[0-9]+\.[0-9]+))?", re.I), "Varnish"),
]


EOL_VERSIONS: dict[str, dict[str, str]] = {
    "Node.js": {
        "12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11",
        "18": "2025-04-30", "19": "2023-06-01", "21": "2024-06-01",
    },
    "PHP": {"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31"},
    "Django": {"3.2": "2024-04-01", "4.0": "2023-04-01", "4.1": "2023-12-01"},
    "Python": {"3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-05"},
    "nginx": {"1.22": "2023-06-01", "1.24": "2024-06-01"},
    "Apache": {"2.2": "2018-01-01"},
    "WordPress": {"5.9": "2024-11-01"},
    "Tomcat": {"8.5": "2024-03-31", "9.0": "2025-03-31"},
}

CDN_VERSION_PATTERNS = [
    re.compile(r"/npm/([a-z@][a-z0-9_./@-]*)@([0-9]+\.[0-9]+\.[0-9]+)", re.I),
    re.compile(r"/ajax/libs/([a-z][a-z0-9._-]*)/([0-9]+\.[0-9]+\.[0-9]+)", re.I),
    re.compile(r"([a-z][a-z0-9._-]*?)[-.]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
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
class DependencyAuditReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    detected_versions: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _load_watchlist() -> dict:
    try:
        with open(WATCHLIST_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"products": {}, "version_match": "prefix"}


def _version_in_affected(version: str, affected_list: list[str], match_mode: str) -> bool:
    """Check if version is in affected list. match_mode: 'prefix' or 'exact'."""
    version = version.strip()
    for a in affected_list:
        a = a.strip()
        if match_mode == "exact":
            if version == a:
                return True
        else:
            if version == a or version.startswith(a + ".") or version.startswith(a + "-"):
                return True
            if a.endswith(".x") and version.startswith(a[:-2]):
                return True
    return False


def _versions_from_sec_ch_ua(val: str) -> list[dict]:
    """Parse Sec-CH-UA for framework hints (e.g. Next.js / React reported by the stack)."""
    out: list[dict] = []
    if not val or not val.strip():
        return out
    for m in re.finditer(r'"([^"]+)"\s*;\s*v="([^"]*)"', val):
        name, ver = m.group(1), m.group(2)
        if not ver or ver in ("?", ""):
            continue
        low = name.lower()
        if "next" in low:
            out.append({"product": "Next.js", "version": ver, "source": "header:Sec-CH-UA"})
        elif "react" in low:
            out.append({"product": "React", "version": ver, "source": "header:Sec-CH-UA"})
    return out


def _collect_versions_from_headers(url: str) -> list[dict]:
    versions: list[dict] = []
    try:
        r = SESSION.head(url, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code >= 400:
            r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        h = r.headers
        sec = h.get("Sec-CH-UA") or h.get("sec-ch-ua")
        if sec:
            for item in _versions_from_sec_ch_ua(sec):
                key = (item.get("product"), item.get("version"))
                if key[0] and key[1] and not any((v.get("product"), v.get("version")) == key for v in versions):
                    versions.append(item)
        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Version", "Via"):
            val = h.get(header_name)
            if not val:
                continue
            for pattern, product in HEADER_VERSION_RE:
                m = pattern.search(val)
                if m:
                    ver = ""
                    if m.lastindex:
                        ver = (m.group(1) or "").strip()
                    if not ver:
                        ver = "unknown"
                    entry = {"product": product, "version": ver, "source": f"header:{header_name}"}
                    key = (entry["product"], entry["version"])
                    if not any((v.get("product"), v.get("version")) == key for v in versions):
                        versions.append(entry)
                    break
    except requests.RequestException:
        pass
    return versions


def _extract_cdn_versions(client_surface_json: str) -> list[dict]:
    """Extract package versions from CDN URLs found in client_surface output."""
    versions: list[dict] = []
    try:
        data = json.loads(client_surface_json)
    except Exception:
        return versions

    urls: list[str] = []
    for script in data.get("scripts", []) or []:
        src = script.get("src", "") if isinstance(script, dict) else str(script)
        if src:
            urls.append(src)
    for ep in data.get("extracted_endpoints", []) or []:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if url and ".js" in url:
            urls.append(url)

    seen: set[tuple[str, str]] = set()
    for url in urls:
        for pattern in CDN_VERSION_PATTERNS:
            for m in pattern.finditer(url):
                pkg = m.group(1).strip().rstrip("/")
                ver = m.group(2).strip()
                if pkg and ver and (pkg.lower(), ver) not in seen:
                    seen.add((pkg.lower(), ver))
                    versions.append({
                        "product": pkg, "version": ver,
                        "source": f"cdn:{url[:120]}",
                    })
    return versions


def _check_eol(product: str, version: str, target_url: str) -> Finding | None:
    """Check if a product version has reached end-of-life."""
    eol_entries = EOL_VERSIONS.get(product)
    if not eol_entries:
        return None
    parts = version.split(".")
    for prefix_len in (2, 1):
        major_minor = ".".join(parts[:prefix_len])
        eol_date = eol_entries.get(major_minor)
        if eol_date:
            try:
                from datetime import date
                if date.fromisoformat(eol_date) < date.today():
                    return Finding(
                        title=f"{product} {version} reached end-of-life ({eol_date})",
                        severity="High",
                        url=target_url,
                        category="Dependency / EOL",
                        evidence=(
                            f"{product} {major_minor}.x EOL date: {eol_date}. "
                            f"Detected version: {version}."
                        ),
                        impact=(
                            "End-of-life software receives no security patches. "
                            "Known and future vulnerabilities will remain unpatched."
                        ),
                        remediation=(
                            f"Upgrade {product} to a currently supported version. "
                            f"Check vendor release schedule for LTS options."
                        ),
                    )
            except Exception:
                pass
    return None


def _run_osv_lookup(
    all_versions: list[dict], target_url: str, cve_seen: set,
) -> list[Finding]:
    """Query OSV.dev for live CVE data on detected packages."""
    try:
        import osv_client
    except ImportError:
        return []

    osv_items: list[tuple[str, str, str]] = []
    for d in all_versions:
        product = d.get("product", "")
        version = d.get("version", "")
        if not product or not version or version == "unknown":
            continue
        eco = osv_client.resolve_ecosystem(product)
        if eco:
            osv_items.append((product, version, eco))

    if not osv_items:
        return []

    findings: list[Finding] = []
    try:
        results = osv_client.query_batch(osv_items)
    except Exception:
        return []

    for (pkg, ver, eco) in osv_items:
        cache_key = f"{eco}:{pkg}:{ver}"
        vulns = results.get(cache_key, [])
        for v in vulns:
            dedupe = (pkg, ver, v.cve_id)
            if dedupe in cve_seen:
                continue
            cve_seen.add(dedupe)
            severity = v.severity or "High"
            fix_str = ", ".join(v.fixed_versions[:3]) if v.fixed_versions else "unknown"
            ref_str = " ".join(v.references[:2]) if v.references else ""
            cvss_note = f" (CVSS {v.cvss_score})" if v.cvss_score else ""
            findings.append(Finding(
                title=f"{pkg} {ver}: {v.cve_id}{cvss_note}",
                severity=severity,
                url=target_url,
                category="Dependency / CVE",
                evidence=(
                    f"OSV.dev: {v.summary[:200]} "
                    f"Fix: {fix_str}. {ref_str}"
                ).strip(),
                impact="Known vulnerability confirmed by OSV.dev live database.",
                remediation=f"Upgrade {pkg} to {fix_str}." if fix_str != "unknown"
                else f"Check {v.cve_id} for patch guidance.",
            ))
    return findings


def run(
    target_url: str,
    scan_type: str = "full",
    client_surface_json: Optional[str] = None,
    recon_json: Optional[str] = None,
) -> str:
    report = DependencyAuditReport(target_url=target_url)
    run_start = time.time()
    all_versions: list[dict] = []

    all_versions.extend(_collect_versions_from_headers(target_url))

    if client_surface_json and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            data = json.loads(client_surface_json)
            for d in data.get("detected_versions", []):
                key = (d.get("product"), d.get("version"))
                if key[0] and key[1] and not any(
                    (v.get("product"), v.get("version")) == key for v in all_versions
                ):
                    all_versions.append({
                        "product": d.get("product"),
                        "version": d.get("version"),
                        "source": d.get("source", "js"),
                    })
        except Exception:
            pass

        cdn_versions = _extract_cdn_versions(client_surface_json)
        for cv in cdn_versions:
            key = (cv["product"], cv["version"])
            if not any((v.get("product"), v.get("version")) == key for v in all_versions):
                all_versions.append(cv)

    if recon_json and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            data = json.loads(recon_json)
            for tech in data.get("technologies", []) or []:
                name = tech.get("name")
                ver = (tech.get("version") or "").strip()
                if name and ver:
                    key = (name, ver)
                    if not any(
                        (v.get("product"), v.get("version")) == key for v in all_versions
                    ):
                        all_versions.append({
                            "product": name, "version": ver, "source": "recon",
                        })
        except Exception:
            pass

    report.detected_versions = all_versions
    watchlist = _load_watchlist()
    products = watchlist.get("products", {})
    match_mode = watchlist.get("version_match", "prefix")

    cve_seen: set[tuple[str, str, str]] = set()
    for d in all_versions:
        product = d.get("product", "")
        version = d.get("version", "")
        if not product or not version or version == "unknown":
            continue
        product_key = product.split(" (")[0].strip()
        entries = products.get(product_key) or products.get(product)
        if not entries:
            continue
        for entry in entries:
            affected = entry.get("affected_versions") or entry.get("affected") or []
            if _version_in_affected(version, affected, match_mode):
                cve_id = str(entry.get("cve_id", "CVE"))
                dedupe_key = (product_key, version, cve_id)
                if dedupe_key in cve_seen:
                    break
                cve_seen.add(dedupe_key)
                report.findings.append(Finding(
                    title=f"Detected {product} {version}; {cve_id} may apply",
                    severity="High",
                    url=target_url,
                    category="Dependency / CVE",
                    evidence=(
                        f"Version {version} (source: {d.get('source', '')}) "
                        f"is in affected range. {entry.get('summary', '')}"
                    ),
                    impact="Known vulnerability may be exploitable. Verify patch status.",
                    remediation="Upgrade to a patched version and re-scan.",
                ))
                break

    if (time.time() - run_start) < RUN_BUDGET_SEC:
        osv_findings = _run_osv_lookup(all_versions, target_url, cve_seen)
        report.findings.extend(osv_findings)

    for d in all_versions:
        product = d.get("product", "")
        version = d.get("version", "")
        if not product or not version or version == "unknown":
            continue
        eol_finding = _check_eol(product, version, target_url)
        if eol_finding:
            report.findings.append(eol_finding)

    if report.detected_versions and not report.findings:
        report.findings.append(Finding(
            title="Detected versions (no CVE match)",
            severity="Info",
            url=target_url,
            category="Dependency / CVE",
            evidence="Collected: " + ", ".join(
                f"{v.get('product')} {v.get('version')}"
                for v in report.detected_versions[:10]
            ),
            impact="No known CVEs found in watchlist or OSV.dev for these versions.",
            remediation="Keep stack updated; re-scan periodically.",
        ))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url))
