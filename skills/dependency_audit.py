"""
Dependency / CVE audit skill — APT-style upgrade (Upgrade 2 + 5).
Collects product/version from headers and optional client_surface (or recon) output,
checks against a curated CVE watchlist, and reports "Detected [stack] [version]; CVE may apply."

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
RUN_BUDGET_SEC = 25
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


def _collect_versions_from_headers(url: str) -> list[dict]:
    versions: list[dict] = []
    try:
        r = SESSION.head(url, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code >= 400:
            r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Version"):
            val = r.headers.get(header_name)
            if not val:
                continue
            for pattern, product in HEADER_VERSION_RE:
                m = pattern.search(val)
                if m:
                    ver = (m.group(1) or "").strip()
                    if not ver:
                        ver = "unknown"
                    versions.append({"product": product, "version": ver, "source": f"header:{header_name}"})
                    break
    except requests.RequestException:
        pass
    return versions


def run(
    target_url: str,
    scan_type: str = "full",
    client_surface_json: Optional[str] = None,
    recon_json: Optional[str] = None,
) -> str:
    report = DependencyAuditReport(target_url=target_url)
    run_start = time.time()
    all_versions: list[dict] = []

    # From headers
    all_versions.extend(_collect_versions_from_headers(target_url))

    # From client_surface report
    if client_surface_json and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            data = json.loads(client_surface_json)
            for d in data.get("detected_versions", []):
                key = (d.get("product"), d.get("version"))
                if key[0] and key[1] and not any((v.get("product"), v.get("version")) == key for v in all_versions):
                    all_versions.append({"product": d.get("product"), "version": d.get("version"), "source": d.get("source", "js")})
        except Exception:
            pass

    # From recon technologies (optional)
    if recon_json and (time.time() - run_start) < RUN_BUDGET_SEC:
        try:
            data = json.loads(recon_json)
            for tech in data.get("technologies", []) or []:
                name = tech.get("name")
                ver = (tech.get("version") or "").strip()
                if name and ver:
                    key = (name, ver)
                    if not any((v.get("product"), v.get("version")) == key for v in all_versions):
                        all_versions.append({"product": name, "version": ver, "source": "recon"})
        except Exception:
            pass

    report.detected_versions = all_versions
    watchlist = _load_watchlist()
    products = watchlist.get("products", {})
    match_mode = watchlist.get("version_match", "prefix")

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
                report.findings.append(Finding(
                    title=f"Detected {product} {version}; {entry.get('cve_id', 'CVE')} may apply",
                    severity="High",
                    url=target_url,
                    category="Dependency / CVE",
                    evidence=f"Version {version} (source: {d.get('source', '')}) is in affected range. {entry.get('summary', '')}",
                    impact="Known vulnerability may be exploitable. Verify patch status.",
                    remediation="Upgrade to a patched version and re-scan.",
                ))
                break

    if report.detected_versions and not report.findings:
        report.findings.append(Finding(
            title="Detected versions (no CVE match in watchlist)",
            severity="Info",
            url=target_url,
            category="Dependency / CVE",
            evidence="Collected: " + ", ".join(f"{v.get('product')} {v.get('version')}" for v in report.detected_versions[:10]),
            impact="Update cve_watchlist.json when new critical CVEs drop to get alerts.",
            remediation="Keep stack updated; add new CVEs to watchlist for future scans.",
        ))

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url))
