"""
OSV.dev API client for live CVE / vulnerability lookups.

Free, keyless API maintained by Google. Covers npm, PyPI, crates.io, Go, Maven,
Packagist, Linux, WordPress, and more.

Docs: https://osv.dev/docs/  |  Batch: POST /v1/querybatch
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

OSV_API = "https://api.osv.dev/v1"
QUERY_TIMEOUT = 5
BATCH_BUDGET_SEC = 15

ECOSYSTEM_MAP: dict[str, str] = {
    "Next.js": "npm",
    "next": "npm",
    "Express": "npm",
    "express": "npm",
    "React": "npm",
    "react": "npm",
    "Vue": "npm",
    "vue": "npm",
    "Angular": "npm",
    "angular": "npm",
    "Svelte": "npm",
    "svelte": "npm",
    "lodash": "npm",
    "axios": "npm",
    "jquery": "npm",
    "webpack": "npm",
    "vite": "npm",
    "Django": "PyPI",
    "django": "PyPI",
    "Flask": "PyPI",
    "flask": "PyPI",
    "FastAPI": "PyPI",
    "fastapi": "PyPI",
    "WordPress": "WordPress",
    "nginx": "Linux",
    "Apache": "Linux",
    "PHP": "Packagist",
    "Node.js": "node",
    "node": "node",
    "Tomcat": "Maven",
    "Spring": "Maven",
    "spring-boot": "Maven",
    "Rails": "RubyGems",
    "Laravel": "Packagist",
    "Joomla": "Packagist",
    "Drupal": "Packagist",
}

# npm uses lowercase package names; map display names to registry names
_NPM_PACKAGE_MAP: dict[str, str] = {
    "Next.js": "next",
    "Express": "express",
    "React": "react",
    "Vue": "vue",
    "Angular": "@angular/core",
    "Svelte": "svelte",
}


@dataclass
class VulnResult:
    cve_id: str
    summary: str
    severity: str = "High"
    cvss_score: float | None = None
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    package: str = ""
    version: str = ""
    ecosystem: str = ""


class _Cache:
    """Simple TTL cache to avoid repeat queries within a scan."""

    def __init__(self, ttl_seconds: int = 3600):
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, list[dict]]] = {}

    def get(self, key: str) -> list[dict] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, data = entry
        if time.time() - ts > self._ttl:
            del self._store[key]
            return None
        return data

    def put(self, key: str, data: list[dict]) -> None:
        self._store[key] = (time.time(), data)

    def clear(self) -> None:
        self._store.clear()


_cache = _Cache(ttl_seconds=3600)


def _osv_package_name(product: str, ecosystem: str) -> str:
    """Resolve the canonical package name for OSV queries."""
    if ecosystem == "npm":
        return _NPM_PACKAGE_MAP.get(product, product.lower())
    return product


def resolve_ecosystem(product: str) -> str | None:
    """Map a product display name to its OSV ecosystem."""
    return ECOSYSTEM_MAP.get(product) or ECOSYSTEM_MAP.get(product.lower())


def _parse_severity(vuln: dict) -> tuple[str, float | None]:
    """Extract severity label + CVSS score from an OSV vulnerability object."""
    severity_list = vuln.get("severity") or []
    best_score: float | None = None
    for s in severity_list:
        score_str = s.get("score", "")
        try:
            score = float(score_str) if score_str else None
        except (ValueError, TypeError):
            vec = s.get("score", "")
            if "CVSS:" in str(vec):
                score = None
            else:
                score = None
        if score is not None:
            if best_score is None or score > best_score:
                best_score = score

    if best_score is not None:
        if best_score >= 9.0:
            return "Critical", best_score
        if best_score >= 7.0:
            return "High", best_score
        if best_score >= 4.0:
            return "Medium", best_score
        return "Low", best_score

    db_severity = (vuln.get("database_specific") or {}).get("severity", "")
    if isinstance(db_severity, str) and db_severity.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        label = db_severity.upper()
        if label == "MODERATE":
            label = "Medium"
        return label.capitalize(), None

    return "High", None


def _parse_fixed_versions(vuln: dict, ecosystem: str, package_name: str) -> list[str]:
    """Extract fixed version strings from affected ranges."""
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for evt in rng.get("events") or []:
                fix_ver = evt.get("fixed")
                if fix_ver and fix_ver not in fixed:
                    fixed.append(fix_ver)
    return fixed


def _parse_references(vuln: dict) -> list[str]:
    refs: list[str] = []
    for r in (vuln.get("references") or [])[:5]:
        url = r.get("url", "")
        if url:
            refs.append(url)
    return refs


def _parse_cve_id(vuln: dict) -> str:
    aliases = vuln.get("aliases") or []
    for a in aliases:
        if isinstance(a, str) and a.startswith("CVE-"):
            return a
    return vuln.get("id", "UNKNOWN")


def query(package: str, version: str, ecosystem: str) -> list[VulnResult]:
    """Query OSV for vulnerabilities affecting a specific package version."""
    cache_key = f"{ecosystem}:{package}:{version}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return [VulnResult(**d) for d in cached]

    pkg_name = _osv_package_name(package, ecosystem)
    payload: dict[str, Any] = {
        "version": version,
        "package": {"name": pkg_name, "ecosystem": ecosystem},
    }

    try:
        resp = requests.post(
            f"{OSV_API}/query",
            json=payload,
            timeout=QUERY_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    results: list[VulnResult] = []
    seen_ids: set[str] = set()
    for vuln in data.get("vulns") or []:
        cve_id = _parse_cve_id(vuln)
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        severity, cvss = _parse_severity(vuln)
        fixed = _parse_fixed_versions(vuln, ecosystem, pkg_name)
        refs = _parse_references(vuln)
        results.append(VulnResult(
            cve_id=cve_id,
            summary=(vuln.get("summary") or vuln.get("details") or "")[:300],
            severity=severity,
            cvss_score=cvss,
            fixed_versions=fixed,
            references=refs,
            package=package,
            version=version,
            ecosystem=ecosystem,
        ))

    _cache.put(cache_key, [asdict(r) for r in results])
    return results


def query_batch(
    items: list[tuple[str, str, str]],
) -> dict[str, list[VulnResult]]:
    """
    Query OSV for multiple (package, version, ecosystem) tuples.
    Returns {cache_key: [VulnResult, ...]}.
    Falls back to individual queries if batch API fails.
    """
    if not items:
        return {}

    start = time.time()
    all_results: dict[str, list[VulnResult]] = {}
    uncached: list[tuple[int, str, str, str]] = []

    for i, (pkg, ver, eco) in enumerate(items):
        cache_key = f"{eco}:{pkg}:{ver}"
        cached = _cache.get(cache_key)
        if cached is not None:
            all_results[cache_key] = [VulnResult(**d) for d in cached]
        else:
            uncached.append((i, pkg, ver, eco))

    if not uncached:
        return all_results

    queries = []
    for _, pkg, ver, eco in uncached:
        pkg_name = _osv_package_name(pkg, eco)
        queries.append({
            "version": ver,
            "package": {"name": pkg_name, "ecosystem": eco},
        })

    try:
        resp = requests.post(
            f"{OSV_API}/querybatch",
            json={"queries": queries},
            timeout=min(QUERY_TIMEOUT * len(queries), BATCH_BUDGET_SEC),
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OSV batch returned {resp.status_code}")
        batch_data = resp.json()
    except Exception:
        for _, pkg, ver, eco in uncached:
            if time.time() - start > BATCH_BUDGET_SEC:
                break
            key = f"{eco}:{pkg}:{ver}"
            all_results[key] = query(pkg, ver, eco)
        return all_results

    batch_results = batch_data.get("results") or []
    for idx, (_, pkg, ver, eco) in enumerate(uncached):
        cache_key = f"{eco}:{pkg}:{ver}"
        if idx >= len(batch_results):
            all_results[cache_key] = []
            continue
        vulns_data = batch_results[idx].get("vulns") or []
        pkg_name = _osv_package_name(pkg, eco)
        results: list[VulnResult] = []
        seen_ids: set[str] = set()
        for vuln in vulns_data:
            cve_id = _parse_cve_id(vuln)
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            severity, cvss = _parse_severity(vuln)
            fixed = _parse_fixed_versions(vuln, eco, pkg_name)
            refs = _parse_references(vuln)
            results.append(VulnResult(
                cve_id=cve_id,
                summary=(vuln.get("summary") or vuln.get("details") or "")[:300],
                severity=severity,
                cvss_score=cvss,
                fixed_versions=fixed,
                references=refs,
                package=pkg,
                version=ver,
                ecosystem=eco,
            ))
        _cache.put(cache_key, [asdict(r) for r in results])
        all_results[cache_key] = results

    return all_results
