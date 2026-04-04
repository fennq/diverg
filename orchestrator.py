#!/usr/bin/env python3
"""
Diverg orchestrator — runs security scans (web, recon, API, etc.) and can optionally
delegate to OpenClaw for multi-agent mode (--use-openclaw).

Usage:
    python orchestrator.py --target https://example.com --scope full
    python orchestrator.py --target example.com --scope recon
    python orchestrator.py --target https://example.com --scope quick --report detailed
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"
CONTENT_DIR = Path(__file__).parent / "content"

sys.path.insert(0, str(SKILLS_DIR))
sys.path.insert(0, str(SKILLS_DIR / "recon"))
sys.path.insert(0, str(SKILLS_DIR / "web_vulns"))
sys.path.insert(0, str(SKILLS_DIR / "headers_ssl"))
sys.path.insert(0, str(SKILLS_DIR / "auth_test"))
sys.path.insert(0, str(SKILLS_DIR / "api_test"))
sys.path.insert(0, str(SKILLS_DIR / "osint"))
sys.path.insert(0, str(SKILLS_DIR / "telegram_report"))


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

SCAN_PROFILES = {
    "full": [
        "osint", "recon", "headers_ssl", "crypto_security", "data_leak_risks", "company_exposure",
        "web_vulns", "auth_test", "api_test", "high_value_flaws", "workflow_probe", "race_condition",
        "payment_financial", "client_surface", "dependency_audit", "logic_abuse", "entity_reputation",
    ],
    "crypto": [
        "osint", "recon", "headers_ssl", "crypto_security", "data_leak_risks", "company_exposure",
        "web_vulns", "auth_test", "api_test", "high_value_flaws", "workflow_probe", "race_condition",
        "payment_financial", "client_surface", "chain_validation_abuse", "dependency_audit", "logic_abuse", "entity_reputation",
    ],
    "quick": ["headers_ssl", "recon", "osint", "company_exposure"],
    "recon": ["osint", "recon"],
    "web": ["web_vulns", "headers_ssl", "auth_test", "company_exposure"],
    "api": ["api_test", "headers_ssl", "company_exposure"],
    "passive": ["osint", "headers_ssl", "company_exposure"],
}


def skill_scan_type_for_scope(scope: str) -> str:
    """Per-skill intensity: dashboard 'quick' uses lighter internal passes."""
    return "quick" if scope == "quick" else "full"


SKILL_TIMEOUT_SECONDS = 20
MAX_DIRECT_WORKERS = 6


def skill_timeout_seconds_for_scope(scope: str) -> int:
    """Wall-clock per skill; higher for full/attack so internal skill budgets can complete."""
    s = (scope or "full").lower()
    if s == "quick":
        return int(os.environ.get("DIVERG_SKILL_TIMEOUT_QUICK", str(SKILL_TIMEOUT_SECONDS)))
    if s == "attack":
        return int(os.environ.get("DIVERG_SKILL_TIMEOUT_ATTACK", "45"))
    return int(os.environ.get("DIVERG_SKILL_TIMEOUT_FULL", "35"))


def _normalize_auth_context(auth: dict | None) -> dict | None:
    if not auth or not isinstance(auth, dict):
        return None
    cookie = (auth.get("cookie_header") or auth.get("cookies") or "").strip()
    bearer = (auth.get("bearer_token") or auth.get("bearer") or "").strip()
    if not cookie and not bearer:
        return None
    out: dict = {}
    if cookie:
        out["cookie_header"] = cookie[:8192]
    if bearer:
        out["bearer_token"] = bearer[:4096]
    return out


def _build_authenticated_session(auth: dict | None):
    """Return a StealthSession with Cookie / Authorization if auth provided; else None."""
    auth = _normalize_auth_context(auth)
    if not auth:
        return None
    from stealth import get_session

    sess = get_session()
    if auth.get("cookie_header"):
        sess.headers["Cookie"] = auth["cookie_header"]
    if auth.get("bearer_token"):
        sess.headers["Authorization"] = f"Bearer {auth['bearer_token']}"
    return sess


def _compute_scan_metrics(results: dict[str, dict], summary: dict, duration_sec: float) -> dict:
    ok = err = timeout = 0
    for _k, v in results.items():
        if not isinstance(v, dict):
            continue
        if v.get("error"):
            e = str(v.get("error", "")).lower()
            if "timed out" in e or "timeout" in e:
                timeout += 1
            else:
                err += 1
        else:
            ok += 1
    return {
        "scan_duration_sec": round(duration_sec, 3),
        "skills_scheduled": len(results),
        "skills_completed_ok": ok,
        "skills_error": err,
        "skills_timeout": timeout,
        "findings_critical": summary.get("critical", 0),
        "findings_high": summary.get("high", 0),
        "findings_medium": summary.get("medium", 0),
        "findings_low": summary.get("low", 0),
        "findings_info": summary.get("info", 0),
        "findings_total": summary.get("total_findings", 0),
    }
OPENCLAW_AGENT_RETRIES = 2
OPENCLAW_AGENT_TIMEOUTS = {
    "surface_mapper": 120,
    "exposure_analyst": 120,
    "auth_api_analyst": 120,
    "correlation_engine": 90,
    "report_composer": 90,
}
SKILL_TARGET_TYPE = {
    "osint": "domain",
    "recon": "domain",
    "headers_ssl": "url",
    "company_exposure": "url",
    "high_value_flaws": "url",
    "race_condition": "url",
    "workflow_probe": "url",
    "payment_financial": "url",
    "crypto_security": "url",
    "data_leak_risks": "url",
    "web_vulns": "url",
    "auth_test": "url",
    "api_test": "url",
    "client_surface": "url",
    "dependency_audit": "url",
    "logic_abuse": "url",
    "entity_reputation": "domain",
    "chain_validation_abuse": "url",
}
ENGAGEMENT_TRACKS = {
    "surface": ["osint", "recon", "headers_ssl", "company_exposure"],
    "application": ["web_vulns", "auth_test"],
    "api": ["api_test"],
}
AGENT_DIRECT_FALLBACKS = {
    "surface_mapper": ["osint", "recon", "headers_ssl", "company_exposure"],
    "exposure_analyst": ["company_exposure", "recon", "headers_ssl"],
    "auth_api_analyst": ["auth_test", "api_test", "web_vulns"],
}
SKILL_DESCRIPTIONS = {
    "osint": "external intelligence, DNS, historic exposure, and internet-facing context",
    "recon": "subdomains, ports, technologies, WAFs, and sensitive files",
    "headers_ssl": "transport, headers, and browser trust controls",
    "company_exposure": "admin, debug, docs, exports, storage, support, staging, and enterprise platforms",
    "high_value_flaws": "IDOR, secret exposure in frontend assets, business-logic and payment tampering",
    "race_condition": "concurrent-request testing for double success, duplicate processing, limit bypass",
    "workflow_probe": "Diverg-proprietary: business-flow order/state abuse — confirm without pay, zero-amount, skip steps",
    "payment_financial": "zero/manipulated payment, payment and wallet IDOR, refund abuse — how users lose money",
    "crypto_security": "JWT alg:none/weak, weak TLS 1.0/1.1, weak crypto in frontend JS",
    "data_leak_risks": "verbose errors, cache misconfig, PII/token in responses and client-side — small leaks that become huge",
    "web_vulns": "web-layer flaw checks such as injection, traversal, SSRF, and file exposure",
    "auth_test": "login, identity, JWT, session, credential hygiene, and enumeration exposure",
    "api_test": "endpoint discovery, methods, auth gaps, schema exposure, and API abuse patterns",
    "client_surface": "frontend JS intel, source maps, API extraction, dangerous sinks, extracted_endpoints",
    "dependency_audit": "detected stack/versions, CVE watchlist, upgrade recommendations",
    "logic_abuse": "numeric/bounds abuse (amount, limit, offset), overflow, success-like response to tampered params",
    "entity_reputation": "domain owner/entity foul-play research, fraud/lawsuit/breach/reputation searches",
    "chain_validation_abuse": "Diverg batch validation: batch vs single path validation, account/subaccount ID substitution, parameter trust (see content/diverg-batch-validation-routes.md)",
}

# Canonical finding schema — all skills normalize to this shape for dedup and correlation
FINDING_KEYS = ("title", "severity", "url", "category", "evidence", "impact", "remediation", "_source_skill")


# ---------------------------------------------------------------------------
# Evidence normalization (shared schema)
# ---------------------------------------------------------------------------

def normalize_finding(raw: dict, source_skill: str, context_key: str = "findings") -> dict:
    """Map any skill output into the canonical finding schema. Dedup and correlation use this."""
    out: dict = {
        "title": "",
        "severity": "Info",
        "url": "",
        "category": "Assessment",
        "evidence": "",
        "impact": "Requires analyst review.",
        "remediation": "Review and harden the affected surface.",
        "_source_skill": source_skill,
        "_normalized": True,
    }
    if context_key == "header_findings":
        header = str(raw.get("header", "")).strip()
        status = str(raw.get("status", "")).strip()
        value = raw.get("value") or ""
        rec = str(raw.get("recommendation", "")).strip()
        out["title"] = f"HTTP header: {header} — {status}"
        out["severity"] = str(raw.get("severity", "Info"))
        out["evidence"] = f"Header: {header}; Value: {value}; Recommendation: {rec}"
        out["category"] = "Transport and Browser Security"
        out["remediation"] = rec or out["remediation"]
        if raw.get("context"):
            out["context"] = str(raw["context"]).strip()
        if raw.get("finding_type"):
            out["finding_type"] = str(raw["finding_type"]).strip()
        return out
    if context_key == "ssl_findings":
        check = str(raw.get("check", "")).strip()
        status = str(raw.get("status", "")).strip()
        detail = str(raw.get("detail", "")).strip()
        out["title"] = f"SSL/TLS: {check} — {status}"
        out["severity"] = str(raw.get("severity", "Info"))
        out["evidence"] = detail or check
        out["category"] = "Transport and Browser Security"
        return out
    # Standard finding shape (findings from web_vulns, auth_test, api_test, company_exposure, etc.)
    out["title"] = str(raw.get("title") or raw.get("check") or raw.get("header") or "Untitled finding").strip()
    out["severity"] = str(raw.get("severity", "Info"))
    out["url"] = str(raw.get("url", "")).strip()
    out["category"] = str(raw.get("category", "Assessment")).strip()
    out["evidence"] = str(raw.get("evidence") or raw.get("detail") or raw.get("value") or raw.get("recommendation") or raw.get("snippet") or "").strip() or "See source output."
    out["impact"] = str(raw.get("impact") or raw.get("relevance_hint") or out["impact"]).strip()
    out["remediation"] = str(raw.get("remediation") or raw.get("recommendation") or out["remediation"]).strip()
    # Preserve zero-FP / workflow fields so reports and UI can show replay steps
    if raw.get("verification_steps") is not None:
        out["verification_steps"] = raw["verification_steps"]
    if raw.get("confidence"):
        out["confidence"] = str(raw["confidence"]).strip()
    if raw.get("context"):
        out["context"] = str(raw["context"]).strip()
    if raw.get("finding_type"):
        out["finding_type"] = str(raw["finding_type"]).strip()
    return out


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Merge duplicates by (title, url, category), keep highest severity and merged evidence.

    Output is sorted deterministically (severity, title, url) so that
    thread-completion order never affects the final report.
    """
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    by_key: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        title = (f.get("title") or "").strip() or "Untitled"
        url = (f.get("url") or "").strip()
        category = (f.get("category") or "").strip() or "General"
        key = (title[:120], url[:200], category[:80])
        if key not in by_key or severity_rank.get(f.get("severity", "Info"), 99) < severity_rank.get(by_key[key].get("severity", "Info"), 99):
            by_key[key] = dict(f)
        else:
            existing = by_key[key]
            existing["evidence"] = (existing.get("evidence") or "") + "; " + (f.get("evidence") or "")
    deduped = list(by_key.values())
    deduped.sort(key=lambda f: (
        severity_rank.get(f.get("severity", "Info"), 99),
        (f.get("title") or "").lower(),
        (f.get("url") or "").lower(),
    ))
    return deduped


def _normalize_confidence_value(value) -> str | None:
    if value is None:
        return None
    c = str(value).strip().lower()
    if c in ("high", "medium", "low"):
        return c
    if c in ("confirmed", "confirm"):
        return "high"
    if c in ("unconfirmed", "possible", "inferential", "low confidence"):
        return "low"
    return None


def _default_finding_source(f: dict) -> str:
    existing = str(f.get("source") or "").strip()
    if existing:
        return existing
    skill = str(f.get("_source_skill") or "").strip().lower()
    category = str(f.get("category") or "").strip().lower()
    if skill == "headers_ssl" or ("transport" in category and "browser" in category):
        return "header_analysis"
    if skill == "client_surface" or "client" in category:
        return "dom_scan"
    if skill == "data_leak_risks" or "sensitive" in category:
        return "regex_match"
    if skill == "entity_reputation":
        return "entity_reputation"
    if skill == "dependency_audit":
        return "dependency_audit"
    if skill == "logic_abuse":
        return "logic_abuse"
    if skill:
        return skill.replace(" ", "_")
    return "analysis"


def _default_finding_confidence(f: dict, source: str) -> str:
    sev = str(f.get("severity") or "").strip().lower()
    if source == "header_analysis":
        return "high"
    if source == "regex_match":
        return "medium" if sev == "high" else "low"
    if source in ("dom_scan", "entity_reputation", "dependency_audit", "logic_abuse"):
        return "medium" if sev in ("critical", "high") else ("low" if sev == "info" else "medium")
    if source == "analysis":
        return "low" if sev == "info" else "medium"
    return "medium"


def _infer_verified(f: dict, source: str) -> bool:
    if f.get("verified") is not None:
        return bool(f["verified"])
    raw_conf = str(f.get("confidence") or "").strip().lower()
    if raw_conf in ("confirmed", "confirm"):
        return True
    title = str(f.get("title") or "")
    ev = str(f.get("evidence") or "")
    if "[confirmed]" in title.lower() or "[confirmed]" in ev.lower():
        return True
    if source == "header_analysis":
        return True
    return False


_FC_TO_CONFIDENCE = {
    "confirmed": "high",
    "likely": "medium",
    "possible": "low",
    "informational": "low",
}


def finalize_api_findings(findings: list[dict]) -> list[dict]:
    """Normalize confidence, source, proof, and verified for API/extension clients.

    Respects the ``finding_confidence`` tier set by skills (confirmed / likely /
    possible / informational) and maps it to the API-level ``confidence`` and
    ``verified`` fields.
    """
    out: list[dict] = []
    for raw in findings:
        f = dict(raw)
        source = _default_finding_source(f)

        fc = str(f.get("finding_confidence") or "").strip().lower()
        if fc in _FC_TO_CONFIDENCE:
            conf = _FC_TO_CONFIDENCE[fc]
            verified = fc == "confirmed"
            if fc == "possible":
                ev = f.get("evidence") or ""
                if not ev.startswith("[Needs manual verification]"):
                    f["evidence"] = f"[Needs manual verification] {ev}"
        else:
            verified = _infer_verified(f, source)
            conf = _normalize_confidence_value(f.get("confidence")) or _default_finding_confidence(f, source)

        f["source"] = source
        f["confidence"] = conf
        proof = str(f.get("proof") or "").strip()
        if not proof:
            ev = str(f.get("evidence") or "")
            proof = ev[:280] if ev else ""
        f["proof"] = proof
        f["verified"] = verified
        out.append(f)
    return out


def build_evidence_summary(findings: list[dict]) -> dict:
    """Roll-up aligned with extension `buildEvidenceSummary` (+ optional top_sources)."""
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    source_breakdown: dict[str, int] = {}
    finding_type_counts = {"vulnerability": 0, "hardening": 0, "informational": 0, "positive": 0}
    verified_count = 0
    for f in findings:
        conf = _normalize_confidence_value(f.get("confidence")) or "medium"
        if conf not in confidence_counts:
            conf = "medium"
        confidence_counts[conf] += 1
        src = str(f.get("source") or "unknown").strip() or "unknown"
        source_breakdown[src] = source_breakdown.get(src, 0) + 1
        if f.get("verified"):
            verified_count += 1
        ft = str(f.get("finding_type") or "").strip().lower()
        if ft in finding_type_counts:
            finding_type_counts[ft] += 1
    total = len(findings)
    verified_ratio = round((verified_count / total), 2) if total else 0.0
    if confidence_counts["high"] >= 3 or verified_ratio >= 0.5:
        quality = "strong"
    elif confidence_counts["high"] >= 1 or confidence_counts["medium"] >= 3:
        quality = "moderate"
    else:
        quality = "limited"
    top_sources = [name for name, _ in sorted(source_breakdown.items(), key=lambda x: (-x[1], x[0]))[:5]]
    return {
        "total_findings": total,
        "confidence_counts": confidence_counts,
        "finding_type_counts": finding_type_counts,
        "verified_count": verified_count,
        "unverified_count": max(0, total - verified_count),
        "verified_ratio": verified_ratio,
        "source_breakdown": dict(sorted(source_breakdown.items(), key=lambda item: (-item[1], item[0]))),
        "top_sources": top_sources,
        "quality": quality,
    }


# ---------------------------------------------------------------------------
# Phase 4: intelligence synthesis (attack paths, risk score, remediation)
# ---------------------------------------------------------------------------

def _remediation_item(f: dict) -> dict:
    er = f.get("exploit_ref") if isinstance(f.get("exploit_ref"), dict) else {}
    rem = str(f.get("remediation") or "").strip() or str(er.get("prevention") or "").strip()
    return {
        "title": str(f.get("title") or "")[:240],
        "url": str(f.get("url") or "")[:500],
        "severity": str(f.get("severity") or "Info"),
        "finding_type": str(f.get("finding_type") or ""),
        "remediation": rem or "Review and remediate.",
    }


def compute_risk_score(findings: list[dict], attack_paths_list: list[dict]) -> dict:
    """0–100 score and verdict; weights hardening lower than real vulnerabilities."""
    base_penalty = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}
    conf_w = {"high": 1.0, "medium": 0.65, "low": 0.35}
    type_mult = {"vulnerability": 1.0, "hardening": 0.4, "informational": 0.35, "positive": 0.0, "": 0.85}
    deductions = 0.0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    has_sensitive = False
    for f in findings:
        ftype = str(f.get("finding_type") or "").strip().lower()
        if ftype == "positive":
            continue
        sev = str(f.get("severity") or "Info").strip()
        base = base_penalty.get(sev, 0)
        lk = sev.lower()
        if lk in counts:
            counts[lk] += 1
        conf = _normalize_confidence_value(f.get("confidence")) or "medium"
        cw = conf_w.get(conf, 0.65)
        tm = type_mult.get(ftype, 0.85)
        deductions += base * cw * tm
        cat = str(f.get("category") or "").lower()
        if cat == "sensitive data" and conf != "low":
            has_sensitive = True
    deductions += min(25.0, len(attack_paths_list or []) * 3.0)
    score = int(round(max(0.0, min(100.0, 100.0 - deductions))))
    verdict = "Safe"
    summary_text = "Safe to run"
    safe_to_run = True
    if counts["critical"] > 0 or score < 40:
        verdict = "Risky"
        summary_text = "Not recommended — significant security risks"
        safe_to_run = False
    elif counts["high"] > 0 or score < 70 or has_sensitive:
        verdict = "Caution"
        summary_text = "Sensitive data patterns — proceed with caution" if has_sensitive else "Proceed with caution"
        safe_to_run = False
    return {
        "score": score,
        "verdict": verdict,
        "summary_text": summary_text,
        "safe_to_run": safe_to_run,
        "counts": counts,
    }


def _build_scan_fingerprint(target_url: str, skills: list[str], timestamp: str) -> dict:
    """Deterministic metadata block so two scans can be compared."""
    seed_material = f"{target_url}|{','.join(sorted(skills))}|{timestamp[:16]}"
    fp_hash = hashlib.sha256(seed_material.encode()).hexdigest()[:16]
    return {
        "hash": fp_hash,
        "target": target_url,
        "skills": sorted(skills),
        "timestamp": timestamp,
        "deterministic_ordering": True,
        "soft_404_baseline": True,
        "content_verified_findings": True,
        "second_pass_verification": True,
    }


def build_remediation_plan(findings: list[dict], attack_paths_list: list[dict]) -> dict:
    """Tiered remediation: fix now / fix soon / harden."""
    chain_titles: set[str] = set()
    for p in attack_paths_list or []:
        for s in p.get("steps") or []:
            t = (s.get("finding_title") or "").strip()
            if t:
                chain_titles.add(t)
                chain_titles.add(t[:80])

    fix_now: list[dict] = []
    fix_soon: list[dict] = []
    harden: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def take(bucket: list[dict], f: dict) -> None:
        title = str(f.get("title") or "").strip()
        url = str(f.get("url") or "").strip()
        key = (title[:240], url[:400])
        if key in seen:
            return
        seen.add(key)
        bucket.append(_remediation_item(f))

    for f in findings:
        if str(f.get("finding_type") or "").lower() == "positive":
            continue
        title_full = str(f.get("title") or "").strip()
        title_trim = title_full[:120]
        ftype = str(f.get("finding_type") or "").lower()
        sev_l = str(f.get("severity") or "Info").strip().lower()
        in_chain = title_trim in chain_titles or (len(title_full) >= 8 and title_full[:80] in chain_titles)

        if in_chain or (ftype == "vulnerability" and sev_l in ("critical", "high")):
            take(fix_now, f)
        elif ftype == "vulnerability" and sev_l == "medium":
            take(fix_soon, f)
        elif ftype == "hardening" and sev_l == "high":
            take(fix_soon, f)
        else:
            take(harden, f)

    return {"fix_now": fix_now, "fix_soon": fix_soon, "harden_when_possible": harden}


def run_phase4_synthesis(target_url: str, results: dict[str, dict], findings: list[dict]) -> dict:
    """Correlate scan results into attack paths, risk score, and remediation tiers."""
    attack_payload: dict = {
        "paths": [],
        "gap_analysis": [],
        "suggested_next_actions": [],
        "role_counts": {},
        "note": "",
    }
    try:
        import attack_paths as attack_paths_skill

        raw = attack_paths_skill.run(target_url, prior_results=results)
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            attack_payload = parsed
    except Exception as exc:
        attack_payload["note"] = f"Phase 4 attack-path correlation failed: {exc}"

    paths_list = attack_payload.get("paths") if isinstance(attack_payload.get("paths"), list) else []
    risk = compute_risk_score(findings, paths_list)
    remediation = build_remediation_plan(findings, paths_list)

    return {
        "attack_paths": paths_list,
        "gap_analysis": attack_payload.get("gap_analysis") or [],
        "suggested_next_tests": attack_payload.get("suggested_next_actions") or [],
        "attack_path_role_counts": attack_payload.get("role_counts") or {},
        "attack_paths_note": attack_payload.get("note", ""),
        "risk_score": risk["score"],
        "risk_verdict": risk["verdict"],
        "risk_summary": risk["summary_text"],
        "safe_to_run": risk["safe_to_run"],
        "remediation_plan": remediation,
    }


# ---------------------------------------------------------------------------
# Exploit catalog — map findings to known exploits and prevention
# ---------------------------------------------------------------------------

_EXPLOIT_CATALOG_CACHE: list[dict] | None = None


def _load_exploit_catalog() -> list[dict]:
    """Load exploit catalog from content/exploit_catalog.json (cached)."""
    global _EXPLOIT_CATALOG_CACHE
    if _EXPLOIT_CATALOG_CACHE is not None:
        return _EXPLOIT_CATALOG_CACHE
    path = CONTENT_DIR / "exploit_catalog.json"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        _EXPLOIT_CATALOG_CACHE = data.get("exploits", [])
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        _EXPLOIT_CATALOG_CACHE = []
    return _EXPLOIT_CATALOG_CACHE


def _enrich_finding_with_exploit(finding: dict, catalog: list[dict]) -> None:
    """If finding title/category match an exploit, add exploit_ref (name, owasp, cwe, prevention)."""
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    # For Transport/Browser Security, require title match so SSL/connection issues don't get clickjacking
    require_title = "transport" in category and "browser" in category
    best = None
    best_score = 0
    for ex in catalog:
        title_kw = [k.lower() for k in ex.get("keywords_title", [])]
        cat_kw = [k.lower() for k in ex.get("keywords_category", [])]
        title_match = any(k in title for k in title_kw) if title_kw else False
        cat_match = any(k in category for k in cat_kw) if cat_kw else False
        if require_title and not title_match:
            continue
        if not (title_match or cat_match):
            continue
        score = (2 if title_match else 0) + (1 if cat_match else 0)
        if score > best_score:
            best_score = score
            best = ex
    if best:
        finding["exploit_ref"] = {
            "name": best.get("name", ""),
            "owasp": best.get("owasp", ""),
            "cwe": best.get("cwe", ""),
            "exploitation": best.get("exploitation", ""),
            "prevention": best.get("prevention", ""),
        }
        if not (finding.get("remediation") or "").strip():
            finding["remediation"] = best.get("prevention", finding.get("remediation", ""))


def enrich_findings_with_exploits(findings: list[dict]) -> list[dict]:
    """Attach exploit_ref (name, owasp, cwe, prevention) to findings that match the catalog."""
    catalog = _load_exploit_catalog()
    if not catalog:
        return findings
    for f in findings:
        _enrich_finding_with_exploit(f, catalog)
    return findings


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ____            _____         _
 / ___|  ___  ___| ____|_ _ ___| |_ ___ _ __
 \___ \ / _ \/ __|  _| / _` / __| __/ _ \ '__|
  ___) |  __/ (__| |__| (_| \__ \ ||  __/ |
 |____/ \___|\___|_____\__,_|___/\__\___|_|

  AI-Powered Security Testing Agent
"""


# ---------------------------------------------------------------------------
# Skill runner
# ---------------------------------------------------------------------------

def run_skill_variant(
    skill_name: str,
    target: str,
    target_url: str,
    *,
    scan_type: str = "full",
    wordlist: str = "medium",
    crawl_depth: int = 2,
    context: dict | None = None,
    scan_scope: str = "full",
    auth_context: dict | None = None,
) -> dict:
    """Import and execute a skill, returning its parsed JSON output.

    scan_type/wordlist apply only to skills that support them (e.g. api_test, recon, auth_test, company_exposure).
    context: optional dict with client_surface_json, recon_json, osint_json, api_results_json for skills that use them.
    """
    print(f"\n{'='*60}")
    print(f"  Running: {skill_name}")
    print(f"  Target:  {target}")
    print(f"{'='*60}")

    ctx = context or {}
    auth_sess = _build_authenticated_session(auth_context)
    from scan_context import clear_active_http_session, set_active_http_session

    if auth_sess:
        set_active_http_session(auth_sess)
    try:
        if skill_name == "recon":
            import recon
            raw = recon.run(target, scan_type=scan_type)
        elif skill_name == "web_vulns":
            import web_vulns
            raw = web_vulns.run(target_url, scan_type=scan_type, crawl_depth=crawl_depth)
        elif skill_name == "headers_ssl":
            import headers_ssl
            raw = headers_ssl.run(target_url, scan_type=scan_type)
        elif skill_name == "company_exposure":
            import company_exposure
            raw = company_exposure.run(target_url, scan_type=scan_type)
        elif skill_name == "high_value_flaws":
            import high_value_flaws
            raw = high_value_flaws.run(target_url, scan_type=scan_type)
        elif skill_name == "race_condition":
            import race_condition
            raw = race_condition.run(target_url, scan_type=scan_type)
        elif skill_name == "workflow_probe":
            import workflow_probe
            raw = workflow_probe.run(target_url, scan_type=scan_type)
        elif skill_name == "payment_financial":
            import payment_financial
            raw = payment_financial.run(target_url, scan_type=scan_type)
        elif skill_name == "crypto_security":
            import crypto_security
            raw = crypto_security.run(target_url, scan_type=scan_type)
        elif skill_name == "data_leak_risks":
            import data_leak_risks
            raw = data_leak_risks.run(target_url, scan_type=scan_type)
        elif skill_name == "auth_test":
            import auth_test
            raw = auth_test.run(target_url, scan_type=scan_type)
        elif skill_name == "api_test":
            import api_test
            raw = api_test.run(
                target_url,
                scan_type=scan_type,
                wordlist=wordlist,
                client_surface_json=ctx.get("client_surface_json"),
            )
        elif skill_name == "osint":
            import osint
            raw = osint.run(target, scan_type=scan_type)
        elif skill_name == "client_surface":
            import client_surface
            raw = client_surface.run(target_url, scan_type=scan_type)
        elif skill_name == "dependency_audit":
            import dependency_audit
            raw = dependency_audit.run(
                target_url,
                scan_type=scan_type,
                client_surface_json=ctx.get("client_surface_json"),
                recon_json=ctx.get("recon_json"),
            )
        elif skill_name == "logic_abuse":
            import logic_abuse
            raw = logic_abuse.run(
                target_url,
                scan_type=scan_type,
                client_surface_json=ctx.get("client_surface_json"),
            )
        elif skill_name == "entity_reputation":
            import entity_reputation
            raw = entity_reputation.run(target, scan_type=scan_type, osint_json=ctx.get("osint_json"))
        elif skill_name == "chain_validation_abuse":
            import chain_validation_abuse
            raw = chain_validation_abuse.run(
                target_url,
                scan_type=scan_type,
                client_surface_json=ctx.get("client_surface_json"),
                api_results_json=ctx.get("api_results_json"),
            )
        else:
            return {"error": f"Unknown skill: {skill_name}"}

        result = json.loads(raw)
        finding_count = len(result.get("findings", []))
        finding_count += len(result.get("header_findings", []))
        finding_count += len(result.get("ssl_findings", []))
        print(f"  -> Completed with {finding_count} findings")
        return result

    except Exception as exc:
        print(f"  -> ERROR: {exc}")
        return {"error": str(exc), "skill": skill_name}
    finally:
        if auth_sess:
            clear_active_http_session()


def run_skill(
    skill_name: str,
    target: str,
    target_url: str,
    context: dict | None = None,
    *,
    scan_type: str = "full",
    wordlist: str = "medium",
    crawl_depth: int = 2,
    scan_scope: str = "full",
    auth_context: dict | None = None,
) -> dict:
    """Run one skill; scan_type 'quick' triggers lighter work inside supported skills."""
    return run_skill_variant(
        skill_name, target, target_url,
        scan_type=scan_type, wordlist=wordlist, crawl_depth=crawl_depth, context=context,
        scan_scope=scan_scope, auth_context=auth_context,
    )


# ---------------------------------------------------------------------------
# Report aggregation
# ---------------------------------------------------------------------------

_PUBLIC_PATH_PATTERNS = re.compile(
    r"^/(?:index\.?\w*|about|contact|login|register|signup|sign-up|"
    r"api/health|api/status|api/ping|health|status|favicon\.ico|robots\.txt|"
    r"sitemap\.xml|manifest\.json|service-worker\.js)?$",
    re.IGNORECASE,
)
_STATIC_PREFIXES = ("/static/", "/assets/", "/css/", "/js/", "/images/", "/img/", "/fonts/", "/media/", "/public/")


def _second_pass_verify(findings: list[dict]) -> list[dict]:
    """Re-verify Critical/High findings that are not already confirmed.

    Re-requests the URL and checks if the original evidence indicator still
    holds. Downgrades to ``possible`` if the re-check fails, preventing
    transient network artefacts from inflating severity.
    """
    import requests as _requests

    out: list[dict] = []
    for f in findings:
        sev = str(f.get("severity") or "").strip()
        fc = str(f.get("finding_confidence") or "").strip().lower()
        if sev not in ("Critical", "High") or fc == "confirmed":
            out.append(f)
            continue

        url = f.get("url") or ""
        if not url or not url.startswith("http"):
            out.append(f)
            continue

        try:
            resp = _requests.get(url, timeout=6, allow_redirects=False, verify=False)
            evidence = str(f.get("evidence") or "")
            title_lower = str(f.get("title") or "").lower()

            still_valid = False
            if "sensitive file" in title_lower or "accessible:" in title_lower.lower():
                still_valid = resp.status_code == 200 and len(resp.text) > 50
            elif "sql injection" in title_lower:
                for pat_str in ("error", "mysql", "postgresql", "oracle", "sqlite", "sql"):
                    if pat_str in resp.text.lower():
                        still_valid = True
                        break
                if not still_valid and resp.status_code == 200:
                    still_valid = True
            elif "xss" in title_lower:
                still_valid = resp.status_code == 200
            else:
                still_valid = resp.status_code == 200

            if still_valid:
                out.append(f)
            else:
                downgraded = dict(f)
                downgraded["finding_confidence"] = "possible"
                downgraded["evidence"] = f"[Needs manual verification] Second-pass re-check did not reproduce finding. " + evidence
                out.append(downgraded)
        except Exception:
            out.append(f)
    return out


def _is_public_route(url: str) -> bool:
    """Return True if *url* matches a common public / marketing / static path."""
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
    except Exception:
        path = url
    if _PUBLIC_PATH_PATTERNS.match(path):
        return True
    path_lower = path.lower()
    return any(path_lower.startswith(p) for p in _STATIC_PREFIXES)


def aggregate_findings(results: dict[str, dict]) -> list[dict]:
    """Collect all findings from every skill into a single flat list; normalize to canonical schema and dedupe."""
    all_findings: list[dict] = []

    for skill_name, result in sorted(results.items()):
        if "error" in result and isinstance(result["error"], str):
            all_findings.append(normalize_finding({
                "title": f"Skill '{skill_name}' encountered an error",
                "severity": "Info",
                "evidence": result["error"],
                "impact": "Some tests could not be completed.",
                "remediation": "Check skill configuration and try again.",
            }, skill_name, "findings"))
            continue

        for key in ("findings", "header_findings", "ssl_findings"):
            for raw in result.get(key, []):
                if not isinstance(raw, dict):
                    continue
                all_findings.append(normalize_finding(raw, skill_name, key))

        for port in result.get("ports", []):
            if port.get("state") == "open":
                all_findings.append(normalize_finding({
                    "title": f"Open port {port['port']} ({port.get('service', 'unknown')})",
                    "severity": "Info",
                    "url": result.get("target", ""),
                    "category": "Reconnaissance",
                    "evidence": f"Port {port['port']}: {port.get('service', '')} {port.get('version', '')}",
                    "impact": "Open ports increase the attack surface.",
                    "remediation": "Close unnecessary ports and services.",
                }, skill_name, "findings"))

        for ep in result.get("endpoints_found", []):
            if not ep.get("auth_required") and ep.get("status_code") == 200:
                ep_url = ep.get("url", "")
                if _is_public_route(ep_url):
                    continue
                all_findings.append(normalize_finding({
                    "title": f"Unauthenticated endpoint: {ep_url}",
                    "severity": "Info",
                    "url": ep_url,
                    "category": "API Discovery",
                    "evidence": f"Status: {ep['status_code']}, Methods: {', '.join(ep.get('methods', []))}",
                    "impact": "Publicly accessible endpoints may leak information.",
                    "remediation": "Review if this endpoint should require authentication.",
                }, skill_name, "findings"))

    deduped = dedupe_findings(all_findings)
    deduped = _second_pass_verify(deduped)
    enriched = enrich_findings_with_exploits(deduped)
    try:
        from rag import build_index, enrich_findings_with_citations

        if not getattr(aggregate_findings, "_rag_index_built", False):
            build_index()
            aggregate_findings._rag_index_built = True
        enrich_findings_with_citations(enriched)
    except Exception:
        pass
    return finalize_api_findings(enriched)


def aggregate_company_surfaces(results: dict[str, dict]) -> list[dict]:
    surfaces: list[dict] = []
    for skill_name, result in results.items():
        for surface in result.get("surfaces", []):
            enriched = dict(surface)
            enriched["_source_skill"] = skill_name
            surfaces.append(enriched)
    return surfaces


def infer_priority_tracks(target: str, scope: str) -> list[str]:
    hay = f"{target} {scope}".lower()
    tracks = ["surface"]
    if any(token in hay for token in ("api", "graphql", "swagger", "openapi")):
        tracks.append("api")
    if scope not in {"passive", "recon"}:
        tracks.append("application")
    return list(dict.fromkeys(tracks))


def infer_engagement_mode(target: str, scope: str) -> str:
    hay = f"{target} {scope}".lower()
    if any(token in hay for token in ("api", "graphql", "swagger", "openapi")):
        return "api-centric"
    if any(token in hay for token in ("admin", "auth", "sso", "login", "portal")):
        return "identity-and-operations"
    if scope in {"passive", "recon", "quick"}:
        return "surface-triage"
    return "broad-attack-surface"


def infer_dynamic_routing(mapper_payload: dict | None, exposure_payload: dict | None) -> dict:
    """Use early surface/exposure outputs to decide which specialist stages to run and at what depth."""
    routing = {
        "run_auth_api": True,
        "run_application": True,
        "api_depth": "full",
        "application_depth": "full",
        "focus_areas": ["admin", "identity", "debug", "docs", "exports", "storage", "support", "staging", "api"],
    }
    if not mapper_payload and not exposure_payload:
        return routing

    def text_from(*sources: dict | None) -> str:
        hay_parts: list[str] = []
        for src in sources:
            if not src or not isinstance(src, dict):
                continue
            for key in ("summary", "high_value_surfaces", "target_profiles", "platform_signals", "findings", "exposed_surfaces", "exposed_platforms"):
                val = src.get(key)
                if isinstance(val, str):
                    hay_parts.append(val.lower())
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            hay_parts.append(json.dumps(item).lower())
                        else:
                            hay_parts.append(str(item).lower())
        return " ".join(hay_parts)

    hay = text_from(mapper_payload, exposure_payload)

    api_signals = ["/api", "graphql", "swagger", "openapi", "rest", "endpoint", "api-docs", "webhook"]
    app_signals = ["admin", "login", "auth", "dashboard", "manage", "console", "sso", "jwt", "session"]
    has_api = any(s in hay for s in api_signals)
    has_app = any(s in hay for s in app_signals)

    if not has_api and not has_app:
        routing["run_auth_api"] = False
        routing["api_depth"] = "light"
        routing["application_depth"] = "light"
        routing["focus_areas"] = ["surface mapping", "recon", "headers", "company_exposure"]
    elif not has_api:
        routing["run_auth_api"] = True
        routing["api_depth"] = "light"
        routing["application_depth"] = "full"
        routing["focus_areas"] = ["admin", "identity", "auth", "application", "company exposure"]
    elif not has_app:
        routing["run_auth_api"] = True
        routing["api_depth"] = "full"
        routing["application_depth"] = "light"
        routing["focus_areas"] = ["api", "endpoints", "schema", "auth headers", "company exposure"]

    # If mapper found almost nothing, keep full depth but note triage
    if mapper_payload and isinstance(mapper_payload.get("findings"), list):
        if len(mapper_payload.get("high_value_surfaces") or []) == 0 and len(mapper_payload.get("findings", [])) < 2:
            routing["application_depth"] = "light"
            routing["api_depth"] = "light"

    return routing


def build_openclaw_manifest(target: str, scope: str, report_type: str) -> dict:
    profile = SCAN_PROFILES.get(scope, SCAN_PROFILES["full"])
    priority_tracks = infer_priority_tracks(target, scope)
    engagement_mode = infer_engagement_mode(target, scope)
    return {
        "target": target,
        "scope": scope,
        "report_type": report_type,
        "engagement_mode": engagement_mode,
        "priority_tracks": priority_tracks,
        "skills": [
            {
                "name": skill,
                "target_type": SKILL_TARGET_TYPE.get(skill, "url"),
                "purpose": SKILL_DESCRIPTIONS.get(skill, skill),
            }
            for skill in profile
        ],
        "operator_intent": [
            "Run an authorized assessment with evidence-backed findings only.",
            "Prioritize company-risk surfaces before commodity issues when evidence supports it.",
            "Correlate admin, identity, debug, docs, exports, storage, support, staging, and API exposure.",
            "Do not exfiltrate real user data or secrets; redact and summarize exposure safely.",
        ],
        "evidence_contract": {
            "confirmed_only_for_raw_evidence": True,
            "require_source_tags": True,
            "highlight_scan_gaps": True,
            "rank_by_company_impact": True,
        },
        "parallel_workstreams": {
            track: [skill for skill in profile if skill in ENGAGEMENT_TRACKS[track]]
            for track in priority_tracks
        },
    }


def build_openclaw_prompt(target: str, scope: str, report_type: str) -> str:
    manifest = build_openclaw_manifest(target, scope, report_type)
    return (
        "Run an authorized security assessment using the configured agents as coordinated workstreams, not a single linear prompt.\n\n"
        f"ENGAGEMENT MANIFEST:\n{json.dumps(manifest, indent=2)}\n\n"
        "EXECUTION RULES:\n"
        "- Use the listed skills as coordinated workstreams.\n"
        "- Start with surface mapping and company-exposure context, then deepen only where evidence warrants it.\n"
        "- Prioritize admin, identity, docs/schema, debug, observability, exports, storage, support, staging, and API exposure.\n"
        "- Correlate findings across skills and call out likely attack paths, control gaps, and scan gaps.\n"
        "- Keep evidence factual and sanitized. Never output raw credentials, tokens, or personal data.\n"
        "- Produce a report that is useful to defenders and suitable to send through Telegram.\n"
    )


JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _result_success(result) -> bool:
    return bool(getattr(result, "success", False))


def _result_content(result) -> str:
    return str(getattr(result, "content", "") or "")


def _parse_openclaw_json(content: str) -> dict:
    if not content:
        return {"raw_content": ""}
    text = content.strip()
    for candidate in (text,):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            pass
    match = JSON_BLOCK_RE.search(text)
    if match:
        try:
            parsed = json.loads(match.group(1).strip())
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            pass
    first_obj = text.find("{")
    last_obj = text.rfind("}")
    if first_obj != -1 and last_obj > first_obj:
        snippet = text[first_obj:last_obj + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            pass
    return {"raw_content": text}


def _default_findings_from_payload(payload: dict, source: str) -> list[dict]:
    findings = payload.get("findings", [])
    normalized: list[dict] = []
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        item.setdefault("_source_skill", source)
        item.setdefault("severity", "Info")
        item.setdefault("title", "Untitled finding")
        item.setdefault("url", "")
        item.setdefault("category", "Assessment")
        item.setdefault("evidence", "See specialist output.")
        item.setdefault("impact", "Requires analyst review.")
        item.setdefault("remediation", "Review and harden the affected surface.")
        normalized.append(item)
    return normalized


def _collect_scan_gaps(payloads: list[dict]) -> list[str]:
    gaps: list[str] = []
    for payload in payloads:
        for gap in payload.get("scan_gaps", []) if isinstance(payload.get("scan_gaps"), list) else []:
            text = str(gap).strip()
            if text and text not in gaps:
                gaps.append(text)
    return gaps[:12]


def _stage_confidence(payload: dict) -> float:
    if not payload:
        return 0.15
    confidence = 0.35
    if payload.get("summary"):
        confidence += 0.1
    findings = payload.get("findings", [])
    if isinstance(findings, list):
        confidence += min(0.25, len(findings) * 0.03)
    if payload.get("raw_content"):
        confidence -= 0.1
    if payload.get("fallback_used"):
        confidence -= 0.08
    if payload.get("stage_error"):
        confidence -= 0.12
    if payload.get("recommended_focus") or payload.get("priority_fixes"):
        confidence += 0.08
    return max(0.1, min(0.95, confidence))


def _weighted_findings(payloads: dict[str, dict]) -> list[dict]:
    severity_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    merged: dict[tuple[str, str, str], dict] = {}
    for stage_name, payload in payloads.items():
        confidence = _stage_confidence(payload)
        for finding in _default_findings_from_payload(payload, stage_name):
            key = (
                str(finding.get("title", "")).strip(),
                str(finding.get("url", "")).strip(),
                str(finding.get("category", "")).strip(),
            )
            entry = merged.setdefault(key, {
                **finding,
                "_supporting_stages": [],
                "_weighted_score": 0.0,
            })
            entry["_supporting_stages"].append({"stage": stage_name, "confidence": round(confidence, 2)})
            entry["_weighted_score"] += severity_weight.get(str(finding.get("severity", "Info")), 0) * confidence
    ranked = sorted(
        merged.values(),
        key=lambda item: (-item["_weighted_score"], item.get("title", "")),
    )
    return ranked


def _synthesize_attack_paths(weighted_findings: list[dict]) -> list[dict]:
    hay = "\n".join(
        " ".join(str(item.get(k, "")).lower() for k in ("title", "category", "evidence", "impact"))
        for item in weighted_findings
    )
    paths: list[dict] = []
    if any(k in hay for k in ("admin", "management", "console", "dashboard")):
        paths.append({
            "name": "Operational surface to privileged workflow",
            "likelihood": "High",
            "rationale": "Admin or management exposure appears in the evidence set.",
        })
    if any(k in hay for k in ("debug", "observability", "swagger", "openapi", "export", "backup", "storage")):
        paths.append({
            "name": "Operational disclosure to data-bearing surface",
            "likelihood": "High",
            "rationale": "Debug, documentation, export, or storage exposure appears in the evidence set.",
        })
    if any(k in hay for k in ("login", "jwt", "session", "auth", "api", "idor", "mass assignment")):
        paths.append({
            "name": "Identity or API weakness to sensitive operation",
            "likelihood": "Medium to High",
            "rationale": "Authentication or API control weakness appears in the evidence set.",
        })
    if not paths:
        paths.append({
            "name": "Surface expansion and reconnaissance-driven targeting",
            "likelihood": "Medium",
            "rationale": "The current evidence mostly supports mapping and follow-on targeting rather than a single dominant chain.",
        })
    return paths[:5]


def _build_report_from_payload(target: str, correlation_payload: dict) -> str:
    findings = _default_findings_from_payload(correlation_payload, "correlation")
    lines = [
        f"VERDICT: {correlation_payload.get('verdict', 'Assessment completed with partial evidence.')}",
        "",
        "TOP FINDINGS:",
    ]
    if findings:
        for idx, finding in enumerate(findings[:8], 1):
            lines.append(
                f"{idx}. [{finding.get('severity', 'Info')}] {finding.get('title', 'Untitled')} | "
                f"{finding.get('url', 'n/a')} | {finding.get('impact', 'Requires review.')}"
            )
    else:
        lines.append("No structured findings were produced.")
    attack_paths = correlation_payload.get("attack_paths", [])
    if attack_paths:
        lines.extend(["", "LIKELY ATTACK PATHS:"])
        for path in attack_paths[:5]:
            if isinstance(path, dict):
                lines.append(
                    f"- {path.get('name', 'Unnamed path')} ({path.get('likelihood', 'Unknown')}): "
                    f"{path.get('rationale', path.get('impact', 'No rationale provided.'))}"
                )
    fixes = correlation_payload.get("priority_fixes", [])
    if fixes:
        lines.extend(["", "PRIORITY FIXES:"])
        for fix in fixes[:6]:
            lines.append(f"- {fix}")
    gaps = correlation_payload.get("scan_gaps", [])
    if gaps:
        lines.extend(["", "SCAN GAPS:"])
        for gap in gaps[:6]:
            lines.append(f"- {gap}")
    return "\n".join(lines).strip()


def _synthesize_correlation_payload(stage_payloads: dict[str, dict]) -> dict:
    weighted_findings = _weighted_findings(stage_payloads)
    avg_confidence = sum(_stage_confidence(payload) for payload in stage_payloads.values()) / max(1, len(stage_payloads))
    readiness_score = max(20.0, min(95.0, 92.0 - (len(weighted_findings[:8]) * 2.5) - ((1 - avg_confidence) * 20.0)))
    priority_fixes = []
    for finding in weighted_findings[:6]:
        remediation = str(finding.get("remediation", "")).strip()
        if remediation and remediation not in priority_fixes:
            priority_fixes.append(remediation)
    scan_gaps = _collect_scan_gaps(list(stage_payloads.values()))
    verdict = (
        "High-priority exposure themes were identified and correlated across multiple specialist stages."
        if weighted_findings
        else "The assessment completed, but structured evidence remains limited and should be verified."
    )
    return {
        "verdict": verdict,
        "ranked_findings": [
            {
                "title": item.get("title"),
                "severity": item.get("severity"),
                "url": item.get("url"),
                "category": item.get("category"),
                "weighted_score": round(item.get("_weighted_score", 0.0), 2),
                "supporting_stages": item.get("_supporting_stages", []),
            }
            for item in weighted_findings[:10]
        ],
        "attack_paths": _synthesize_attack_paths(weighted_findings),
        "readiness_score": round(readiness_score, 1),
        "scan_gaps": scan_gaps,
        "priority_fixes": priority_fixes[:6],
        "findings": weighted_findings[:12],
        "stage_confidence": {
            stage_name: round(_stage_confidence(payload), 2)
            for stage_name, payload in stage_payloads.items()
        },
        "synthesized": True,
    }


def _fallback_stage_payload(agent_role: str, direct_results: dict[str, dict], reason: str) -> dict:
    findings = aggregate_findings(direct_results)
    payload = {
        "summary": f"{agent_role} fallback generated from direct skill execution.",
        "findings": findings,
        "scan_gaps": [reason],
        "fallback_used": True,
        "stage_error": reason,
    }
    if agent_role in {"surface_mapper", "exposure_analyst"}:
        payload["high_value_surfaces"] = aggregate_company_surfaces(direct_results)
    if agent_role == "surface_mapper":
        payload["recommended_focus"] = ["admin and operational surfaces", "identity and API exposure", "high-value company assets"]
    if agent_role == "exposure_analyst":
        payload["exposed_surfaces"] = aggregate_company_surfaces(direct_results)
    if agent_role == "auth_api_analyst":
        payload["likely_chains"] = ["identity or API weakness to sensitive operation"]
    return payload


def _run_direct_subset(
    skills_to_run: list[str],
    domain: str,
    target_url: str,
    *,
    scan_type: str = "full",
) -> dict[str, dict]:
    """Run a subset of skills in parallel with per-skill hard timeout; cancel on overrun."""
    if not skills_to_run:
        return {}
    sc = "quick" if scan_type == "quick" else "full"
    st = skill_timeout_seconds_for_scope(sc)
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_to_run))) as pool:
        future_to_skill = {
            pool.submit(
                run_skill,
                skill_name,
                domain,
                target_url,
                None,
                scan_type=scan_type,
                scan_scope=sc,
            ): skill_name
            for skill_name in skills_to_run
        }
        for future in concurrent.futures.as_completed(future_to_skill):
            skill_name = future_to_skill[future]
            try:
                results[skill_name] = future.result(timeout=st)
            except concurrent.futures.TimeoutError:
                future.cancel()
                results[skill_name] = {
                    "error": f"Skill timed out after {st}s",
                    "skill": skill_name,
                }
            except Exception as exc:
                results[skill_name] = {"error": str(exc), "skill": skill_name}
    return results


async def _run_agent_stage(agent, agent_name: str, prompt: str) -> tuple[bool, dict, str]:
    timeout = OPENCLAW_AGENT_TIMEOUTS.get(agent_name, 90)
    last_error = "Unknown error"
    for attempt in range(1, OPENCLAW_AGENT_RETRIES + 2):
        try:
            result = await asyncio.wait_for(agent.execute(prompt), timeout=timeout)
            content = _result_content(result)
            if _result_success(result):
                payload = _parse_openclaw_json(content)
                payload.setdefault("_meta", {})
                payload["_meta"].update({
                    "agent": agent_name,
                    "attempt": attempt,
                    "timeout_sec": timeout,
                })
                return True, payload, content
            last_error = f"agent returned unsuccessful result on attempt {attempt}"
        except asyncio.TimeoutError:
            last_error = f"timed out after {timeout}s on attempt {attempt}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    return False, {"stage_error": last_error, "scan_gaps": [last_error]}, ""


def _save_openclaw_report(target: str, scope: str, report_type: str, manifest: dict, stages: dict, final_payload: dict) -> Path:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = Path(__file__).parent / "reports"
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / f"openclaw_{domain}_{timestamp}.json"
    report = {
        "target": target,
        "scope": scope,
        "report_type": report_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manifest": manifest,
        "stages": stages,
        "final": final_payload,
    }
    report_path.write_text(json.dumps(report, indent=2, default=str))
    return report_path


def _specialist_prompt(agent_role: str, target: str, manifest: dict, handoff: dict | None = None, routing: dict | None = None) -> str:
    common = (
        f"Authorized assessment target: {target}\n"
        f"Engagement manifest:\n{json.dumps(manifest, indent=2)}\n\n"
        "Return STRICT JSON only. No markdown. No prose outside JSON.\n"
        "Never include raw secrets, credentials, tokens, or personal data.\n"
        "Every finding must be evidence-backed and sanitized.\n"
    )
    routing = routing or {}
    if agent_role == "surface_mapper":
        return common + (
            "Role: surface mapping specialist.\n"
            "Use recon, osint, headers_ssl, and company_exposure to build the best possible map of the target.\n"
            "Output JSON keys: summary, target_profiles, high_value_surfaces, platform_signals, findings, recommended_focus, scan_gaps.\n"
        )
    if agent_role == "exposure_analyst":
        focus = ", ".join(routing.get("focus_areas", [])) or "admin, debug, docs, exports, storage, support, staging"
        return common + (
            f"Prior handoff:\n{json.dumps(handoff or {}, indent=2)}\n\n"
            "Role: company exposure specialist.\n"
            f"Focus areas for this run: {focus}.\n"
            "Prioritize admin, debug, docs, exports, storage, support, staging, and enterprise platform exposure.\n"
            "Output JSON keys: summary, findings, exposed_platforms, exposed_surfaces, recommended_followups, scan_gaps.\n"
        )
    if agent_role == "auth_api_analyst":
        api_depth = routing.get("api_depth", "full")
        app_depth = routing.get("application_depth", "full")
        return common + (
            f"Prior handoff:\n{json.dumps(handoff or {}, indent=2)}\n\n"
            "Role: authentication, application, and API specialist.\n"
            f"API depth: {api_depth}. Application depth: {app_depth}. "
            "If depth is 'light', perform targeted checks only; if 'full', run comprehensive auth and API tests.\n"
            "Prioritize identity/auth weaknesses, API exposure, business logic risk, and routes to privileged data.\n"
            "Output JSON keys: summary, findings, auth_risks, api_risks, likely_chains, scan_gaps.\n"
        )
    if agent_role == "correlation_engine":
        return common + (
            f"Specialist outputs:\n{json.dumps(handoff or {}, indent=2)}\n\n"
            "Role: correlation and prioritization engine.\n"
            "Merge duplicate themes, rank by company impact, and produce likely defensive attack paths.\n"
            "Output JSON keys: verdict, ranked_findings, attack_paths, readiness_score, scan_gaps, priority_fixes, findings.\n"
        )
    if agent_role == "report_composer":
        return common + (
            f"Correlation output:\n{json.dumps(handoff or {}, indent=2)}\n\n"
            "Role: final report composer.\n"
            "Produce a plain-text client-facing report that is simple, detailed, and defensive. Also output a structured findings array suitable for Telegram reporting.\n"
            "Output JSON keys: final_report, findings, executive_summary, operator_notes.\n"
        )
    return common


def print_summary(findings: list[dict], target: str) -> None:
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {target}")
    print(f"{'='*60}")
    print(f"  Total findings: {len(findings)}")
    print()
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        indicator = {"Critical": "!!!", "High": "!! ", "Medium": "!  ", "Low": ".  ", "Info": "   "}
        count = severity_counts[sev]
        if count > 0:
            print(f"  {indicator[sev]} {sev}: {count}")
    print()

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    actionable = [f for f in findings if f.get("severity") in ("Critical", "High", "Medium")]
    actionable.sort(key=lambda f: severity_order.get(f.get("severity", "Info"), 99))

    if actionable:
        print(f"  Top actionable findings:")
        print(f"  {'-'*56}")
        for i, f in enumerate(actionable[:15], 1):
            print(f"  {i:2}. [{f['severity']:>8}] {f.get('title', 'Untitled')}")
            if f.get("url"):
                print(f"               {f['url']}")
    print(f"\n{'='*60}\n")


# ---------------------------------------------------------------------------
# Telegram reporting
# ---------------------------------------------------------------------------

def send_telegram_report(findings: list[dict], target: str, report_type: str) -> None:
    try:
        import telegram_report
        findings_json = json.dumps(findings)
        result = telegram_report.run(findings_json, target, report_type)
        parsed = json.loads(result)
        if parsed.get("success"):
            print(f"  Telegram: {parsed.get('messages_sent', 0)} messages sent successfully")
        else:
            print(f"  Telegram: Failed — {parsed.get('errors', [])}")
    except Exception as exc:
        print(f"  Telegram: Error — {exc}")


# ---------------------------------------------------------------------------
# OpenClaw SDK integration (optional)
# ---------------------------------------------------------------------------

async def run_via_openclaw(target: str, scope: str, report_type: str) -> None:
    """Use the OpenClaw SDK to execute the scan via an agent session."""
    try:
        from openclaw_sdk import OpenClawClient

        async with OpenClawClient.connect() as client:
            manifest = build_openclaw_manifest(target, scope, report_type)
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            target_url = target if target.startswith("http") else f"https://{target}"
            agent_names = [
                "surface_mapper",
                "exposure_analyst",
                "auth_api_analyst",
                "correlation_engine",
                "report_composer",
            ]
            agents = {name: client.get_agent(name) for name in agent_names}
            stage_outputs: dict[str, dict] = {}
            stage_raw_content: dict[str, str] = {}

            print("  Multi-agent engagement starting...")
            mapper_ok, mapper_payload, mapper_content = await _run_agent_stage(
                agents["surface_mapper"],
                "surface_mapper",
                _specialist_prompt("surface_mapper", target, manifest)
            )
            if not mapper_ok:
                print("  surface_mapper failed. Backfilling with direct surface execution.")
                mapper_payload = _fallback_stage_payload(
                    "surface_mapper",
                    _run_direct_subset(AGENT_DIRECT_FALLBACKS["surface_mapper"], domain, target_url),
                    mapper_payload.get("stage_error", "surface_mapper failed"),
                )
            stage_outputs["surface_mapper"] = mapper_payload
            stage_raw_content["surface_mapper"] = mapper_content

            routing = infer_dynamic_routing(mapper_payload, None)
            print(f"  Dynamic routing: api_depth={routing.get('api_depth')}, application_depth={routing.get('application_depth')}")

            exposure_task = _run_agent_stage(
                agents["exposure_analyst"],
                "exposure_analyst",
                _specialist_prompt("exposure_analyst", target, manifest, mapper_payload, routing)
            )
            if routing.get("run_auth_api", True):
                auth_api_task = _run_agent_stage(
                    agents["auth_api_analyst"],
                    "auth_api_analyst",
                    _specialist_prompt("auth_api_analyst", target, manifest, mapper_payload, routing)
                )
                (exposure_ok, exposure_payload, exposure_content), (auth_ok, auth_api_payload, auth_content) = await asyncio.gather(exposure_task, auth_api_task)
            else:
                (exposure_ok, exposure_payload, exposure_content) = await exposure_task
                auth_ok, auth_api_payload, auth_content = False, {
                    "summary": "Auth/API stage skipped by dynamic routing (no API or application surface detected).",
                    "findings": [],
                    "scan_gaps": ["Auth and API checks were not run; surface did not indicate API or app surface."],
                    "fallback_used": True,
                    "skipped_by_routing": True,
                }, ""
            if not exposure_ok:
                print("  exposure_analyst failed. Backfilling with direct exposure execution.")
                exposure_payload = _fallback_stage_payload(
                    "exposure_analyst",
                    _run_direct_subset(AGENT_DIRECT_FALLBACKS["exposure_analyst"], domain, target_url),
                    exposure_payload.get("stage_error", "exposure_analyst failed"),
                )
            if not auth_ok and not auth_api_payload.get("skipped_by_routing"):
                print("  auth_api_analyst failed. Backfilling with direct auth/API execution.")
                auth_api_payload = _fallback_stage_payload(
                    "auth_api_analyst",
                    _run_direct_subset(AGENT_DIRECT_FALLBACKS["auth_api_analyst"], domain, target_url),
                    auth_api_payload.get("stage_error", "auth_api_analyst failed"),
                )
            stage_outputs["exposure_analyst"] = exposure_payload
            stage_outputs["auth_api_analyst"] = auth_api_payload
            stage_raw_content["exposure_analyst"] = exposure_content
            stage_raw_content["auth_api_analyst"] = auth_content

            correlation_input = {
                "surface_mapper": mapper_payload,
                "exposure_analyst": exposure_payload,
                "auth_api_analyst": auth_api_payload,
            }
            correlation_ok, correlation_payload, correlation_content = await _run_agent_stage(
                agents["correlation_engine"],
                "correlation_engine",
                _specialist_prompt("correlation_engine", target, manifest, correlation_input)
            )
            if not correlation_ok:
                print("  correlation_engine failed. Synthesizing correlation from specialist outputs.")
                correlation_payload = _synthesize_correlation_payload(correlation_input)
            stage_outputs["correlation_engine"] = correlation_payload
            stage_raw_content["correlation_engine"] = correlation_content

            reporter_ok, reporter_payload, reporter_content = await _run_agent_stage(
                agents["report_composer"],
                "report_composer",
                _specialist_prompt("report_composer", target, manifest, correlation_payload)
            )
            if not reporter_ok:
                print("  report_composer failed. Building report from correlation payload.")
                reporter_payload = {
                    "final_report": _build_report_from_payload(target, correlation_payload),
                    "findings": correlation_payload.get("findings", []),
                    "executive_summary": correlation_payload.get("verdict", "Assessment completed with synthesized reporting."),
                    "operator_notes": ["Reporter fallback was used."],
                    "fallback_used": True,
                    "scan_gaps": _collect_scan_gaps(list(stage_outputs.values())),
                }
            stage_outputs["report_composer"] = reporter_payload
            stage_raw_content["report_composer"] = reporter_content

            final_report = reporter_payload.get("final_report") or reporter_content
            telegram_findings = _default_findings_from_payload(reporter_payload, "openclaw_reporter")
            if not telegram_findings:
                telegram_findings = _default_findings_from_payload(correlation_payload, "openclaw_correlation")

            print("  Multi-agent engagement completed successfully.")
            print(f"  Final report:\n{final_report}")

            report_path = _save_openclaw_report(
                target,
                scope,
                report_type,
                manifest,
                {
                    name: {
                        **payload,
                        "_runtime": {
                            "confidence": round(_stage_confidence(payload), 2),
                            "had_raw_content": bool(stage_raw_content.get(name)),
                        },
                    }
                    for name, payload in stage_outputs.items()
                },
                reporter_payload,
            )
            print(f"  Report saved: {report_path}")

            if telegram_findings:
                send_telegram_report(telegram_findings, target, report_type)
            else:
                print("  Telegram: No structured findings from reporter")

    except ImportError:
        print("  openclaw-sdk not installed. Running skills directly.")
        run_direct(target, scope, report_type)
    except Exception as exc:
        print(f"  Multi-agent connection failed ({exc}). Falling back to direct execution.")
        run_direct(target, scope, report_type)


# ---------------------------------------------------------------------------
# Direct execution (no OpenClaw dependency)
# ---------------------------------------------------------------------------

# Web-only profile for API/extension: full web scan, no blockchain.
# Phase 1: all skills that do not need context from other skills.
# Phase 2: dependency_audit, logic_abuse, entity_reputation (run with context from phase 1).
WEB_SCAN_PHASE1 = [
    "osint", "recon", "headers_ssl", "crypto_security", "data_leak_risks",
    "company_exposure", "web_vulns", "auth_test", "api_test", "high_value_flaws",
    "workflow_probe", "race_condition", "payment_financial", "client_surface",
]
WEB_SCAN_PHASE2 = ["dependency_audit", "logic_abuse", "entity_reputation"]
WEB_SCAN_PROFILE = WEB_SCAN_PHASE1 + WEB_SCAN_PHASE2

# Phase 3 (attack-style probing): targeted scan_type passes for high-signal checks.
# This is opt-in via scope="attack" for the API/extension so default scans stay fast.
WEB_SCAN_PHASE3: list[tuple[str, str, str]] = [
    # Web vulns: include full pass with deeper crawl (runner sets crawl_depth=3)
    ("web_vulns", "full", "medium"),
    ("web_vulns", "files", "medium"),

    # API probing: expand into the heavier/higher-signal passes
    ("api_test", "info_disclosure", "medium"),
    ("api_test", "auth_bypass", "small"),
    ("api_test", "cors", "small"),
    ("api_test", "host_header", "small"),
    ("api_test", "rate_limit", "small"),
    ("api_test", "param_fuzz", "medium"),
    ("api_test", "mass_assign", "medium"),
    ("api_test", "contract_drift", "small"),

    # Auth probing (targeted submodules; full scan already runs auth_test:full)
    ("auth_test", "enumeration", "medium"),
    ("auth_test", "jwt", "medium"),

    # Company surface: prioritize high-value operational buckets
    ("company_exposure", "business", "medium"),
    ("company_exposure", "debug", "medium"),
    ("company_exposure", "docs", "medium"),
    ("company_exposure", "staging", "medium"),
    ("company_exposure", "support", "medium"),
    ("company_exposure", "admin", "medium"),
    ("company_exposure", "identity", "medium"),
    ("company_exposure", "observability", "medium"),
]


def _is_crypto_site(target_url: str) -> bool:
    """Quick crypto/DeFi detection so we can add chain_validation_abuse when relevant."""
    try:
        import crypto_site_detector
        result = crypto_site_detector.detect_from_url(target_url, fetch=True)
        return result.is_crypto and result.confidence >= 0.2
    except Exception:
        return False


def _get_crypto_detection(target_url: str) -> dict:
    """Return crypto detection result for API/report. Keys: is_crypto, confidence, signals (optional)."""
    try:
        import crypto_site_detector
        result = crypto_site_detector.detect_from_url(target_url, fetch=True)
        return {
            "is_crypto": result.is_crypto,
            "confidence": result.confidence,
            "signals": getattr(result, "signals", [])[:12],
        }
    except Exception:
        return {"is_crypto": False, "confidence": 0.0, "signals": []}


def run_web_scan(
    target: str,
    scope: str = "full",
    goal: str | None = None,
    auth_context: dict | None = None,
) -> dict:
    """
    Run full web-only scan (no blockchain) and return aggregated result for API/extension.
    If goal is provided, run only skills matching the natural-language goal (see intent_skills).
    Otherwise runs phase 1 then phase 2. When target is detected as crypto/DeFi, chain_validation_abuse is added automatically.
    Returns dict with target_url, findings, summary, scanned_at, skills_run.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    target_url = target if target.startswith("http") else f"https://{target}"
    skill_st = skill_scan_type_for_scope(scope)

    needs_crypto = scope in ("full", "crypto")
    site_classification = _get_crypto_detection(target_url) if needs_crypto else {"is_crypto": False, "confidence": 0.0, "signals": []}
    chain_validation_abuse_reason: str | None = None

    if goal and str(goal).strip():
        from intent_skills import resolve_goal
        requested = resolve_goal(goal)
        skills_phase1 = [s for s in WEB_SCAN_PHASE1 if s in requested]
        skills_phase2 = [s for s in WEB_SCAN_PHASE2 if s in requested]
        skills_phase3: list[tuple[str, str, str]] = []
        if "chain_validation_abuse" in requested and "chain_validation_abuse" not in skills_phase2:
            skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "goal"
    else:
        if scope == "attack":
            # Attack profile = full Phase 1 + Phase 2 context skills + Phase 3 probe passes.
            skills_phase1 = WEB_SCAN_PHASE1
            skills_phase2 = WEB_SCAN_PHASE2
            skills_phase3 = WEB_SCAN_PHASE3
        else:
            skills_phase1 = WEB_SCAN_PHASE1 if scope == "full" else SCAN_PROFILES.get(scope, SCAN_PROFILES["full"])
            skills_phase2 = WEB_SCAN_PHASE2 if scope == "full" else []
            skills_phase3 = []
        if scope == "crypto":
            if "chain_validation_abuse" not in skills_phase2:
                skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "scope_crypto"
        elif scope == "full" and (site_classification.get("is_crypto") and site_classification.get("confidence", 0) >= 0.2):
            if "chain_validation_abuse" not in skills_phase2:
                skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "auto_crypto"

    results: dict[str, dict] = {}
    auth_context = _normalize_auth_context(auth_context)
    skill_to = skill_timeout_seconds_for_scope(scope)
    t_scan0 = time.monotonic()

    # Phase 1a: skills that do not need peer context (api_test runs after client_surface — see 1b)
    skills_phase1_early = [s for s in skills_phase1 if s != "api_test"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, max(len(skills_phase1_early), 1))) as pool:
        future_to_skill = {
            pool.submit(
                run_skill,
                skill_name,
                domain,
                target_url,
                None,
                scan_type=skill_st,
                scan_scope=scope,
                auth_context=auth_context,
            ): skill_name
            for skill_name in skills_phase1_early
        }
        for future in concurrent.futures.as_completed(future_to_skill):
            skill_name = future_to_skill[future]
            try:
                results[skill_name] = future.result(timeout=skill_to)
            except concurrent.futures.TimeoutError:
                future.cancel()
                results[skill_name] = {
                    "error": f"Skill timed out after {skill_to}s",
                    "skill": skill_name,
                }
            except Exception as exc:
                results[skill_name] = {"error": str(exc), "skill": skill_name}

    # Phase 1b: api_test uses client_surface extracted_endpoints when available
    if "api_test" in skills_phase1:
        ctx_api: dict[str, str | None] = {}
        cs = results.get("client_surface")
        if cs and isinstance(cs, dict) and "error" not in cs:
            ctx_api["client_surface_json"] = json.dumps(cs)
        try:
            results["api_test"] = run_skill(
                "api_test",
                domain,
                target_url,
                ctx_api if ctx_api else None,
                scan_type=skill_st,
                scan_scope=scope,
                auth_context=auth_context,
            )
        except Exception as exc:
            results["api_test"] = {"error": str(exc), "skill": "api_test"}

    # Phase 2: run context-dependent skills with context from phase 1
    if skills_phase2:
        ctx = {
            "client_surface_json": json.dumps(results["client_surface"]) if results.get("client_surface") and "error" not in results.get("client_surface", {}) else None,
            "recon_json": json.dumps(results["recon"]) if results.get("recon") and "error" not in results.get("recon", {}) else None,
            "osint_json": json.dumps(results["osint"]) if results.get("osint") and "error" not in results.get("osint", {}) else None,
            "api_results_json": json.dumps(results["api_test"]) if results.get("api_test") and "error" not in results.get("api_test", {}) else None,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_phase2))) as pool:
            future_to_skill = {
                pool.submit(
                    run_skill,
                    skill_name,
                    domain,
                    target_url,
                    ctx,
                    scan_type=skill_st,
                    scan_scope=scope,
                    auth_context=auth_context,
                ): skill_name
                for skill_name in skills_phase2
            }
            for future in concurrent.futures.as_completed(future_to_skill):
                skill_name = future_to_skill[future]
                try:
                    results[skill_name] = future.result(timeout=skill_to)
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    results[skill_name] = {
                        "error": f"Skill timed out after {skill_to}s",
                        "skill": skill_name,
                    }
                except Exception as exc:
                    results[skill_name] = {"error": str(exc), "skill": skill_name}

    # Phase 3: vulnerability probing (opt-in via scope="attack")
    if skills_phase3:
        ctx3 = {
            "client_surface_json": json.dumps(results["client_surface"]) if results.get("client_surface") and "error" not in results.get("client_surface", {}) else None,
            "recon_json": json.dumps(results["recon"]) if results.get("recon") and "error" not in results.get("recon", {}) else None,
            "osint_json": json.dumps(results["osint"]) if results.get("osint") and "error" not in results.get("osint", {}) else None,
            "api_results_json": json.dumps(results["api_test"]) if results.get("api_test") and "error" not in results.get("api_test", {}) else None,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_phase3))) as pool:
            future_to_task = {
                pool.submit(
                    run_skill_variant,
                    skill,
                    domain if skill in {"recon", "osint", "entity_reputation"} else domain,
                    target_url,
                    scan_type=stype,
                    wordlist=wl,
                    crawl_depth=3 if (skill == "web_vulns" and stype == "full") else 2,
                    context=ctx3,
                    scan_scope=scope,
                    auth_context=auth_context,
                ): f"{skill}:{stype}:{wl}"
                for (skill, stype, wl) in skills_phase3
            }
            for future in concurrent.futures.as_completed(future_to_task):
                key = future_to_task[future]
                try:
                    results[key] = future.result(timeout=skill_to)
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    results[key] = {"error": f"Skill timed out after {skill_to}s", "skill": key}
                except Exception as exc:
                    results[key] = {"error": str(exc), "skill": key}

    findings = aggregate_findings(results)
    company_surfaces = aggregate_company_surfaces(results)
    timestamp = datetime.now(timezone.utc).isoformat()
    evidence_summary = build_evidence_summary(findings)
    phase4 = run_phase4_synthesis(target_url, results, findings)

    summary_block = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
        "high": sum(1 for f in findings if f.get("severity") == "High"),
        "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
        "low": sum(1 for f in findings if f.get("severity") == "Low"),
        "info": sum(1 for f in findings if f.get("severity") == "Info"),
    }
    scan_metrics = _compute_scan_metrics(results, {**summary_block, "total_findings": len(findings)}, time.monotonic() - t_scan0)

    scan_fp = _build_scan_fingerprint(target_url, list(results.keys()), timestamp)

    return {
        "target_url": target_url,
        "findings": findings,
        "company_surfaces": company_surfaces,
        "scanned_at": timestamp,
        "skills_run": list(results.keys()),
        "scan_metrics": scan_metrics,
        "auth_supplied": bool(auth_context),
        "site_classification": {
            **site_classification,
            "chain_validation_abuse_ran": "chain_validation_abuse" in results,
            "chain_validation_abuse_reason": chain_validation_abuse_reason,
        },
        "summary": summary_block,
        "evidence_summary": evidence_summary,
        "scan_fingerprint": scan_fp,
        **phase4,
    }


def _run_skill_phase(skill_name, domain, target_url, eq, ctx=None, *, scan_type: str = "full", scan_scope: str = "full", auth_context=None):
    """Run a single skill and put start/done events into the queue."""
    eq.put({"event": "skill_start", "skill": skill_name})
    try:
        out = run_skill(
            skill_name, domain, target_url, ctx, scan_type=scan_type,
            scan_scope=scan_scope, auth_context=auth_context,
        )
        cnt = len(out.get("findings", [])) + len(out.get("header_findings", [])) + len(out.get("ssl_findings", []))
        eq.put({"event": "skill_done", "skill": skill_name, "findings_count": cnt})
        return skill_name, out
    except Exception as exc:
        eq.put({"event": "skill_done", "skill": skill_name, "findings_count": 0, "error": str(exc)})
        return skill_name, {"error": str(exc), "skill": skill_name}


def _run_variant_phase(skill_name, stype, wl, domain, target_url, eq, ctx=None, *, scan_scope: str = "full", auth_context=None):
    """Run a skill variant and put start/done events into the queue."""
    label = f"{skill_name}:{stype}"
    eq.put({"event": "skill_start", "skill": label})
    try:
        out = run_skill_variant(
            skill_name, domain, target_url,
            scan_type=stype, wordlist=wl,
            crawl_depth=3 if (skill_name == "web_vulns" and stype == "full") else 2,
            context=ctx,
            scan_scope=scan_scope,
            auth_context=auth_context,
        )
        cnt = len(out.get("findings", [])) + len(out.get("header_findings", [])) + len(out.get("ssl_findings", []))
        eq.put({"event": "skill_done", "skill": label, "findings_count": cnt})
        return f"{skill_name}:{stype}:{wl}", out
    except Exception as exc:
        eq.put({"event": "skill_done", "skill": label, "findings_count": 0, "error": str(exc)})
        return f"{skill_name}:{stype}:{wl}", {"error": str(exc), "skill": skill_name}


def run_web_scan_streaming(
    target: str,
    scope: str = "full",
    goal: str | None = None,
    auth_context: dict | None = None,
):
    """
    Generator that runs the same scan as run_web_scan but yields progress events (NDJSON).
    Skills within each phase run in PARALLEL for speed.
    Yields: skill_start, skill_done per skill, then done with full report.
    """
    import queue as _queue

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    target_url = target if target.startswith("http") else f"https://{target}"
    skill_st = skill_scan_type_for_scope(scope)

    needs_crypto = scope in ("full", "crypto")
    site_classification = _get_crypto_detection(target_url) if needs_crypto else {"is_crypto": False, "confidence": 0.0, "signals": []}
    chain_validation_abuse_reason: str | None = None

    if goal and str(goal).strip():
        from intent_skills import resolve_goal
        requested = resolve_goal(goal)
        skills_phase1 = [s for s in WEB_SCAN_PHASE1 if s in requested]
        skills_phase2 = [s for s in WEB_SCAN_PHASE2 if s in requested]
        skills_phase3: list[tuple[str, str, str]] = []
        if "chain_validation_abuse" in requested and "chain_validation_abuse" not in skills_phase2:
            skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "goal"
    else:
        if scope == "attack":
            skills_phase1 = WEB_SCAN_PHASE1
            skills_phase2 = WEB_SCAN_PHASE2
            skills_phase3 = WEB_SCAN_PHASE3
        else:
            skills_phase1 = WEB_SCAN_PHASE1 if scope == "full" else SCAN_PROFILES.get(scope, SCAN_PROFILES["full"])
            skills_phase2 = WEB_SCAN_PHASE2 if scope == "full" else []
            skills_phase3 = []
        if scope == "crypto":
            if "chain_validation_abuse" not in skills_phase2:
                skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "scope_crypto"
        elif scope == "full" and (site_classification.get("is_crypto") and site_classification.get("confidence", 0) >= 0.2):
            if "chain_validation_abuse" not in skills_phase2:
                skills_phase2 = list(skills_phase2) + ["chain_validation_abuse"]
            chain_validation_abuse_reason = "auto_crypto"

    results: dict[str, dict] = {}
    eq = _queue.Queue()
    auth_context = _normalize_auth_context(auth_context)
    skill_to = skill_timeout_seconds_for_scope(scope)
    t_scan0 = time.monotonic()

    def _drain_queue():
        while not eq.empty():
            try:
                yield eq.get_nowait()
            except _queue.Empty:
                break

    skills_phase1_early = [s for s in skills_phase1 if s != "api_test"]

    # Phase 1a: independent skills (excluding api_test — needs client_surface)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, max(len(skills_phase1_early), 1))) as pool:
        futures = {
            pool.submit(
                _run_skill_phase,
                s,
                domain,
                target_url,
                eq,
                None,
                scan_type=skill_st,
                scan_scope=scope,
                auth_context=auth_context,
            ): s
            for s in skills_phase1_early
        }
        while futures:
            done, _ = concurrent.futures.wait(futures, timeout=0.3, return_when=concurrent.futures.FIRST_COMPLETED)
            yield from _drain_queue()
            for f in done:
                skill_name = futures.pop(f)
                try:
                    name, out = f.result(timeout=skill_to)
                    results[name] = out
                except concurrent.futures.TimeoutError:
                    results[skill_name] = {
                        "error": f"Skill timed out after {skill_to}s",
                        "skill": skill_name,
                    }
                except Exception as exc:
                    results[skill_name] = {"error": str(exc), "skill": skill_name}
        yield from _drain_queue()

    # Phase 1b: api_test after client_surface is available
    if "api_test" in skills_phase1:
        ctx_api: dict[str, str | None] = {}
        cs = results.get("client_surface")
        if cs and isinstance(cs, dict) and "error" not in cs:
            ctx_api["client_surface_json"] = json.dumps(cs)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(
                _run_skill_phase,
                "api_test",
                domain,
                target_url,
                eq,
                ctx_api if ctx_api else None,
                scan_type=skill_st,
                scan_scope=scope,
                auth_context=auth_context,
            )
            yield from _drain_queue()
            try:
                name, out = fut.result(timeout=skill_to)
                results[name] = out
            except concurrent.futures.TimeoutError:
                results["api_test"] = {"error": f"Skill timed out after {skill_to}s", "skill": "api_test"}
            except Exception as exc:
                results["api_test"] = {"error": str(exc), "skill": "api_test"}
        yield from _drain_queue()

    # Phase 2: context-dependent skills (also parallel)
    if skills_phase2:
        ctx = {
            "client_surface_json": json.dumps(results["client_surface"]) if results.get("client_surface") and "error" not in results.get("client_surface", {}) else None,
            "recon_json": json.dumps(results["recon"]) if results.get("recon") and "error" not in results.get("recon", {}) else None,
            "osint_json": json.dumps(results["osint"]) if results.get("osint") and "error" not in results.get("osint", {}) else None,
            "api_results_json": json.dumps(results["api_test"]) if results.get("api_test") and "error" not in results.get("api_test", {}) else None,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, max(len(skills_phase2), 1))) as pool:
            futures = {
                pool.submit(
                    _run_skill_phase,
                    s,
                    domain,
                    target_url,
                    eq,
                    ctx,
                    scan_type=skill_st,
                    scan_scope=scope,
                    auth_context=auth_context,
                ): s
                for s in skills_phase2
            }
            while futures:
                done, _ = concurrent.futures.wait(futures, timeout=0.3, return_when=concurrent.futures.FIRST_COMPLETED)
                yield from _drain_queue()
                for f in done:
                    skill_name = futures.pop(f)
                    try:
                        name, out = f.result(timeout=skill_to)
                        results[name] = out
                    except concurrent.futures.TimeoutError:
                        results[skill_name] = {
                            "error": f"Skill timed out after {skill_to}s",
                            "skill": skill_name,
                        }
                    except Exception as exc:
                        results[skill_name] = {"error": str(exc), "skill": skill_name}
            yield from _drain_queue()

    # Phase 3: variant probes (also parallel)
    if skills_phase3:
        ctx3 = {
            "client_surface_json": json.dumps(results["client_surface"]) if results.get("client_surface") and "error" not in results.get("client_surface", {}) else None,
            "recon_json": json.dumps(results["recon"]) if results.get("recon") and "error" not in results.get("recon", {}) else None,
            "osint_json": json.dumps(results["osint"]) if results.get("osint") and "error" not in results.get("osint", {}) else None,
            "api_results_json": json.dumps(results["api_test"]) if results.get("api_test") and "error" not in results.get("api_test", {}) else None,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, max(len(skills_phase3), 1))) as pool:
            futures = {
                pool.submit(
                    _run_variant_phase,
                    skill,
                    stype,
                    wl,
                    domain,
                    target_url,
                    eq,
                    ctx3,
                    scan_scope=scope,
                    auth_context=auth_context,
                ): f"{skill}:{stype}:{wl}"
                for (skill, stype, wl) in skills_phase3
            }
            while futures:
                done, _ = concurrent.futures.wait(futures, timeout=0.3, return_when=concurrent.futures.FIRST_COMPLETED)
                yield from _drain_queue()
                for f in done:
                    key = futures.pop(f)
                    try:
                        name, out = f.result(timeout=skill_to)
                        results[name] = out
                    except concurrent.futures.TimeoutError:
                        results[key] = {
                            "error": f"Skill timed out after {skill_to}s",
                            "skill": key,
                        }
                    except Exception as exc:
                        results[key] = {"error": str(exc), "skill": key}
            yield from _drain_queue()

    findings = aggregate_findings(results)
    company_surfaces = aggregate_company_surfaces(results)
    timestamp = datetime.now(timezone.utc).isoformat()
    evidence_summary = build_evidence_summary(findings)
    phase4 = run_phase4_synthesis(target_url, results, findings)
    summary_block = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
        "high": sum(1 for f in findings if f.get("severity") == "High"),
        "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
        "low": sum(1 for f in findings if f.get("severity") == "Low"),
        "info": sum(1 for f in findings if f.get("severity") == "Info"),
    }
    scan_metrics = _compute_scan_metrics(
        results,
        {**summary_block, "total_findings": len(findings)},
        time.monotonic() - t_scan0,
    )
    report = {
        "target_url": target_url,
        "findings": findings,
        "company_surfaces": company_surfaces,
        "scanned_at": timestamp,
        "skills_run": list(results.keys()),
        "scan_metrics": scan_metrics,
        "auth_supplied": bool(auth_context),
        "site_classification": {
            **site_classification,
            "chain_validation_abuse_ran": "chain_validation_abuse" in results,
            "chain_validation_abuse_reason": chain_validation_abuse_reason,
        },
        "summary": summary_block,
        "evidence_summary": evidence_summary,
        **phase4,
    }
    yield {"event": "done", "report": report}


def run_direct(target: str, scope: str, report_type: str) -> None:
    skills_to_run = SCAN_PROFILES.get(scope, SCAN_PROFILES["full"])

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    target_url = target if target.startswith("http") else f"https://{target}"
    skill_st = skill_scan_type_for_scope(scope)

    print(f"  Engagement mode: {infer_engagement_mode(target, scope)}")
    print(f"  Priority tracks: {', '.join(infer_priority_tracks(target, scope))}")

    skill_to = skill_timeout_seconds_for_scope(scope)
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_to_run))) as pool:
        future_to_skill = {
            pool.submit(
                run_skill,
                skill_name,
                domain,
                target_url,
                None,
                scan_type=skill_st,
                scan_scope=scope,
            ): skill_name
            for skill_name in skills_to_run
        }
        for future in concurrent.futures.as_completed(future_to_skill):
            skill_name = future_to_skill[future]
            try:
                results[skill_name] = future.result(timeout=skill_to)
            except concurrent.futures.TimeoutError:
                future.cancel()
                results[skill_name] = {
                    "error": f"Skill timed out after {skill_to}s",
                    "skill": skill_name,
                }
            except Exception as exc:
                results[skill_name] = {"error": str(exc), "skill": skill_name}

    findings = aggregate_findings(results)
    company_surfaces = aggregate_company_surfaces(results)
    print_summary(findings, target)

    # Save raw results to JSON
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = Path(__file__).parent / "reports"
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / f"sectester_{domain}_{timestamp}.json"

    full_report = {
        "target": target,
        "scope": scope,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in findings if f.get("severity") == "High"),
            "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in findings if f.get("severity") == "Low"),
            "info": sum(1 for f in findings if f.get("severity") == "Info"),
            "company_surfaces": len(company_surfaces),
        },
        "findings": findings,
        "company_surfaces": company_surfaces,
        "openclaw_manifest": build_openclaw_manifest(target, scope, report_type),
        "raw_results": results,
    }

    report_path.write_text(json.dumps(full_report, indent=2, default=str))
    print(f"  Report saved: {report_path}")

    # Send to Telegram
    send_telegram_report(findings, target, report_type)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(description="SecTester — AI-Powered Security Testing Agent")
    parser.add_argument("--target", required=True, help="Target domain or URL to scan")
    parser.add_argument("--scope", default="full", choices=list(SCAN_PROFILES.keys()),
                        help="Scan scope/profile (default: full)")
    parser.add_argument("--report", default="summary", choices=["summary", "detailed", "alert"],
                        help="Telegram report format (default: summary)")
    parser.add_argument("--use-openclaw", action="store_true",
                        help="Use optional OpenClaw multi-agent session instead of running skills directly")

    args = parser.parse_args()

    print(f"  Target:  {args.target}")
    print(f"  Scope:   {args.scope}")
    print(f"  Profile: {', '.join(SCAN_PROFILES[args.scope])}")
    print(f"  Report:  {args.report}")

    if args.use_openclaw:
        asyncio.run(run_via_openclaw(args.target, args.scope, args.report))
    else:
        run_direct(args.target, args.scope, args.report)


if __name__ == "__main__":
    main()
