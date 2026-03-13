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
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"

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
    "full": ["osint", "recon", "headers_ssl", "crypto_security", "data_leak_risks", "company_exposure", "web_vulns", "auth_test", "api_test", "high_value_flaws", "race_condition", "payment_financial"],
    "quick": ["headers_ssl", "recon", "osint", "company_exposure"],
    "recon": ["osint", "recon"],
    "web": ["web_vulns", "headers_ssl", "auth_test", "company_exposure"],
    "api": ["api_test", "headers_ssl", "company_exposure"],
    "passive": ["osint", "headers_ssl", "company_exposure"],
}

SKILL_TIMEOUT_SECONDS = 90  # skills exit in ~58s; buffer to avoid timeouts
MAX_DIRECT_WORKERS = 4
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
    "payment_financial": "url",
    "crypto_security": "url",
    "data_leak_risks": "url",
    "web_vulns": "url",
    "auth_test": "url",
    "api_test": "url",
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
    "payment_financial": "zero/manipulated payment, payment and wallet IDOR, refund abuse — how users lose money",
    "crypto_security": "JWT alg:none/weak, weak TLS 1.0/1.1, weak crypto in frontend JS",
    "data_leak_risks": "verbose errors, cache misconfig, PII/token in responses and client-side — small leaks that become huge",
    "web_vulns": "web-layer flaw checks such as injection, traversal, SSRF, and file exposure",
    "auth_test": "login, identity, JWT, session, credential hygiene, and enumeration exposure",
    "api_test": "endpoint discovery, methods, auth gaps, schema exposure, and API abuse patterns",
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
    out["evidence"] = str(raw.get("evidence") or raw.get("detail") or raw.get("value") or raw.get("recommendation") or "").strip() or "See source output."
    out["impact"] = str(raw.get("impact", out["impact"])).strip()
    out["remediation"] = str(raw.get("remediation") or raw.get("recommendation") or out["remediation"]).strip()
    return out


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Merge duplicates by (title, url, category), keep highest severity and merged evidence."""
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
    return list(by_key.values())


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

def run_skill(skill_name: str, target: str, target_url: str) -> dict:
    """Import and execute a skill, returning its parsed JSON output."""
    print(f"\n{'='*60}")
    print(f"  Running: {skill_name}")
    print(f"  Target:  {target}")
    print(f"{'='*60}")

    try:
        if skill_name == "recon":
            import recon
            raw = recon.run(target, scan_type="full")
        elif skill_name == "web_vulns":
            import web_vulns
            raw = web_vulns.run(target_url, scan_type="full", crawl_depth=2)
        elif skill_name == "headers_ssl":
            import headers_ssl
            raw = headers_ssl.run(target_url, scan_type="full")
        elif skill_name == "company_exposure":
            import company_exposure
            raw = company_exposure.run(target_url, scan_type="full")
        elif skill_name == "high_value_flaws":
            import high_value_flaws
            raw = high_value_flaws.run(target_url, scan_type="full")
        elif skill_name == "race_condition":
            import race_condition
            raw = race_condition.run(target_url, scan_type="full")
        elif skill_name == "payment_financial":
            import payment_financial
            raw = payment_financial.run(target_url, scan_type="full")
        elif skill_name == "crypto_security":
            import crypto_security
            raw = crypto_security.run(target_url, scan_type="full")
        elif skill_name == "data_leak_risks":
            import data_leak_risks
            raw = data_leak_risks.run(target_url, scan_type="full")
        elif skill_name == "auth_test":
            import auth_test
            raw = auth_test.run(target_url, scan_type="full")
        elif skill_name == "api_test":
            import api_test
            raw = api_test.run(target_url, scan_type="full", wordlist="medium")
        elif skill_name == "osint":
            import osint
            raw = osint.run(target, scan_type="full")
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


# ---------------------------------------------------------------------------
# Report aggregation
# ---------------------------------------------------------------------------

def aggregate_findings(results: dict[str, dict]) -> list[dict]:
    """Collect all findings from every skill into a single flat list; normalize to canonical schema and dedupe."""
    all_findings: list[dict] = []

    for skill_name, result in results.items():
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
                all_findings.append(normalize_finding({
                    "title": f"Unauthenticated endpoint: {ep['url']}",
                    "severity": "Low",
                    "url": ep["url"],
                    "category": "API Discovery",
                    "evidence": f"Status: {ep['status_code']}, Methods: {', '.join(ep.get('methods', []))}",
                    "impact": "Publicly accessible endpoints may leak information.",
                    "remediation": "Review if this endpoint should require authentication.",
                }, skill_name, "findings"))

    return dedupe_findings(all_findings)


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


def _run_direct_subset(skills_to_run: list[str], domain: str, target_url: str) -> dict[str, dict]:
    """Run a subset of skills in parallel with per-skill hard timeout; cancel on overrun."""
    if not skills_to_run:
        return {}
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_to_run))) as pool:
        future_to_skill = {
            pool.submit(run_skill, skill_name, domain, target_url): skill_name
            for skill_name in skills_to_run
        }
        for future in concurrent.futures.as_completed(future_to_skill):
            skill_name = future_to_skill[future]
            try:
                results[skill_name] = future.result(timeout=SKILL_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                future.cancel()
                results[skill_name] = {
                    "error": f"Skill timed out after {SKILL_TIMEOUT_SECONDS}s",
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

def run_direct(target: str, scope: str, report_type: str) -> None:
    skills_to_run = SCAN_PROFILES.get(scope, SCAN_PROFILES["full"])

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    target_url = target if target.startswith("http") else f"https://{target}"

    print(f"  Engagement mode: {infer_engagement_mode(target, scope)}")
    print(f"  Priority tracks: {', '.join(infer_priority_tracks(target, scope))}")

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_DIRECT_WORKERS, len(skills_to_run))) as pool:
        future_to_skill = {
            pool.submit(run_skill, skill_name, domain, target_url): skill_name
            for skill_name in skills_to_run
        }
        for future in concurrent.futures.as_completed(future_to_skill):
            skill_name = future_to_skill[future]
            try:
                results[skill_name] = future.result(timeout=SKILL_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                future.cancel()
                results[skill_name] = {
                    "error": f"Skill timed out after {SKILL_TIMEOUT_SECONDS}s",
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
