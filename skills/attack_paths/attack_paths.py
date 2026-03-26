"""
Attack paths — Diverg-proprietary skill that turns raw findings into ranked
exploit chains. Others run checklists; we correlate across skills to show
how an attacker would chain issues to reach impact (data, money, internal).

Input: prior scan results (findings from run_full_attack or any skill run).
Output: ranked attack paths with steps, evidence refs, and exploitability score.

Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Finding roles for chaining (what an attacker uses this for)
ROLE_ENTRY = "entry"       # unauthenticated access, open redirect, XSS, info leak → get in or lure
ROLE_PRIVILEGE = "privilege"  # auth bypass, IDOR, JWT flaw, mass assignment → escalate or impersonate
ROLE_PIVOT = "pivot"       # SSRF, internal host disclosure, verbose errors → reach internal
ROLE_DATA = "data"         # sensitive file, PII leak, credential in JS → steal data
ROLE_FINANCIAL = "financial"  # payment bypass, zero amount, refund abuse → money impact

# Keywords per role (title + category + impact)
ENTRY_PATTERNS = [
    r"unauthenticated|no auth|without auth|publicly accessible|open redirect",
    r"XSS|cross-site|reflected|stored",
    r"information disclosure|info disclosure|verbose error|stack trace",
    r"directory listing|sensitive file|exposed.*file",
    r"CORS.*wildcard|CORS.*reflect",
]
PRIVILEGE_PATTERNS = [
    r"auth.*bypass|bypass.*auth|authentication bypass",
    r"IDOR|insecure direct object|other user.*data|another user",
    r"JWT|alg.*none|mass assignment|role.*admin|isAdmin",
    r"privilege|escalation|elevation",
]
PIVOT_PATTERNS = [
    r"SSRF|server-side request|internal.*host|169\.254|metadata",
    r"internal|verbose.*error|stack trace|path.*disclosure",
    r"redirect.*internal|proxy",
]
DATA_PATTERNS = [
    r"credential|secret|API key|token.*exposed|password.*leak",
    r"PII|personal data|sensitive.*response",
    r"database|dump|\.env|config.*exposed",
    r"source map|original source",
]
FINANCIAL_PATTERNS = [
    r"payment|zero.*amount|amount.*0|discount.*100",
    r"refund|double.*spend|race.*condition",
    r"IDOR.*payment|IDOR.*order|wallet.*IDOR",
    r"checkout.*bypass|order.*without.*pay",
]


def _classify_finding(f: dict) -> list[str]:
    """Return list of roles this finding supports (can be multiple)."""
    text = f"{f.get('title','')} {f.get('category','')} {f.get('impact','')}".lower()
    roles = []
    for pat in ENTRY_PATTERNS:
        if re.search(pat, text, re.I):
            roles.append(ROLE_ENTRY)
            break
    for pat in PRIVILEGE_PATTERNS:
        if re.search(pat, text, re.I):
            roles.append(ROLE_PRIVILEGE)
            break
    for pat in PIVOT_PATTERNS:
        if re.search(pat, text, re.I):
            roles.append(ROLE_PIVOT)
            break
    for pat in DATA_PATTERNS:
        if re.search(pat, text, re.I):
            roles.append(ROLE_DATA)
            break
    for pat in FINANCIAL_PATTERNS:
        if re.search(pat, text, re.I):
            roles.append(ROLE_FINANCIAL)
            break
    ftype = (f.get("finding_type") or "").lower()
    if ftype == "hardening":
        roles = [r for r in roles if r not in (ROLE_PRIVILEGE, ROLE_FINANCIAL)]
    # Fallback by severity/category
    if not roles:
        cat = (f.get("category") or "").lower()
        sev = f.get("severity", "Info")
        if "injection" in cat or "sql" in cat or "xss" in cat:
            roles.append(ROLE_ENTRY)
        elif "access control" in cat or "idor" in cat:
            roles.append(ROLE_PRIVILEGE)
        elif "ssrf" in cat or "request forgery" in cat:
            roles.append(ROLE_PIVOT)
        elif sev == "Critical" and "payment" in text:
            roles.append(ROLE_FINANCIAL)
    return roles if roles else [ROLE_ENTRY]  # default: can be entry


def _finding_has_evidence(f: dict) -> bool:
    """True if finding has enough evidence to include in chains (zero FP: no vague steps)."""
    if (f.get("finding_type") or "").lower() == "positive":
        return False
    url = (f.get("url") or "").strip()
    evidence = (f.get("evidence") or "").strip()
    return len(url) > 0 and len(evidence) > 20


def _aggregate_findings_from_results(results: dict) -> list[dict]:
    """Extract a flat list of findings from skill results (same shape as orchestrator)."""
    out: list[dict] = []
    for skill_name, result in results.items():
        if not isinstance(result, dict):
            continue
        for key in ("findings", "header_findings", "ssl_findings"):
            for raw in result.get(key, []):
                if not isinstance(raw, dict):
                    continue
                f = {
                    "title": str(raw.get("title") or raw.get("check") or raw.get("header") or "Untitled").strip(),
                    "severity": str(raw.get("severity", "Info")),
                    "url": str(raw.get("url", "")).strip(),
                    "category": str(raw.get("category", "Assessment") or "").strip(),
                    "evidence": str(raw.get("evidence") or raw.get("detail") or "").strip()[:500],
                    "impact": str(raw.get("impact", "")).strip()[:300],
                    "remediation": str(raw.get("remediation") or "").strip()[:200],
                    "_source_skill": skill_name,
                }
                if raw.get("finding_type"):
                    f["finding_type"] = str(raw.get("finding_type")).strip()
                out.append(f)
        for ep in result.get("endpoints_found", []):
            if isinstance(ep, dict) and not ep.get("auth_required") and ep.get("status_code") == 200:
                out.append({
                    "title": f"Unauthenticated endpoint: {ep.get('url','')}",
                    "severity": "Low",
                    "url": str(ep.get("url", "")),
                    "category": "API Discovery",
                    "evidence": f"Status: {ep.get('status_code')}, Methods: {', '.join(ep.get('methods', []))}",
                    "impact": "Publicly accessible; may leak information.",
                    "remediation": "Review if endpoint should require authentication.",
                    "_source_skill": skill_name,
                })
    return out


# Valid chains (ordered): entry → privilege → data, entry → pivot, privilege → financial, etc.
CHAIN_TEMPLATES = [
    [ROLE_ENTRY, ROLE_PRIVILEGE, ROLE_DATA],
    [ROLE_ENTRY, ROLE_PRIVILEGE, ROLE_FINANCIAL],
    [ROLE_ENTRY, ROLE_DATA],
    [ROLE_ENTRY, ROLE_PIVOT],
    [ROLE_PRIVILEGE, ROLE_DATA],
    [ROLE_PRIVILEGE, ROLE_FINANCIAL],
    [ROLE_ENTRY, ROLE_FINANCIAL],
    [ROLE_PIVOT, ROLE_DATA],
]

# Which skills to run to get findings for each role (for gap analysis)
ROLE_TO_SKILLS = {
    ROLE_ENTRY: ["recon", "api_test", "web_vulns", "headers_ssl"],
    ROLE_PRIVILEGE: ["auth_test", "api_test", "web_vulns"],
    ROLE_PIVOT: ["api_test", "web_vulns"],
    ROLE_DATA: ["api_test", "data_leak_risks", "company_exposure"],
    ROLE_FINANCIAL: ["workflow_probe", "payment_financial", "race_condition", "api_test"],
}


@dataclass
class PathStep:
    role: str
    finding_title: str
    finding_url: str
    source_skill: str
    severity: str


@dataclass
class AttackPath:
    chain_type: str
    steps: list[PathStep]
    exploitability_score: int  # 0-100
    impact_summary: str
    evidence_refs: list[str]


def _compute_gap_analysis(by_role: dict[str, list[dict]]) -> list[dict]:
    """Return gaps: chain templates that are one role short, with suggested skills to run."""
    gaps: list[dict] = []
    for template in CHAIN_TEMPLATES:
        missing = [r for r in template if not by_role.get(r)]
        if len(missing) != 1:
            continue
        role = missing[0]
        chain_desc = " → ".join(template)
        skills = ROLE_TO_SKILLS.get(role, ["api_test", "web_vulns"])
        gaps.append({
            "missing_role": role,
            "chain_template": chain_desc,
            "suggested_skills": skills,
            "reason": f"One more finding (role: {role}) would complete chain: {chain_desc}.",
        })
    return gaps[:10]


def _suggested_next_actions(
    paths: list[AttackPath],
    gaps: list[dict],
    role_counts: dict[str, int],
    has_workflow_urls: bool,
) -> list[dict]:
    """Produce actionable next steps for the operator."""
    actions: list[dict] = []
    if gaps:
        # Prioritize filling high-impact gaps (financial, data)
        for g in sorted(gaps, key=lambda x: (ROLE_FINANCIAL in x["chain_template"], ROLE_DATA in x["chain_template"]), reverse=True)[:3]:
            actions.append({
                "action": f"Run {', '.join(g['suggested_skills'][:2])}",
                "reason": g["reason"],
            })
    if paths and not has_workflow_urls and any(ROLE_FINANCIAL in p.chain_type for p in paths):
        actions.append({
            "action": "Run workflow_probe with context from api_test (endpoints)",
            "reason": "Financial paths exist; validate checkout/order flows and zero-amount acceptance.",
        })
    if role_counts.get(ROLE_ENTRY) and not role_counts.get(ROLE_PRIVILEGE):
        actions.append({
            "action": "Run auth_test and api_test (IDOR, mass assignment)",
            "reason": "Entry points found; privilege escalation checks could complete entry→privilege→data chains.",
        })
    return actions[:6]


def _build_paths(findings: list[dict], max_variants_per_template: int = 2) -> list[AttackPath]:
    """Build attack paths from classified findings. Only findings with url+evidence; high-impact chains need one High/Critical."""
    evidence_only = [f for f in findings if _finding_has_evidence(f)]
    by_role: dict[str, list[dict]] = {r: [] for r in [ROLE_ENTRY, ROLE_PRIVILEGE, ROLE_PIVOT, ROLE_DATA, ROLE_FINANCIAL]}
    for f in evidence_only:
        for r in _classify_finding(f):
            if r in by_role:
                by_role[r].append(f)

    paths: list[AttackPath] = []
    seen_signatures: set[tuple] = set()

    for template in CHAIN_TEMPLATES:
        if not all(by_role[r] for r in template):
            continue
        # Build up to max_variants_per_template paths per template (different finding per role)
        for variant_idx in range(min(max_variants_per_template, max(len(by_role[r]) for r in template) or 1)):
            steps_list: list[PathStep] = []
            refs: list[str] = []
            for role in template:
                cands = by_role[role]
                cand = cands[min(variant_idx, len(cands) - 1)]
                steps_list.append(PathStep(
                    role=role,
                    finding_title=(cand.get("title") or "")[:120],
                    finding_url=(cand.get("url") or "")[:500],
                    source_skill=cand.get("_source_skill", ""),
                    severity=cand.get("severity", "Info"),
                ))
                refs.append(f"{cand.get('title','')} [{cand.get('_source_skill','')}]")

            sig = tuple((s.role, s.finding_title[:60]) for s in steps_list)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)

            sev_score = {"Critical": 25, "High": 18, "Medium": 10, "Low": 5, "Info": 2}
            score = min(100, sum(sev_score.get(s.severity, 2) for s in steps_list) + 10 * len(steps_list))

            if ROLE_FINANCIAL in template:
                impact_summary = "Financial impact: payment/refund/order abuse possible."
            elif ROLE_DATA in template:
                impact_summary = "Data impact: sensitive data or credentials reachable."
            elif ROLE_PIVOT in template:
                impact_summary = "Pivot impact: internal systems or metadata reachable."
            else:
                impact_summary = f"Chain: {' → '.join(template)}."

            if ROLE_FINANCIAL in template or ROLE_DATA in template:
                if not any(s.severity in ("High", "Critical") for s in steps_list):
                    continue
            paths.append(AttackPath(
                chain_type=" → ".join(template),
                steps=steps_list,
                exploitability_score=score,
                impact_summary=impact_summary,
                evidence_refs=refs[:5],
            ))

    paths.sort(key=lambda p: (-p.exploitability_score, -len(p.steps)))
    return paths[:20]


def _attack_story_narrative(p: AttackPath) -> str:
    """Concrete attack story: Step 1 → Step 2 → Impact (zero FP: each step has title + url)."""
    lines = []
    for i, s in enumerate(p.steps, 1):
        lines.append(f"Step {i}: {s.finding_title[:100]} at {s.finding_url[:120]}")
    lines.append(f"Impact: {p.impact_summary}")
    return " ".join(lines)


@dataclass
class AttackPathsReport:
    target_url: str
    findings_count: int
    paths: list[AttackPath]
    role_counts: dict[str, int]
    note: str


def run(
    target_url: str,
    prior_results: dict | None = None,
    prior_results_json: str | None = None,
    scan_type: str = "full",
) -> str:
    """
    Correlate prior scan findings into ranked attack paths. Run after run_full_attack
    or other skills; pass their results to get exploit chains.

    prior_results: dict keyed by skill name, values = skill output dicts.
    prior_results_json: same structure as JSON string (for bot tool).
    """
    if prior_results_json and not prior_results:
        try:
            prior_results = json.loads(prior_results_json)
        except json.JSONDecodeError:
            return json.dumps({
                "target_url": target_url,
                "error": "Invalid prior_results_json.",
                "note": "Pass the JSON object of prior skill results (e.g. from run_full_attack).",
            }, indent=2)

    if not prior_results or not isinstance(prior_results, dict):
        return json.dumps({
            "target_url": target_url,
            "findings_count": 0,
            "paths": [],
            "role_counts": {},
            "gap_analysis": [],
            "suggested_next_actions": [{"action": "Run run_full_attack (or recon, api_test, web_vulns, auth_test, workflow_probe)", "reason": "No prior results; run scans first to build attack paths from findings."}],
            "note": "No prior results provided. Run run_full_attack or other tools first, then pass their results to build attack paths. This skill correlates findings across tools to show how an attacker would chain issues to reach impact.",
        }, indent=2)

    findings = _aggregate_findings_from_results(prior_results)
    if not findings:
        return json.dumps({
            "target_url": target_url,
            "findings_count": 0,
            "paths": [],
            "role_counts": {},
            "gap_analysis": [],
            "suggested_next_actions": [],
            "note": "No findings found in prior results. Run more tools (web_vulns, api_test, auth_test, high_value_flaws, payment_financial, etc.) then pass results again.",
        }, indent=2)

    by_role: dict[str, list[dict]] = {r: [] for r in [ROLE_ENTRY, ROLE_PRIVILEGE, ROLE_PIVOT, ROLE_DATA, ROLE_FINANCIAL]}
    for f in findings:
        for r in _classify_finding(f):
            if r in by_role:
                by_role[r].append(f)

    paths = _build_paths(findings)
    role_counts: dict[str, int] = {}
    for f in findings:
        for r in _classify_finding(f):
            role_counts[r] = role_counts.get(r, 0) + 1

    gap_analysis = _compute_gap_analysis(by_role)
    has_workflow_urls = any(
        u for u in (f.get("url") or "" for f in findings)
        if u and any(h in u.lower() for h in ("confirm", "checkout", "order", "complete", "place"))
    )
    suggested_next_actions = _suggested_next_actions(paths, gap_analysis, role_counts, bool(has_workflow_urls))

    def path_to_dict(p: AttackPath) -> dict:
        return {
            "chain_type": p.chain_type,
            "exploitability_score": p.exploitability_score,
            "impact_summary": p.impact_summary,
            "attack_story": _attack_story_narrative(p),
            "steps": [
                {"role": s.role, "finding_title": s.finding_title, "finding_url": s.finding_url, "source_skill": s.source_skill, "severity": s.severity}
                for s in p.steps
            ],
            "evidence_refs": p.evidence_refs,
        }

    report = {
        "target_url": target_url,
        "findings_count": len(findings),
        "paths": [path_to_dict(p) for p in paths],
        "role_counts": role_counts,
        "gap_analysis": gap_analysis,
        "suggested_next_actions": suggested_next_actions,
        "note": "Diverg attack-path correlation: chains built from your scan findings. Use gap_analysis and suggested_next_actions to prioritize follow-up; prioritize paths with high exploitability_score and financial/data impact.",
    }
    return json.dumps(report, indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    # Optional: pass path to a JSON file of prior results
    results_path = sys.argv[2] if len(sys.argv) > 2 else None
    prior = None
    if results_path and Path(results_path).exists():
        prior = json.loads(Path(results_path).read_text())
    print(run(target, prior_results=prior))
