"""
Natural-language scan intent → skill list. Maps user goal phrases to which skills to run.
Maximum coverage: comprehensive phrase list; unknown goals fall back to full scan.
"""

from __future__ import annotations

import re
from typing import Sequence

# All web skills (no blockchain). Phase1 can run in parallel; phase2 need context.
WEB_PHASE1 = [
    "osint", "recon", "headers_ssl", "crypto_security", "data_leak_risks",
    "company_exposure", "web_vulns", "auth_test", "api_test", "high_value_flaws",
    "workflow_probe", "race_condition", "payment_financial", "client_surface",
]
WEB_PHASE2 = ["dependency_audit", "logic_abuse", "entity_reputation"]
ALL_WEB_SKILLS = WEB_PHASE1 + WEB_PHASE2


# (regex or substring list, skills to run). Substring match is case-insensitive.
# Order: more specific phrases first; we take union of all matching rows.
GOAL_PHRASES: list[tuple[Sequence[str], list[str]]] = [
    # Payment / money / launchpad / rug
    (["payment bypass", "payment bypasses", "bypass payment", "pay bypass"], ["workflow_probe", "payment_financial", "race_condition"]),
    (["rug", "rug pull", "rug risk", "launchpad risk"], ["workflow_probe", "payment_financial", "race_condition", "entity_reputation"]),
    (["launchpad", "token launch", "ido", "presale"], ["workflow_probe", "payment_financial", "race_condition", "company_exposure", "api_test"]),
    (["checkout", "order flow", "order abuse", "zero amount", "skip step"], ["workflow_probe", "payment_financial"]),
    (["refund abuse", "double spend", "race condition"], ["race_condition", "payment_financial", "workflow_probe"]),
    (["financial", "money", "payments", "wallet"], ["payment_financial", "workflow_probe", "auth_test"]),
    # Headers / SSL / transport
    (["headers", "security headers", "hsts", "csp", "x-frame"], ["headers_ssl", "crypto_security"]),
    (["ssl", "tls", "certificate", "https"], ["headers_ssl", "crypto_security"]),
    (["clickjacking", "frame", "iframe"], ["headers_ssl", "company_exposure"]),
    # Injection / OWASP
    (["injection", "sql", "sqli", "nosql", "xss", "ssrf", "ssti", "command injection"], ["web_vulns", "api_test", "high_value_flaws"]),
    (["sql injection", "sqli"], ["web_vulns", "api_test"]),
    (["xss", "cross-site scripting"], ["web_vulns", "client_surface"]),
    (["ssrf", "server-side request forgery"], ["web_vulns", "api_test"]),
    (["idor", "object reference", "access other user"], ["high_value_flaws", "api_test", "auth_test"]),
    (["owasp", "top 10", "full audit"], ALL_WEB_SKILLS),
    # Auth / API
    (["auth", "authentication", "login", "jwt", "session", "cookie"], ["auth_test", "api_test", "crypto_security"]),
    (["api", "rest", "graphql", "endpoints", "swagger", "openapi"], ["api_test", "company_exposure", "web_vulns"]),
    (["admin", "admin panel", "debug", "phpmyadmin", "backend"], ["company_exposure", "api_test", "headers_ssl"]),
    (["exposed admin", "database interface"], ["api_test", "company_exposure"]),
    # Client-side / frontend
    (["client-side", "frontend", "javascript", "source map", "dangerous sink"], ["client_surface", "data_leak_risks"]),
    (["third-party script", "cdn", "trust script"], ["client_surface"]),
    (["sensitive data", "token in js", "key in frontend"], ["client_surface", "data_leak_risks"]),
    # Recon / surface
    (["recon", "reconnaissance", "subdomain", "ports", "surface"], ["recon", "osint", "company_exposure"]),
    (["osint", "intel", "external"], ["osint", "recon"]),
    (["exposure", "sensitive path", "backup", "config file"], ["company_exposure", "recon"]),
    # Business logic / workflow
    (["business logic", "workflow", "workflow abuse", "logic abuse"], ["workflow_probe", "logic_abuse", "race_condition"]),
    (["dependency", "cve", "outdated", "vulnerable library"], ["dependency_audit"]),
    (["reputation", "entity", "fraud", "scam", "lawsuit"], ["entity_reputation", "osint"]),
    # Crypto / DeFi / chain validation (Diverg batch vs single, account ID substitution)
    (["crypto", "cryptocurrency", "defi", "decentralized finance", "web3", "blockchain", "chain"], ["crypto_security", "payment_financial", "api_test", "high_value_flaws", "chain_validation_abuse", "client_surface"]),
    (["batch validation", "batch vs single", "chain validation", "account drain", "subaccount"], ["chain_validation_abuse", "api_test", "high_value_flaws"]),
    (["crypto audit", "defi audit", "chain audit", "exchange security"], ["crypto_security", "chain_validation_abuse", "payment_financial", "api_test", "workflow_probe", "high_value_flaws"]),
    # General / safe / comprehensive
    (["everything", "full", "comprehensive", "deep", "thorough", "complete scan"], ALL_WEB_SKILLS),
    (["safe", "secure", "make sure we're safe", "compliance"], ALL_WEB_SKILLS),
]


def _normalize_goal(goal: str | None) -> str:
    if not goal or not isinstance(goal, str):
        return ""
    return " " + goal.lower().strip() + " "


def resolve_goal(goal: str | None) -> list[str]:
    """
    Map natural-language goal to list of skill names to run.
    If goal is empty or no phrase matches, returns full web skill list (maximum coverage).
    """
    if not goal or not str(goal).strip():
        return list(ALL_WEB_SKILLS)
    hay = _normalize_goal(goal)
    collected: set[str] = set()
    for phrases, skills in GOAL_PHRASES:
        for p in phrases:
            if p.lower() in hay or (p.startswith("^") and re.search(p, hay)):
                collected.update(skills)
                break
    if not collected:
        return list(ALL_WEB_SKILLS)
    # Preserve order: phase1 first, then phase2
    phase1 = [s for s in WEB_PHASE1 if s in collected]
    phase2 = [s for s in WEB_PHASE2 if s in collected]
    return phase1 + phase2
