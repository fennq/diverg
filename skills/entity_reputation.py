"""
Entity reputation / foul-play research — external research on domain owners and
associated entities to surface past crimes, lawsuits, breaches, and controversy.

Uses WHOIS (org, registrant name) and optional OSINT context to identify entities,
then runs external reputation searches (e.g. fraud, lawsuit, convicted, breach, FTC, SEC)
to find connections to potential foul play, backdooring, or crime dating back years.

Authorized use only. For improving company security and assessing whether companies
or owners have been linked to crime, foul play, or backdooring.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote_plus

import requests

import sys
_skills_dir = str(Path(__file__).resolve().parent)
if _skills_dir not in sys.path:
    sys.path.insert(0, _skills_dir)
from stealth import get_session

SESSION = get_session()
TIMEOUT = 15
MAX_ENTITIES = 4
REPUTATION_QUERY_SUFFIX = " fraud OR lawsuit OR convicted OR fined OR data breach OR scandal OR backdoor OR FTC OR SEC OR regulatory"
REPUTATION_QUERY_EXECUTIVE = " CEO OR founder OR arrested OR indicted OR sanction OR fined OR DOJ OR indictment"
RUN_BUDGET_SEC = 25
MAX_RESULTS_PER_ENTITY = 6
YEAR_RE = __import__("re").compile(r"\b(19[89]\d|20[0-2]\d)\b")


@dataclass
class ReputationFinding:
    entity: str
    query: str
    title: str
    snippet: str
    url: str
    relevance_hint: str
    severity: str = "Medium"  # High | Medium | Low
    date_hint: str | None = None  # e.g. "2019", "2020-2022"


@dataclass
class EntityReputationReport:
    target_domain: str
    entities_searched: list[str] = field(default_factory=list)
    findings: list[ReputationFinding] = field(default_factory=list)
    recommended_queries: list[str] = field(default_factory=list)
    summary: str = ""
    errors: list[str] = field(default_factory=list)


def _extract_entities_from_osint(osint_json: str | None) -> tuple[list[str], list[str]]:
    """Pull org, registrant_name, and email domains from OSINT whois_info. Returns (entities, email_domains)."""
    entities: list[str] = []
    email_domains: list[str] = []
    if not osint_json or not osint_json.strip():
        return entities, email_domains
    try:
        data = json.loads(osint_json)
        whois = data.get("whois_info") or {}
        org = whois.get("org") or whois.get("organization")
        if org and isinstance(org, str) and len(org) > 1 and org.strip() not in entities:
            entities.append(org.strip())
        name = whois.get("registrant_name") or whois.get("name") or whois.get("registrant")
        if name and isinstance(name, str) and len(name) > 1 and name.strip() not in entities:
            entities.append(name.strip())
        emails = whois.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        for e in emails[:5]:
            if not isinstance(e, str) or "@" not in e:
                continue
            domain = e.split("@")[-1].strip().lower()
            if domain and domain not in email_domains and len(domain) > 4:
                email_domains.append(domain)
    except Exception:
        pass
    return entities[:MAX_ENTITIES], email_domains[:2]


def _extract_date_hint(text: str) -> str | None:
    """Extract a year or year range from snippet for timeline context."""
    if not text:
        return None
    years = YEAR_RE.findall(text)
    if not years:
        return None
    uniq = sorted(set(years), key=int)
    if len(uniq) == 1:
        return uniq[0]
    return f"{uniq[0]}-{uniq[-1]}"


def _search_duckduckgo_html(query: str) -> list[tuple[str, str, str]]:
    """Return list of (title, snippet, url) from DuckDuckGo HTML search. No API key."""
    results = []
    try:
        url = "https://html.duckduckgo.com/html/"
        payload = {"q": query}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        r = SESSION.post(url, data=payload, headers=headers, timeout=TIMEOUT)
        if not r.ok:
            return results
        html = r.text
        # Parse result blocks: DDG uses class result__body and result__url, result__snippet
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for block in soup.select(".result__body")[:MAX_RESULTS_PER_ENTITY]:
            link = block.select_one(".result__url") or block.select_one("a.result__a")
            snippet_el = block.select_one(".result__snippet")
            title_el = block.select_one(".result__title") or block.select_one("a.result__a")
            title = (title_el.get_text(strip=True) if title_el else "")[:200]
            snippet = (snippet_el.get_text(strip=True) if snippet_el else "")[:300]
            href = ""
            if link and link.get("href"):
                href = link["href"] if isinstance(link.get("href"), str) else ""
            if link and hasattr(link, "get") and not href and link.get("href"):
                href = link.get("href", "")
            if not href and title_el and title_el.get("href"):
                href = title_el["href"]
            if title or snippet or href:
                results.append((title, snippet, href))
    except Exception:
        pass
    return results


def _relevance_and_severity(snippet: str) -> tuple[str, str]:
    sn_lower = (snippet or "").lower()
    if "lawsuit" in sn_lower or "sued" in sn_lower:
        return "lawsuit", "Medium"
    if "breach" in sn_lower or "leak" in sn_lower or "pwned" in sn_lower:
        return "breach", "Medium"
    if "convicted" in sn_lower or "pleaded" in sn_lower or "guilty" in sn_lower or "arrested" in sn_lower or "indicted" in sn_lower:
        return "criminal", "High"
    if "ftc" in sn_lower or "sec" in sn_lower or "fined" in sn_lower or "penalty" in sn_lower or "doj" in sn_lower or "sanction" in sn_lower:
        return "regulatory", "High"
    if "fraud" in sn_lower or "scam" in sn_lower or "backdoor" in sn_lower:
        return "foul_play", "High"
    return "reputation", "Low"


def _canonical_findings(domain: str, reputation_findings: list[ReputationFinding]) -> list[dict]:
    """Normalize reputation hits into the shared Diverg finding schema for aggregation and UI."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    impact_map = {
        "criminal": "Public reporting references criminal, arrest, indictment, or guilty plea context; corroborate with court or government sources.",
        "regulatory": "Public reporting references regulatory or enforcement actions; verify dockets and official releases.",
        "breach": "Public reporting references data breach or leak context tied to the entity or domain mail host.",
        "lawsuit": "Public reporting references civil litigation; review filings for relevance to your assessment.",
        "foul_play": "Public reporting references fraud, scam, or serious trust allegations.",
        "reputation": "Generic news or reputation hit; treat as a lead until corroborated.",
    }
    for rf in reputation_findings:
        u = (rf.url or "").strip()
        t = ((rf.title or "").strip())[:180]
        key = (u, t) if u else ("", t + rf.entity)
        if key in seen:
            continue
        seen.add(key)
        rel = (rf.relevance_hint or "reputation").strip()
        sev = str(rf.severity or "Medium")
        impact = impact_map.get(rel, impact_map["reputation"])
        ev_parts = [x for x in (rf.snippet or "", f"Query: {rf.query}", f"Timeline: {rf.date_hint}" if rf.date_hint else "") if x]
        evidence = " | ".join(ev_parts)
        search_url = f"https://duckduckgo.com/?q={quote_plus(rf.query)}"
        out.append({
            "title": f"Entity / reputation ({rel}): {(rf.entity or domain)[:80]} — {(rf.title or 'Result')[:90]}",
            "severity": sev,
            "url": u or search_url,
            "category": "Entity / Reputation",
            "evidence": (evidence or "See search query in title context.")[:4000],
            "impact": impact,
            "remediation": "Corroborate with primary sources. Third-party search snippets are not legal or factual conclusions.",
            "confidence": "low" if sev == "Low" else "medium",
        })
    return out


def _run_reputation_search(entity: str, query_suffix: str) -> list[ReputationFinding]:
    """Run one external reputation search for entity; return structured findings with severity and date_hint."""
    findings = []
    query = f'"{entity}" {query_suffix}'
    for title, snippet, url in _search_duckduckgo_html(query):
        relevance, severity = _relevance_and_severity(snippet or "")
        date_hint = _extract_date_hint((snippet or "") + " " + (title or ""))
        findings.append(ReputationFinding(
            entity=entity,
            query=query,
            title=title or "",
            snippet=snippet or "",
            url=url or "",
            relevance_hint=relevance,
            severity=severity,
            date_hint=date_hint,
        ))
    return findings


def run(
    target: str,
    scan_type: str = "full",
    osint_json: str | None = None,
) -> str:
    """
    Run entity reputation / foul-play research on the domain owner and related entities.

    target: domain (e.g. example.com) or URL; domain will be extracted.
    osint_json: optional JSON string from osint skill run (whois_info used to get org/registrant).
    """
    domain = (target or "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
    if not domain:
        return json.dumps({
            "target_domain": "",
            "target_url": "",
            "findings": [],
            "entities_searched": [],
            "recommended_queries": [],
            "summary": "",
            "errors": ["No domain provided"],
        })

    report = EntityReputationReport(target_domain=domain)
    run_start = time.time()
    raw_findings: list[ReputationFinding] = []

    def _over_budget() -> bool:
        return (time.time() - run_start) > RUN_BUDGET_SEC

    entities, email_domains = _extract_entities_from_osint(osint_json)
    if not entities:
        try:
            import whois
            w = whois.whois(domain)
            org = getattr(w, "org", None)
            if isinstance(org, list):
                org = org[0] if org else None
            if org and str(org).strip():
                entities.append(str(org).strip())
            name = getattr(w, "name", None)
            if isinstance(name, list):
                name = name[0] if name else None
            if name and str(name).strip() and str(name).strip() not in entities:
                entities.append(str(name).strip())
        except Exception as e:
            report.errors.append(f"WHOIS fallback: {e}")
    if not entities:
        entities = [domain]

    report.entities_searched = list(entities[:MAX_ENTITIES])

    for entity in entities[:MAX_ENTITIES]:
        if _over_budget():
            break
        raw_findings.extend(_run_reputation_search(entity, REPUTATION_QUERY_SUFFIX))
        report.recommended_queries.append(f'"{entity}" {REPUTATION_QUERY_SUFFIX}')
        time.sleep(0.8)
        if _over_budget():
            break
        raw_findings.extend(_run_reputation_search(entity, REPUTATION_QUERY_EXECUTIVE))
        report.recommended_queries.append(f'"{entity}" {REPUTATION_QUERY_EXECUTIVE}')
        time.sleep(0.8)

    for email_domain in email_domains:
        if _over_budget():
            break
        label = f"email_domain:{email_domain}"
        if label not in report.entities_searched:
            report.entities_searched.append(label)
        raw_findings.extend(_run_reputation_search(email_domain, "data breach OR leak OR pwned OR exposed"))
        report.recommended_queries.append(f'"{email_domain}" data breach OR leak')
        time.sleep(0.8)

    high = sum(1 for f in raw_findings if getattr(f, "severity", "") == "High")
    report.summary = (
        f"{len(report.entities_searched)} entities researched, {len(raw_findings)} raw hits ({high} high-severity signals). "
        + ("Corroborate top items in findings." if raw_findings else "No public hits; use recommended_queries for manual follow-up.")
    )
    if report.entities_searched and not str(report.entities_searched[0]).startswith("email_domain:"):
        report.recommended_queries.append(f'"{report.entities_searched[0]}" 2019..2024 fraud OR lawsuit OR breach')

    canonical = _canonical_findings(domain, raw_findings)
    payload = {
        "target_domain": domain,
        "target_url": f"https://{domain}",
        "entities_searched": report.entities_searched,
        "findings": canonical,
        "recommended_queries": report.recommended_queries,
        "summary": report.summary,
        "errors": report.errors,
        "reputation_hits_count": len(raw_findings),
    }
    return json.dumps(payload, indent=2)
