"""
Domain trust assessment — multi-factor domain reputation using WHOIS, TLD
abuse stats, registrar reputation, privacy/proxy detection, and email auth.

Data comes from osint_json (phase 1) with WHOIS fallback if needed.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


RUN_BUDGET_SEC = 20

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Freenom free TLDs + TLDs consistently topping abuse charts (Spamhaus, SURBL, APWG)
HIGH_ABUSE_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "work", "click", "buzz", "surf", "rest", "icu", "cam",
    "monster", "cyou", "cfd", "sbs", "quest",
})

MODERATE_ABUSE_TLDS: frozenset[str] = frozenset({
    "info", "biz", "online", "site", "website", "store", "fun", "space",
    "live", "club", "pw", "cc", "ws", "life", "tech", "uno",
})

MAINSTREAM_TLDS: frozenset[str] = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int",
    "co", "io", "dev", "app", "ai",
})

PRIVACY_KEYWORDS: list[str] = [
    "whoisguard", "domains by proxy", "contact privacy", "redacted for privacy",
    "identity protection", "perfect privacy", "withheldforprivacy",
    "privacy protect", "whois privacy", "data protected", "domain privacy",
    "privacy service", "gdpr masked", "statutorymasking", "redacted",
    "not disclosed", "identity shield", "whoisprivacyprotect",
    "privacydotlink", "super privacy", "domainprivacygroup",
]

# Registrars disproportionately represented in phishing/abuse reports
HIGH_ABUSE_REGISTRARS: list[str] = [
    "namecheap", "namesilo", "reg.ru", "nicenic", "alibaba",
    "publicdomainregistry", "pdr ltd", "web commerce communications",
    "epik", "hosting concepts", "internet domain service",
    "gmo internet", "todaynic", "bizcn", "jiangsu bangning",
    "west263", "hichina", "ename",
]

# Signal weights for composite trust score
WEIGHT_DOMAIN_AGE = 0.35
WEIGHT_TLD = 0.20
WEIGHT_EXPIRATION = 0.15
WEIGHT_PRIVACY = 0.15
WEIGHT_REGISTRAR = 0.15

# Severity / finding-type mapping
_RISK_SEVERITY: dict[str, tuple[str, str]] = {
    "high": ("High", "vulnerability"),
    "medium": ("Medium", "vulnerability"),
    "low": ("Low", "informational"),
    "info": ("Info", "informational"),
    "unknown": ("Info", "informational"),
}

_SIGNAL_TITLES: dict[str, str] = {
    "domain_age": "Domain age",
    "expiration_proximity": "Registration expiration",
    "tld_reputation": "TLD reputation",
    "privacy_proxy": "WHOIS privacy/proxy",
    "registrar_reputation": "Registrar reputation",
    "email_security": "Email security posture",
}

_SIGNAL_IMPACT: dict[str, str] = {
    "domain_age": "Newly registered domains are heavily overrepresented in phishing and throwaway attack infra.",
    "expiration_proximity": "Short reg windows or imminent expiry are typical of disposable campaign domains.",
    "tld_reputation": "Some TLDs have significantly higher abuse rates (Spamhaus, SURBL data).",
    "privacy_proxy": "WHOIS privacy hides ownership — legit use exists, but also enables anonymous abuse.",
    "registrar_reputation": "Certain registrars show up disproportionately in abuse reports (lax verification, cheap bulk reg).",
    "email_security": "No SPF/DKIM/DMARC suggests the domain lacks operational maturity or config.",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class DomainSignal:
    signal: str
    value: Any
    risk: str       # high | medium | low | info | unknown
    score: int      # 0-100 sub-score (100 = fully trusted)
    reason: str
    weight: float   # contribution to composite (0.0 = modifier only)


@dataclass
class DomainTrustReport:
    target_url: str
    domain: str
    trust_score: int | None = None
    trust_verdict: str = "unknown"
    signals: list[DomainSignal] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    domain_trust: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_domain(target_url: str) -> str:
    t = (target_url or "").strip()
    t = t.replace("https://", "").replace("http://", "")
    t = t.split("/")[0].split(":")[0].strip().lower()
    return t


def _extract_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def _parse_any_datetime(raw: Any) -> datetime | None:
    """Best-effort parse for python-whois values and JSON-serialized variants."""
    if raw is None:
        return None
    if isinstance(raw, list) and raw:
        parsed = [_parse_any_datetime(x) for x in raw]
        parsed = [p for p in parsed if p is not None]
        return min(parsed) if parsed else None

    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc) if raw.tzinfo else raw.replace(tzinfo=timezone.utc)

    try:
        import datetime as _dt
        if isinstance(raw, _dt.date) and not isinstance(raw, _dt.datetime):
            return datetime(raw.year, raw.month, raw.day, tzinfo=timezone.utc)
    except Exception:
        pass

    s = str(raw).strip()
    if not s:
        return None
    s = s.replace("/", "-").replace(".", "-")

    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    fmts = (
        "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z",
        "%d-%b-%Y", "%d-%b-%Y %H:%M:%S %Z",
    )
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _parse_osint_context(osint_json: str | None) -> dict:
    """Extract all usable fields from the phase-1 osint JSON into a flat dict."""
    ctx: dict[str, Any] = {
        "creation_date": None,
        "expiration_date": None,
        "registrar": None,
        "org": None,
        "registrant_name": None,
        "country": None,
        "emails": [],
        "dnssec": None,
        "spf_record": None,
        "spf_analysis": None,
        "dkim_selectors": [],
        "dmarc_record": None,
        "dmarc_analysis": None,
    }
    if not osint_json or not osint_json.strip():
        return ctx
    try:
        data = json.loads(osint_json)
        if not isinstance(data, dict):
            return ctx
        whois_info = data.get("whois_info")
        if isinstance(whois_info, dict):
            for key in ("creation_date", "expiration_date", "registrar",
                        "org", "registrant_name", "country", "dnssec"):
                if whois_info.get(key) is not None:
                    ctx[key] = whois_info[key]
            ctx["emails"] = whois_info.get("emails") or []
        tech_infra = data.get("tech_infra")
        if isinstance(tech_infra, dict):
            ctx["spf_record"] = tech_infra.get("spf_record")
            ctx["spf_analysis"] = tech_infra.get("spf_analysis")
            dkim = tech_infra.get("dkim_records")
            if isinstance(dkim, dict):
                ctx["dkim_selectors"] = list(dkim.keys())
            ctx["dmarc_record"] = tech_infra.get("dmarc_record")
            ctx["dmarc_analysis"] = tech_infra.get("dmarc_analysis")
    except Exception:
        pass
    return ctx


# ---------------------------------------------------------------------------
# Signal computations
# ---------------------------------------------------------------------------


def _signal_domain_age(domain: str, ctx: dict) -> DomainSignal:
    """Days since WHOIS creation_date."""
    created_dt = _parse_any_datetime(ctx.get("creation_date"))

    if created_dt is None:
        try:
            import whois  # type: ignore
            w = whois.whois(domain)
            created_dt = _parse_any_datetime(getattr(w, "creation_date", None))
        except Exception as exc:
            return DomainSignal(
                signal="domain_age", value=None, risk="unknown", score=50,
                reason=f"WHOIS lookup failed: {type(exc).__name__}: {exc}",
                weight=WEIGHT_DOMAIN_AGE,
            )

    if created_dt is None:
        return DomainSignal(
            signal="domain_age", value=None, risk="unknown", score=50,
            reason="Creation date unavailable from WHOIS.",
            weight=WEIGHT_DOMAIN_AGE,
        )

    now = datetime.now(timezone.utc)
    age_days = max(0, int((now - created_dt).total_seconds() // 86400))

    if age_days < 7:
        score, risk = 0, "high"
    elif age_days < 30:
        score, risk = 15, "high"
    elif age_days < 90:
        score, risk = 40, "medium"
    elif age_days < 365:
        score, risk = 65, "low"
    elif age_days < 730:
        score, risk = 80, "low"
    elif age_days < 1825:
        score, risk = 90, "info"
    else:
        score, risk = 100, "info"

    return DomainSignal(
        signal="domain_age", value=age_days, risk=risk, score=score,
        reason=f"Domain registered {age_days} day(s) ago (created {created_dt.date().isoformat()}).",
        weight=WEIGHT_DOMAIN_AGE,
    )


def _signal_expiration_proximity(domain: str, ctx: dict) -> DomainSignal:
    """How soon the registration expires and the total registration window."""
    expiry_dt = _parse_any_datetime(ctx.get("expiration_date"))
    created_dt = _parse_any_datetime(ctx.get("creation_date"))

    if expiry_dt is None:
        return DomainSignal(
            signal="expiration_proximity", value=None, risk="unknown", score=50,
            reason="Expiration date unavailable from WHOIS.",
            weight=WEIGHT_EXPIRATION,
        )

    now = datetime.now(timezone.utc)
    days_until = max(0, int((expiry_dt - now).total_seconds() // 86400))

    window_days: int | None = None
    if created_dt:
        window_days = max(0, int((expiry_dt - created_dt).total_seconds() // 86400))

    if days_until < 30:
        score, risk = 15, "high"
        reason = f"Domain expires in {days_until} day(s) — imminent expiration."
    elif days_until < 90:
        score, risk = 40, "medium"
        reason = f"Domain expires in {days_until} day(s)."
    elif window_days is not None and window_days < 400:
        score, risk = 20, "high"
        reason = f"Registration window is only {window_days} days (minimum-period registration)."
    elif window_days is not None and window_days < 800:
        score, risk = 50, "medium"
        reason = f"Registration window is {window_days} days — short commitment."
    elif days_until > 365:
        score, risk = 95, "info"
        reason = f"Domain expires in {days_until} days — long runway."
    else:
        score, risk = 70, "low"
        reason = f"Domain expires in {days_until} day(s)."

    return DomainSignal(
        signal="expiration_proximity", value=days_until, risk=risk, score=score,
        reason=reason, weight=WEIGHT_EXPIRATION,
    )


def _signal_tld_reputation(domain: str) -> DomainSignal:
    """TLD reputation based on aggregate abuse statistics."""
    tld = _extract_tld(domain)
    if not tld:
        return DomainSignal(
            signal="tld_reputation", value=None, risk="unknown", score=50,
            reason="Could not extract TLD.", weight=WEIGHT_TLD,
        )

    if tld in HIGH_ABUSE_TLDS:
        return DomainSignal(
            signal="tld_reputation", value=f".{tld}", risk="high", score=10,
            reason=f".{tld} is a high-abuse TLD frequently used in phishing and spam campaigns.",
            weight=WEIGHT_TLD,
        )
    if tld in MODERATE_ABUSE_TLDS:
        return DomainSignal(
            signal="tld_reputation", value=f".{tld}", risk="medium", score=40,
            reason=f".{tld} has elevated abuse rates compared to mainstream TLDs.",
            weight=WEIGHT_TLD,
        )
    if tld in MAINSTREAM_TLDS:
        return DomainSignal(
            signal="tld_reputation", value=f".{tld}", risk="info", score=100,
            reason=f".{tld} is a mainstream TLD with normal abuse rates.",
            weight=WEIGHT_TLD,
        )
    return DomainSignal(
        signal="tld_reputation", value=f".{tld}", risk="low", score=70,
        reason=f".{tld} is not on known high-abuse lists.",
        weight=WEIGHT_TLD,
    )


def _signal_privacy_proxy(ctx: dict, age_days: int | None) -> DomainSignal:
    """Detect WHOIS privacy/proxy services, contextualised by domain age."""
    haystack = " ".join(
        str(ctx.get(k) or "").lower()
        for k in ("registrar", "org", "registrant_name")
    )
    haystack += " " + " ".join(str(e).lower() for e in (ctx.get("emails") or []))

    matched_keyword = ""
    for kw in PRIVACY_KEYWORDS:
        if kw in haystack:
            matched_keyword = kw
            break

    if not matched_keyword:
        return DomainSignal(
            signal="privacy_proxy", value=False, risk="info", score=100,
            reason="No WHOIS privacy/proxy service detected.",
            weight=WEIGHT_PRIVACY,
        )

    if age_days is not None and age_days < 365:
        return DomainSignal(
            signal="privacy_proxy", value=True, risk="high", score=15,
            reason=(
                f"WHOIS privacy detected ('{matched_keyword}') on a domain "
                f"less than 1 year old — common in disposable phishing domains."
            ),
            weight=WEIGHT_PRIVACY,
        )
    if age_days is not None and age_days < 1095:
        return DomainSignal(
            signal="privacy_proxy", value=True, risk="medium", score=45,
            reason=f"WHOIS privacy detected ('{matched_keyword}') on a domain under 3 years old.",
            weight=WEIGHT_PRIVACY,
        )
    return DomainSignal(
        signal="privacy_proxy", value=True, risk="low", score=70,
        reason=f"WHOIS privacy detected ('{matched_keyword}'), but domain is well-established.",
        weight=WEIGHT_PRIVACY,
    )


def _signal_registrar_reputation(ctx: dict) -> DomainSignal:
    """Check registrar against known high-abuse registrar list."""
    registrar = str(ctx.get("registrar") or "").lower().strip()
    if not registrar:
        return DomainSignal(
            signal="registrar_reputation", value=None, risk="unknown", score=50,
            reason="Registrar information unavailable.",
            weight=WEIGHT_REGISTRAR,
        )

    for abuse_reg in HIGH_ABUSE_REGISTRARS:
        if abuse_reg in registrar:
            return DomainSignal(
                signal="registrar_reputation", value=registrar, risk="medium", score=35,
                reason=(
                    f"Registrar '{registrar}' appears in high-abuse registrar lists.  "
                    "This is contextual — many legitimate domains also use this registrar."
                ),
                weight=WEIGHT_REGISTRAR,
            )

    return DomainSignal(
        signal="registrar_reputation", value=registrar, risk="info", score=85,
        reason=f"Registrar '{registrar}' is not flagged in abuse lists.",
        weight=WEIGHT_REGISTRAR,
    )


def _signal_email_security(ctx: dict) -> DomainSignal:
    """Email security posture (SPF/DKIM/DMARC) as a domain maturity indicator."""
    has_spf = bool(ctx.get("spf_record"))
    has_dkim = bool(ctx.get("dkim_selectors"))
    has_dmarc = bool(ctx.get("dmarc_record"))
    count = sum([has_spf, has_dkim, has_dmarc])

    spf_strict = has_spf and "-all" in str(ctx.get("spf_record", ""))
    dmarc_strict = False
    if has_dmarc and ctx.get("dmarc_analysis"):
        analysis_upper = str(ctx["dmarc_analysis"]).upper()
        dmarc_strict = "REJECT" in analysis_upper or "QUARANTINE" in analysis_upper

    present = [k.upper() for k, v in [("spf", has_spf), ("dkim", has_dkim), ("dmarc", has_dmarc)] if v]
    val: dict[str, Any] = {"spf": has_spf, "dkim": has_dkim, "dmarc": has_dmarc}

    if count == 0:
        return DomainSignal(
            signal="email_security", value=val, risk="high", score=10,
            reason="No email authentication records (SPF, DKIM, DMARC) found.",
            weight=0.0,
        )
    if count == 1:
        return DomainSignal(
            signal="email_security", value=val, risk="medium", score=35,
            reason=f"Partial email authentication: {', '.join(present)} only.",
            weight=0.0,
        )
    if count == 2:
        return DomainSignal(
            signal="email_security", value=val, risk="low", score=65,
            reason=f"Good email authentication (2/3): {', '.join(present)}.",
            weight=0.0,
        )

    strict = spf_strict and dmarc_strict
    val["strict"] = strict
    return DomainSignal(
        signal="email_security", value=val, risk="info",
        score=95 if strict else 80,
        reason=f"Full email authentication ({'strict' if strict else 'present'}): SPF, DKIM, DMARC.",
        weight=0.0,
    )


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------


def _compute_trust_score(signals: list[DomainSignal]) -> int:
    """Weighted average of sub-scores (weight > 0 only), adjusted by email modifier."""
    weighted_sum = 0.0
    total_weight = 0.0
    for sig in signals:
        if sig.weight > 0 and sig.risk != "unknown":
            weighted_sum += sig.score * sig.weight
            total_weight += sig.weight
    if total_weight == 0:
        return 50

    base = weighted_sum / total_weight

    email_sig = next((s for s in signals if s.signal == "email_security"), None)
    if email_sig and email_sig.risk != "unknown":
        if email_sig.score < 20:
            base -= 5
        elif email_sig.score >= 80:
            base += 3

    return max(0, min(100, int(round(base))))


def _cross_signal_severity(signals: list[DomainSignal]) -> str:
    """Determine composite severity from signal combinations."""
    core = [s for s in signals if s.weight > 0]
    high_count = sum(1 for s in core if s.risk == "high")
    medium_count = sum(1 for s in core if s.risk == "medium")

    age_sig = next((s for s in signals if s.signal == "domain_age"), None)
    tld_sig = next((s for s in signals if s.signal == "tld_reputation"), None)
    priv_sig = next((s for s in signals if s.signal == "privacy_proxy"), None)

    if high_count >= 3:
        return "Critical"
    if age_sig and age_sig.risk == "high":
        if (tld_sig and tld_sig.risk in ("high", "medium")) or \
           (priv_sig and priv_sig.risk == "high"):
            return "High"
    if high_count >= 2:
        return "High"
    if high_count == 1 or medium_count >= 2:
        return "Medium"
    if medium_count == 1:
        return "Low"
    return "Info"


def _trust_verdict(score: int) -> str:
    if score < 20:
        return "critical"
    if score < 40:
        return "poor"
    if score < 60:
        return "fair"
    if score < 80:
        return "good"
    return "excellent"


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------


def _signal_title_suffix(sig: DomainSignal) -> str:
    """Human-friendly suffix for each signal type."""
    if sig.signal == "domain_age":
        return f"{sig.value} days" if sig.value is not None else "unknown"
    if sig.signal == "expiration_proximity":
        return f"{sig.value} days remaining" if sig.value is not None else "unknown"
    if sig.signal == "tld_reputation":
        return str(sig.value) if sig.value else "unknown"
    if sig.signal == "privacy_proxy":
        return "detected" if sig.value else "not detected"
    if sig.signal == "email_security" and isinstance(sig.value, dict):
        present = [k.upper() for k in ("spf", "dkim", "dmarc") if sig.value.get(k)]
        if present:
            return f"{len(present)}/3 ({', '.join(present)})"
        return "none configured"
    if sig.signal == "registrar_reputation":
        return str(sig.value)[:60] if sig.value else "unknown"
    return str(sig.value) if sig.value is not None else "unknown"


def _signal_to_finding(target_url: str, sig: DomainSignal) -> dict:
    severity, finding_type = _RISK_SEVERITY.get(sig.risk, ("Info", "informational"))
    title_prefix = _SIGNAL_TITLES.get(sig.signal, sig.signal)
    suffix = _signal_title_suffix(sig)
    impact = _SIGNAL_IMPACT.get(sig.signal, "Contextual signal for domain trust assessment.")

    return {
        "title": f"{title_prefix}: {suffix}",
        "severity": severity,
        "url": target_url,
        "category": "Domain Trust",
        "evidence": f"signal={sig.signal}; sub_score={sig.score}/100; {sig.reason}",
        "impact": impact,
        "remediation": "Evaluate alongside other trust signals — isolated hits are informational, stacked hits need investigation.",
        "finding_type": finding_type,
        "context": sig.reason,
        "confidence": "medium" if sig.risk != "unknown" else "low",
        "verified": False,
    }


def _summary_finding(target_url: str, report: DomainTrustReport) -> dict:
    """Composite domain trust assessment finding."""
    severity = _cross_signal_severity(report.signals)
    score = report.trust_score if report.trust_score is not None else 50
    verdict = report.trust_verdict

    elevated = [s for s in report.signals if s.risk in ("high", "medium")]
    elevated_names = ", ".join(
        _SIGNAL_TITLES.get(s.signal, s.signal) for s in elevated
    )

    evidence_parts = [f"trust_score={score}/100", f"verdict={verdict}"]
    for sig in report.signals:
        evidence_parts.append(f"{sig.signal}={sig.score}/100 ({sig.risk})")

    return {
        "title": f"Domain Trust Assessment: {score}/100 ({verdict})",
        "severity": severity,
        "url": target_url,
        "category": "Domain Trust",
        "evidence": "; ".join(evidence_parts),
        "impact": (
            f"Composite domain trust score based on {len(report.signals)} signals. "
            + (f"Elevated signals: {elevated_names}. " if elevated else "No elevated signals. ")
            + "Low trust scores correlate with disposable infrastructure used in "
            "phishing, fraud, and short-lived attack campaigns."
        ),
        "remediation": (
            "Low-trust: dig into CT logs, ownership history, and threat intel feeds. "
            "High-trust: normal monitoring is fine."
        ),
        "finding_type": "vulnerability" if severity in ("Critical", "High", "Medium") else "informational",
        "context": f"Domain trust score {score}/100 ({verdict}) from {len(report.signals)} signals.",
        "confidence": "high" if all(
            s.risk != "unknown" for s in report.signals if s.weight > 0
        ) else "medium",
        "verified": False,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(target_url: str, scan_type: str = "full", osint_json: str | None = None) -> str:
    """Skill entry point.  Returns JSON with findings + domain_trust payload."""
    run_start = time.time()
    domain = _extract_domain(target_url)
    report = DomainTrustReport(target_url=target_url, domain=domain)

    if not domain:
        report.errors.append("No domain extracted from target_url.")
        return json.dumps(asdict(report), indent=2)

    ctx = _parse_osint_context(osint_json)

    def _over_budget() -> bool:
        return (time.time() - run_start) > RUN_BUDGET_SEC

    # -- Compute all signals --
    age_sig = _signal_domain_age(domain, ctx)
    report.signals.append(age_sig)
    age_days: int | None = age_sig.value if isinstance(age_sig.value, int) else None

    if not _over_budget():
        report.signals.append(_signal_tld_reputation(domain))
    if not _over_budget():
        report.signals.append(_signal_expiration_proximity(domain, ctx))
    if not _over_budget():
        report.signals.append(_signal_privacy_proxy(ctx, age_days))
    if not _over_budget():
        report.signals.append(_signal_registrar_reputation(ctx))
    if not _over_budget():
        report.signals.append(_signal_email_security(ctx))

    # -- Composite trust score --
    report.trust_score = _compute_trust_score(report.signals)
    report.trust_verdict = _trust_verdict(report.trust_score)

    # -- Generate findings --
    for sig in report.signals:
        if sig.risk != "unknown":
            report.findings.append(_signal_to_finding(target_url, sig))
    report.findings.insert(0, _summary_finding(target_url, report))

    # -- Structured payload for API consumers --
    report.domain_trust = {
        "score": report.trust_score,
        "verdict": report.trust_verdict,
        "signals": {
            sig.signal: {"score": sig.score, "risk": sig.risk, "value": sig.value}
            for sig in report.signals
        },
    }

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    import sys

    u = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    osint = sys.argv[2] if len(sys.argv) > 2 else None
    print(run(u, osint_json=osint))
