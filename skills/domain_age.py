"""
Domain age risk signal.

Implements a lightweight, structured risk signal based on WHOIS creation date.
Returns a canonical `findings` list so it plugs into the existing Diverg scoring
and API response pipeline (aggregate_findings → /api/scan).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


RUN_BUDGET_SEC = 20  # keep extremely fast; phase2 context skill


@dataclass
class DomainAgeSignal:
    signal: str
    value: int | None  # days since creation
    risk: str  # high | medium | low | unknown
    reason: str
    created_date: str | None = None


@dataclass
class DomainAgeReport:
    target_url: str
    domain: str
    signals: list[DomainAgeSignal] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _extract_domain(target_url: str) -> str:
    t = (target_url or "").strip()
    t = t.replace("https://", "").replace("http://", "")
    t = t.split("/")[0].split(":")[0].strip().lower()
    return t


def _parse_any_datetime(raw: Any) -> datetime | None:
    """
    Best-effort parse for python-whois values and JSON-serialized variants.

    Handles:
    - datetime / date objects
    - list of datetimes / strings
    - ISO-ish strings and common WHOIS string formats
    """
    if raw is None:
        return None
    if isinstance(raw, list) and raw:
        # prefer earliest creation date if list contains multiple
        parsed = [_parse_any_datetime(x) for x in raw]
        parsed = [p for p in parsed if p is not None]
        return min(parsed) if parsed else None

    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc) if raw.tzinfo else raw.replace(tzinfo=timezone.utc)

    # date without time (python-whois sometimes returns date)
    try:
        import datetime as _dt

        if isinstance(raw, _dt.date) and not isinstance(raw, _dt.datetime):
            return datetime(raw.year, raw.month, raw.day, tzinfo=timezone.utc)
    except Exception:
        pass

    s = str(raw).strip()
    if not s:
        return None
    # Normalize common separators
    s = s.replace("/", "-").replace(".", "-")

    # Try ISO 8601 first (including 'Z')
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    # Common WHOIS formats (best-effort)
    fmts = (
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%d-%b-%Y",
        "%d-%b-%Y %H:%M:%S %Z",
    )
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _compute_signal(domain: str, *, osint_json: str | None = None) -> DomainAgeSignal:
    created_raw = None
    created_dt: datetime | None = None

    # Prefer OSINT context (already fetched in phase1) to avoid duplicate WHOIS requests
    if osint_json and osint_json.strip():
        try:
            data = json.loads(osint_json)
            whois_info = data.get("whois_info") if isinstance(data, dict) else None
            if isinstance(whois_info, dict):
                created_raw = whois_info.get("creation_date")
                created_dt = _parse_any_datetime(created_raw)
        except Exception:
            # fall through to direct WHOIS
            created_dt = None

    # Fallback: direct WHOIS lookup
    if created_dt is None:
        try:
            import whois  # type: ignore

            w = whois.whois(domain)
            created_raw = getattr(w, "creation_date", None)
            created_dt = _parse_any_datetime(created_raw)
        except Exception as exc:
            return DomainAgeSignal(
                signal="domain_age",
                value=None,
                risk="unknown",
                reason=f"WHOIS lookup failed: {type(exc).__name__}: {exc}",
                created_date=None,
            )

    if created_dt is None:
        return DomainAgeSignal(
            signal="domain_age",
            value=None,
            risk="unknown",
            reason="Domain creation date unavailable from WHOIS.",
            created_date=None,
        )

    now = datetime.now(timezone.utc)
    age_days = int((now - created_dt).total_seconds() // 86400)

    if age_days < 30:
        risk = "high"
        reason = f"Domain registered {age_days} day(s) ago."
    elif age_days < 90:
        risk = "medium"
        reason = f"Domain registered {age_days} day(s) ago."
    else:
        risk = "low"
        reason = f"Domain registered {age_days} day(s) ago."

    return DomainAgeSignal(
        signal="domain_age",
        value=age_days,
        risk=risk,
        reason=reason,
        created_date=created_dt.date().isoformat(),
    )


def _signal_to_finding(target_url: str, sig: DomainAgeSignal) -> dict:
    # Map risk level into the existing severity scheme.
    if sig.risk == "high":
        severity = "High"
        finding_type = "vulnerability"
    elif sig.risk == "medium":
        severity = "Medium"
        finding_type = "vulnerability"
    elif sig.risk == "low":
        severity = "Info"
        finding_type = "informational"
    else:
        severity = "Info"
        finding_type = "informational"

    value_str = "unknown" if sig.value is None else f"{sig.value} days"
    created_str = sig.created_date or "unknown"
    return {
        "title": f"Domain age signal: {value_str}",
        "severity": severity,
        "url": target_url,
        "category": "Domain and Reputation",
        "evidence": f"WHOIS creation_date={created_str}; computed_age_days={sig.value if sig.value is not None else 'unknown'}",
        "impact": (
            "Newly registered domains are more commonly associated with phishing and short-lived fraud campaigns. "
            "This signal is contextual and should be weighed alongside technical findings."
        ),
        "remediation": (
            "If this is a new domain, increase verification and monitoring (brand protection, DNS/registrar controls, "
            "certificate transparency alerts). If unexpected, investigate domain ownership and deployment provenance."
        ),
        "finding_type": finding_type,
        "context": sig.reason,
        "confidence": "medium" if sig.value is not None else "low",
        "verified": False,
    }


def run(target_url: str, scan_type: str = "full", osint_json: str | None = None) -> str:
    """
    Entry point for the Diverg skill runner.

    Returns JSON with a `findings` list (canonical shape expected by orchestrator aggregation).
    """
    run_start = time.time()
    domain = _extract_domain(target_url)
    report = DomainAgeReport(target_url=target_url, domain=domain)

    if not domain:
        report.errors.append("No domain extracted from target_url.")
        return json.dumps(asdict(report), indent=2)

    if (time.time() - run_start) > RUN_BUDGET_SEC:
        report.errors.append("Time budget exceeded before WHOIS check.")
        return json.dumps(asdict(report), indent=2)

    sig = _compute_signal(domain, osint_json=osint_json)
    report.signals.append(sig)
    report.findings.append(_signal_to_finding(target_url, sig))
    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    import sys

    u = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(u))

