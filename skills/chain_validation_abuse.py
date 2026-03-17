"""
Chain / batch validation abuse — Injective-style checks for crypto and high-value apps:
batch vs single path validation gaps, account/subaccount ID substitution, and parameter trust.

Reference: content/injective-style-exploit-routes.md (100+ routes).
Run when target is crypto/DeFi (detected automatically) or when goal includes "batch", "crypto audit", "chain validation".
Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent))

try:
    import requests
except ImportError:
    requests = None

SESSION = requests.Session() if requests else None
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; Diverg/1.0)"})
TIMEOUT = 6
RUN_BUDGET_SEC = 45

# Batch-like path suffixes to probe (single vs batch comparison)
BATCH_PATH_HINTS = [
    "/batch", "/bulk", "/bulk-create", "/multi", "/batch/create",
    "/orders/batch", "/orders/bulk", "/transfers/batch", "/batch/orders",
    "/api/batch", "/api/v1/batch", "/api/bulk", "/api/orders/batch",
    "/submit/batch", "/batch/submit", "/batchUpdate", "/batch_update",
]
# Parameters that may indicate account/subaccount (IDOR / Injective-style)
ACCOUNT_PARAM_NAMES = [
    "subaccount_id", "subaccountId", "subaccount", "account_id", "accountId",
    "wallet_id", "wallet_address", "address", "owner", "user_id", "userId",
    "beneficiary", "recipient", "from_address", "sender", "delegator",
    "position_id", "order_id", "withdrawal_id",
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
class ChainValidationReport:
    target_url: str
    is_crypto: bool
    crypto_confidence: float
    findings: list[Finding] = field(default_factory=list)
    recommended_routes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def run(
    target_url: str,
    scan_type: str = "full",
    client_surface_json: str | None = None,
    api_results_json: str | None = None,
) -> str:
    """
    Run chain/batch validation abuse checks. Returns JSON string of ChainValidationReport.
    """
    start = time.time()
    base = target_url if target_url.startswith("http") else "https://" + target_url
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Crypto detection
    try:
        from crypto_site_detector import detect_from_url, detect_from_content
        det = detect_from_url(base, fetch=True)
    except Exception as e:
        det = type("R", (), {"is_crypto": False, "confidence": 0.0, "signals": [], "suggested_scan_routes": []})()

    findings: list[Finding] = []
    errors: list[str] = []
    recommended_routes: list[str] = []

    if getattr(det, "is_crypto", False):
        confidence = getattr(det, "confidence", 0)
        recommended_routes = getattr(det, "suggested_scan_routes", []) or [
            "batch_vs_single_validation",
            "account_subaccount_id_substitution",
            "parameter_trust_body_header",
        ]
        findings.append(Finding(
            title="Target classified as crypto/DeFi — run Injective-style validation checks",
            severity="Info",
            url=base,
            category="Chain / Batch Validation",
            evidence=f"Crypto confidence: {confidence}. Signals: {getattr(det, 'signals', [])[:8]}.",
            impact="Batch vs single path and account-id substitution checks are recommended (see content/injective-style-exploit-routes.md).",
            remediation="Compare validation on batch vs single endpoints; verify account_id/subaccount_id are not trusted from request body without signer check.",
        ))
    else:
        findings.append(Finding(
            title="Site not classified as crypto/DeFi — generic batch/IDOR checks still applied",
            severity="Info",
            url=base,
            category="Chain / Batch Validation",
            evidence="Crypto detection confidence below threshold or no crypto signals. This skill ran due to scope=crypto or goal (e.g. batch validation, crypto audit).",
            impact="Batch-like endpoints and account_id/subaccount_id in request body are still checked; findings apply to any API with batch or account parameters.",
            remediation="If the site is crypto-related, use scope=crypto or goal 'crypto audit' for full Injective-style checks.",
        ))

    if not SESSION or not requests:
        report = ChainValidationReport(
            target_url=base,
            is_crypto=getattr(det, "is_crypto", False),
            crypto_confidence=getattr(det, "confidence", 0.0),
            findings=findings,
            recommended_routes=recommended_routes,
            errors=errors + ["requests not available"],
        )
        return json.dumps(asdict(report), indent=2)

    # Collect candidate endpoints from client_surface or api_results
    endpoints_to_probe: list[str] = []
    if client_surface_json:
        try:
            data = json.loads(client_surface_json)
            for ep in data.get("extracted_endpoints", []) or []:
                if isinstance(ep, str) and ep.startswith("/"):
                    endpoints_to_probe.append(urljoin(origin, ep))
            for key in ("findings", "snippets"):
                for item in data.get(key, []) or []:
                    if isinstance(item, dict):
                        u = item.get("url") or item.get("endpoint") or item.get("path")
                        if u and isinstance(u, str) and "/api" in u:
                            endpoints_to_probe.append(u if u.startswith("http") else urljoin(origin, u))
        except Exception:
            pass
    if api_results_json:
        try:
            data = json.loads(api_results_json)
            for ep in data.get("endpoints_found", []) or []:
                if isinstance(ep, dict):
                    u = ep.get("url")
                    if u:
                        endpoints_to_probe.append(u)
        except Exception:
            pass

    # Add batch-like paths from base
    for path in BATCH_PATH_HINTS:
        if _over_budget(start):
            break
        url = urljoin(origin, path)
        if url not in endpoints_to_probe:
            endpoints_to_probe.append(url)

    # Probe batch-like endpoints (existence + 405/401/400 vs 200)
    seen_batch: set[str] = set()
    for url in endpoints_to_probe[:30]:
        if _over_budget(start):
            break
        path = urlparse(url).path.lower()
        if not any(h in path for h in ["batch", "bulk", "multi", "order"]):
            continue
        try:
            r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 201, 400, 401, 403, 405):
                key = (url, r.status_code)
                if key not in seen_batch:
                    seen_batch.add(key)
                    if r.status_code in (200, 201):
                        findings.append(Finding(
                            title="Batch-like endpoint responds to GET — verify validation vs single-path",
                            severity="Low",
                            url=url,
                            category="Chain / Batch Validation",
                            evidence=f"GET {url} returned {r.status_code}. Compare with single-create path (see injective-style-exploit-routes.md routes 1–10).",
                            impact="If batch path skips ownership/validation that single path has, account drain possible.",
                            remediation="Ensure batch handler calls same ValidateBasic/ownership checks as single-operation handler.",
                        ))
        except Exception as e:
            errors.append(str(e))

    # Check for account/subaccount params in JS or API docs (heuristic)
    try:
        r = SESSION.get(base, timeout=TIMEOUT)
        if r.ok and _over_budget(start) is False:
            text = r.text[:150000]
            for param in ACCOUNT_PARAM_NAMES:
                if re.search(rf"\b{re.escape(param)}\s*[:=]|\"{param}\"|\'{param}\'", text, re.I):
                    findings.append(Finding(
                        title=f"Request parameter '{param}' found — ensure not trusted without signer/session check",
                        severity="Info",
                        url=base,
                        category="Chain / Batch Validation",
                        evidence=f"Parameter '{param}' appears in page/JS. (Injective-style: subaccount_id was trusted in batch path.)",
                        impact="If server uses client-supplied account/subaccount without verifying ownership, IDOR or account drain.",
                        remediation="Validate account_id/subaccount_id against authenticated signer or session in every path (single and batch).",
                    ))
                    break
    except Exception as e:
        errors.append(str(e))

    report = ChainValidationReport(
        target_url=base,
        is_crypto=getattr(det, "is_crypto", False),
        crypto_confidence=getattr(det, "confidence", 0.0),
        findings=findings,
        recommended_routes=recommended_routes,
        errors=errors[:10],
    )
    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(run(url, scan_type="full"))
