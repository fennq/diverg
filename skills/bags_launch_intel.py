"""
Bags Launch Intelligence — AI-Powered Creator Forensics & Token Due Diligence.

Orchestrator skill that takes a Bags.fm mint address and runs the full
investigation pipeline:

1. Creator forensics (wallet history, identity, funding source)
2. Previous launch behavior (serial launcher detection)
3. Fee behavior analysis (extraction patterns, timing, concentration)
4. Bundle analysis (holder coordination, same-funder clusters)
5. Cross-chain context (bridge/mixer signals)
6. Liquidity & pool state
7. Composite risk scoring with evidence

Returns a structured forensic report answering:
"Should I trust this creator and buy this token?"

Requires: BAGS_API_KEY, HELIUS_API_KEY (env).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Ensure investigation modules are importable
_ROOT = Path(__file__).resolve().parent.parent
_INV_DIR = _ROOT / "investigation"
for p in (str(_ROOT), str(_INV_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from bags_client import (
    get_bags_pool_by_token_mint,
    get_dexscreener_order_availability,
    get_token_creators,
    get_token_launch_feed,
    get_token_lifetime_fees,
    find_mint_in_token_launch_feed,
    is_configured as bags_configured,
    parse_bags_pool,
    parse_dexscreener_order_availability,
    parse_lifetime_fees,
    parse_token_creators,
)
from bags_creator_intel import run_creator_intel
from bags_fee_behavior import run_fee_behavior_analysis


# Optional: bundle analysis (requires Helius)
try:
    from solana_bundle import run_bundle_snapshot
    from solana_bundle_signals import compute_coordination_bundle
    BUNDLE_AVAILABLE = True
except ImportError:
    BUNDLE_AVAILABLE = False
    run_bundle_snapshot = None

try:
    from cross_chain_hints import get_cross_chain_candidates, summarize_cross_chain_payload
    CROSS_CHAIN_AVAILABLE = True
except ImportError:
    CROSS_CHAIN_AVAILABLE = False

_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# ---------------------------------------------------------------------------
# Composite risk scoring
# ---------------------------------------------------------------------------

# Weight allocations (sum = 100)
WEIGHT_CREATOR = 25
WEIGHT_FEE_BEHAVIOR = 25
WEIGHT_BUNDLE = 30
WEIGHT_LIQUIDITY = 10
WEIGHT_CROSS_CHAIN = 10


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def compute_composite_score(
    creator_intel: dict[str, Any],
    fee_behavior: dict[str, Any],
    bundle_result: Optional[dict[str, Any]],
    pool_info: dict[str, Any],
    cross_chain: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compute a composite risk score (0-100) from all intelligence sources.
    Higher = more risk.
    """
    scores: dict[str, float] = {}
    flags: list[str] = []
    evidence: list[dict[str, str]] = []

    # --- Creator risk ---
    creator_score = 0.0
    creator_flags = creator_intel.get("flags") or []
    if "serial_launcher" in creator_flags:
        creator_score += 40
        evidence.append({
            "signal": "serial_launcher",
            "detail": f"Creator has {creator_intel.get('previous_launches', {}).get('total_previous_launches', 0)} previous launches",
            "severity": "High",
        })
    elif "repeat_launcher" in creator_flags:
        creator_score += 15
        evidence.append({
            "signal": "repeat_launcher",
            "detail": "Creator has launched tokens before",
            "severity": "Medium",
        })
    if "many_admin_tokens" in creator_flags:
        creator_score += 25
        evidence.append({
            "signal": "many_admin_tokens",
            "detail": "Creator is admin for many tokens",
            "severity": "High",
        })
    if "shared_funding_source" in creator_flags:
        creator_score += 20
        evidence.append({
            "signal": "shared_funding_source",
            "detail": "Multiple creator wallets share the same funding source",
            "severity": "Medium",
        })
    if "no_creator_wallets_found" in creator_flags:
        creator_score += 30
        evidence.append({
            "signal": "no_creator_wallets",
            "detail": "No creator wallets could be identified",
            "severity": "High",
        })
    creator_score = min(100, creator_score)
    scores["creator"] = creator_score
    flags.extend(creator_flags)

    # --- Fee behavior risk ---
    fee_score = _safe_float(fee_behavior.get("fee_risk_score"))
    fee_flags = fee_behavior.get("combined_flags") or []
    if "aggressive_creator_extraction" in fee_flags:
        evidence.append({
            "signal": "aggressive_creator_extraction",
            "detail": "Creator claims >80% of all fees",
            "severity": "High",
        })
    if "whale_dominated_claims" in fee_flags:
        evidence.append({
            "signal": "whale_dominated_claims",
            "detail": "Single claimer dominates >60% of fees",
            "severity": "High",
        })
    if "front_loaded_claims" in fee_flags:
        evidence.append({
            "signal": "front_loaded_claims",
            "detail": "Most fee claims concentrated in recent window",
            "severity": "Medium",
        })
    scores["fee_behavior"] = min(100, fee_score)
    flags.extend(fee_flags)

    # --- Bundle / coordination risk ---
    bundle_score = 0.0
    if bundle_result and isinstance(bundle_result, dict) and bundle_result.get("ok"):
        bs = bundle_result.get("bundle_signals") or {}
        coord = _safe_float(bs.get("coordination_score"))
        bundle_score = coord
        if coord >= 50:
            evidence.append({
                "signal": "high_coordination",
                "detail": f"Bundle coordination score: {coord}/100",
                "severity": "Critical",
            })
        elif coord >= 28:
            evidence.append({
                "signal": "moderate_coordination",
                "detail": f"Bundle coordination score: {coord}/100",
                "severity": "Medium",
            })
        # Check for specific bundle signals
        reasons = bs.get("coordination_reasons") or []
        if any("cex" in str(r).lower() for r in reasons):
            flags.append("cex_funded_holders")
        if any("mixer" in str(r).lower() for r in reasons):
            flags.append("mixer_funded_holders")
    scores["bundle"] = min(100, bundle_score)

    # --- Liquidity risk ---
    liquidity_score = 0.0
    liq_stage = pool_info.get("liquidity_stage", "unknown")
    if liq_stage == "unknown":
        liquidity_score = 40
        flags.append("unknown_liquidity")
        evidence.append({
            "signal": "unknown_liquidity",
            "detail": "No Bags pool found for this token",
            "severity": "Medium",
        })
    elif liq_stage == "dbc_only":
        liquidity_score = 15
        flags.append("dbc_only_no_migration")
    scores["liquidity"] = min(100, liquidity_score)

    # --- Cross-chain risk ---
    cross_chain_score = 0.0
    if cross_chain and isinstance(cross_chain, dict):
        candidates = cross_chain.get("candidates") or []
        if candidates:
            # Cross-chain presence isn't inherently risky, but note it
            cross_chain_score = 5
            flags.append("cross_chain_presence")
    scores["cross_chain"] = min(100, cross_chain_score)

    # --- Weighted composite ---
    composite = (
        scores["creator"] * WEIGHT_CREATOR / 100
        + scores["fee_behavior"] * WEIGHT_FEE_BEHAVIOR / 100
        + scores["bundle"] * WEIGHT_BUNDLE / 100
        + scores["liquidity"] * WEIGHT_LIQUIDITY / 100
        + scores["cross_chain"] * WEIGHT_CROSS_CHAIN / 100
    )
    composite = min(100, max(0, round(composite, 2)))

    # Verdict
    if composite >= 60:
        verdict = "High Risk"
    elif composite >= 35:
        verdict = "Moderate Risk"
    elif composite >= 15:
        verdict = "Low Risk"
    else:
        verdict = "Minimal Risk"

    # Deduplicate flags
    flags = list(dict.fromkeys(flags))

    return {
        "composite_score": composite,
        "verdict": verdict,
        "component_scores": scores,
        "weights": {
            "creator": WEIGHT_CREATOR,
            "fee_behavior": WEIGHT_FEE_BEHAVIOR,
            "bundle": WEIGHT_BUNDLE,
            "liquidity": WEIGHT_LIQUIDITY,
            "cross_chain": WEIGHT_CROSS_CHAIN,
        },
        "flags": flags,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Generate findings in canonical format
# ---------------------------------------------------------------------------

def _evidence_to_findings(evidence: list[dict[str, str]], token_mint: str) -> list[dict[str, Any]]:
    """Convert evidence list to Diverg-standard finding dicts."""
    severity_map = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
    findings: list[dict[str, Any]] = []
    for ev in evidence:
        sev = severity_map.get(ev.get("severity", ""), "Info")
        findings.append({
            "title": f"Bags Intel: {ev.get('signal', 'unknown')}",
            "severity": sev,
            "category": "Blockchain / Bags Launch Intel",
            "evidence": ev.get("detail", ""),
            "impact": f"Risk signal detected for token {token_mint}",
            "remediation": "Review the full Bags Intel report before trading.",
            "confidence": "high" if sev in ("Critical", "High") else "medium",
            "source": "bags_launch_intel",
            "proof": f"mint:{token_mint}",
            "verified": True,
            "url": f"https://bags.fm/token/{token_mint}",
        })
    return findings


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run(
    target_url: str = "",
    scan_type: str = "full",
    token_mint: str = "",
    **kwargs,
) -> str:
    """
    Run full Bags Launch Intelligence investigation.

    Args:
        target_url: Optional URL (bags.fm token page or raw mint).
        scan_type: "full" or "quick".
        token_mint: SPL mint address to investigate.

    Returns:
        JSON string with the full forensic report.
    """
    start = time.time()

    # Resolve mint from input
    mint = (token_mint or "").strip()
    if not mint and target_url:
        # Try to extract mint from URL
        url_clean = target_url.strip()
        # Pattern: bags.fm/token/MINT or just a raw address
        match = re.search(r"([1-9A-HJ-NP-Za-km-z]{32,44})", url_clean)
        if match:
            mint = match.group(1)

    if not mint or not _ADDR_RE.match(mint):
        return json.dumps({
            "error": "Valid SPL mint address required",
            "token_mint": mint,
        })

    report: dict[str, Any] = {
        "token_mint": mint,
        "investigation_type": "bags_launch_intel",
        "scan_type": scan_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "creator_intel": None,
        "fee_behavior": None,
        "bundle_analysis": None,
        "pool_info": None,
        "launch_feed_match": None,
        "dexscreener": None,
        "cross_chain": None,
        "risk_assessment": None,
        "findings": [],
        "errors": [],
    }

    # --- 1. Creator Intel ---
    try:
        creator_intel = run_creator_intel(mint)
        report["creator_intel"] = creator_intel
    except Exception as e:
        report["errors"].append(f"creator_intel: {e}")
        creator_intel = {"flags": [], "creators": None}

    # --- 2. Fee Behavior ---
    try:
        fee_behavior = run_fee_behavior_analysis(mint)
        report["fee_behavior"] = fee_behavior
    except Exception as e:
        report["errors"].append(f"fee_behavior: {e}")
        fee_behavior = {"fee_risk_score": 0, "combined_flags": []}

    # --- 3. Bundle Analysis (optional, requires Helius) ---
    bundle_result = None
    if BUNDLE_AVAILABLE:
        try:
            bundle_result = run_bundle_snapshot(
                mint,
                max_holders=80,
                max_funded_by_lookups=80,
            )
            report["bundle_analysis"] = _slim_bundle(bundle_result)
        except Exception as e:
            report["errors"].append(f"bundle_analysis: {e}")

    # --- 4. Pool / Liquidity Info ---
    pool_info: dict[str, Any] = {}
    try:
        pool_raw = get_bags_pool_by_token_mint(mint)
        pool_info = parse_bags_pool(pool_raw, mint)
        report["pool_info"] = pool_info
    except Exception as e:
        report["errors"].append(f"pool_info: {e}")

    # --- 5. Launch Feed Match ---
    try:
        feed_raw = get_token_launch_feed()
        feed_match = find_mint_in_token_launch_feed(feed_raw, mint)
        report["launch_feed_match"] = feed_match
    except Exception as e:
        report["errors"].append(f"launch_feed: {e}")

    # --- 6. Dexscreener Availability ---
    try:
        dex_raw = get_dexscreener_order_availability(mint)
        dex_parsed = parse_dexscreener_order_availability(dex_raw)
        report["dexscreener"] = dex_parsed
    except Exception as e:
        report["errors"].append(f"dexscreener: {e}")

    # --- 7. Cross-Chain Context ---
    cross_chain_summary = None
    if CROSS_CHAIN_AVAILABLE:
        try:
            cc_raw = get_cross_chain_candidates(mint)
            if cc_raw:
                cross_chain_summary = summarize_cross_chain_payload(cc_raw)
                report["cross_chain"] = cross_chain_summary
        except Exception as e:
            report["errors"].append(f"cross_chain: {e}")

    # --- 8. Composite Risk Assessment ---
    try:
        risk = compute_composite_score(
            creator_intel,
            fee_behavior,
            bundle_result,
            pool_info,
            cross_chain_summary,
        )
        report["risk_assessment"] = risk
        report["findings"] = _evidence_to_findings(risk.get("evidence", []), mint)
    except Exception as e:
        report["errors"].append(f"risk_scoring: {e}")

    report["duration_sec"] = round(time.time() - start, 2)
    return json.dumps(report, default=str)


def _slim_bundle(bundle: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return a slimmed version of bundle output for the report (avoid huge payloads)."""
    if not bundle or not isinstance(bundle, dict):
        return bundle
    slim = {
        "ok": bundle.get("ok"),
        "mint": bundle.get("mint"),
        "token": bundle.get("token"),
        "holder_count": len(bundle.get("holders") or []),
        "cluster_count": len(bundle.get("clusters") or {}),
        "bundle_signals": bundle.get("bundle_signals"),
        "cross_chain_bundle": bundle.get("cross_chain_bundle"),
    }
    # Include top 10 holders only
    holders = bundle.get("holders") or []
    slim["top_holders"] = holders[:10]
    # Include top 5 clusters by wallet count
    clusters = bundle.get("clusters") or {}
    sorted_clusters = sorted(
        clusters.items(),
        key=lambda kv: kv[1].get("count", 0) if isinstance(kv[1], dict) else 0,
        reverse=True,
    )[:5]
    slim["top_clusters"] = {k: v for k, v in sorted_clusters}
    return slim


# ---------------------------------------------------------------------------
# Standalone entry point (for skill runner / CLI)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys

    mint_arg = _sys.argv[1] if len(_sys.argv) > 1 else ""
    if not mint_arg:
        print("Usage: python bags_launch_intel.py <mint_address>")
        _sys.exit(1)
    result = run(token_mint=mint_arg)
    print(result)
