"""
Fee behavior analysis for Bags.fm token launches.

Analyzes fee-share claim patterns to detect:
- Aggressive extraction (large claims shortly after launch)
- Abnormal timing patterns (front-loaded claiming)
- Whale concentration in fee claims
- Creator vs non-creator claim ratios

Produces structured risk signals for the bags_launch_intel orchestrator.

Requires: BAGS_API_KEY (env).
"""
from __future__ import annotations

import time
from typing import Any, Optional

from bags_client import (
    get_token_claim_events,
    get_token_claim_stats,
    get_token_lifetime_fees,
    is_configured as bags_configured,
    parse_lifetime_fees,
    parse_token_claim_stats,
    summarize_claim_events,
    compare_claim_windows,
    _unwrap_response,
)

# ---------------------------------------------------------------------------
# Thresholds (tuneable)
# ---------------------------------------------------------------------------

# Creator claims > this share of total fees = aggressive extraction
AGGRESSIVE_CREATOR_SHARE = 0.80
# Top-1 claimer > this share = whale-dominated
WHALE_SHARE_THRESHOLD = 0.60
# Herfindahl index > this = highly concentrated
HHI_CONCENTRATED = 0.35
# If most claims happen in first N hours, flag as front-loaded
FRONT_LOAD_HOURS = 24
FRONT_LOAD_SHARE = 0.70
# Minimum total fees (SOL) to consider meaningful
MIN_FEES_SOL = 0.01


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Core fee behavior analysis
# ---------------------------------------------------------------------------

def analyze_claim_stats(token_mint: str) -> dict[str, Any]:
    """
    Analyze per-claimer claim statistics for a token.
    Returns concentration metrics, creator share, and risk flags.
    """
    result: dict[str, Any] = {
        "token_mint": token_mint,
        "claim_stats": None,
        "flags": [],
        "risk_score_component": 0,
    }

    if not bags_configured():
        result["error"] = "BAGS_API_KEY not configured"
        return result

    raw = get_token_claim_stats(token_mint)
    parsed = parse_token_claim_stats(raw)
    result["claim_stats"] = parsed

    total_sol = _safe_float(parsed.get("total_claimed_sol"))
    if total_sol < MIN_FEES_SOL:
        result["flags"].append("minimal_fees")
        return result

    # Creator share analysis
    creator_share = _safe_float(parsed.get("creator_share_of_total"))
    if creator_share >= AGGRESSIVE_CREATOR_SHARE:
        result["flags"].append("aggressive_creator_extraction")
        result["risk_score_component"] += 20

    # Top-1 whale concentration
    top1_share = _safe_float(parsed.get("top1_share_of_total"))
    if top1_share >= WHALE_SHARE_THRESHOLD:
        result["flags"].append("whale_dominated_claims")
        result["risk_score_component"] += 15

    # Herfindahl concentration index
    hhi = _safe_float(parsed.get("fee_herfindahl_index"))
    if hhi >= HHI_CONCENTRATED:
        result["flags"].append("highly_concentrated_fees")
        result["risk_score_component"] += 10

    # Distribution label from bags_client
    dist_label = parsed.get("distribution_label")
    if dist_label == "highly_concentrated":
        result["risk_score_component"] += 5

    # Few claimers
    claimers_count = _safe_int(parsed.get("claimers_count"))
    if 0 < claimers_count <= 2 and total_sol >= 1.0:
        result["flags"].append("very_few_claimers")
        result["risk_score_component"] += 10

    return result


def analyze_claim_timing(token_mint: str) -> dict[str, Any]:
    """
    Analyze the timing of fee claims to detect front-loading or rushed extraction.
    Compares recent (7d) vs longer (30d) claim activity windows.
    """
    result: dict[str, Any] = {
        "token_mint": token_mint,
        "timing_analysis": None,
        "claim_events_sample": None,
        "flags": [],
        "risk_score_component": 0,
    }

    if not bags_configured():
        result["error"] = "BAGS_API_KEY not configured"
        return result

    now = int(time.time())
    seven_days_ago = now - (7 * 86400)
    thirty_days_ago = now - (30 * 86400)

    # Fetch recent claim events (first page)
    events_raw = get_token_claim_events(token_mint, mode="offset", limit=100, offset=0)
    events_summary = summarize_claim_events(events_raw)
    result["claim_events_sample"] = events_summary

    # Time-windowed comparisons
    events_7d_raw = get_token_claim_events(
        token_mint, mode="time", from_ts=seven_days_ago, to_ts=now
    )
    events_30d_raw = get_token_claim_events(
        token_mint, mode="time", from_ts=thirty_days_ago, to_ts=now
    )

    summary_7d = summarize_claim_events(events_7d_raw)
    summary_30d = summarize_claim_events(events_30d_raw)
    comparison = compare_claim_windows(summary_7d, summary_30d)
    result["timing_analysis"] = {
        "summary_7d": summary_7d,
        "summary_30d": summary_30d,
        "comparison": comparison,
    }

    # Detect front-loading: if >70% of 30d claims happened in 7d window
    claimed_ratio = _safe_float(comparison.get("claimed_ratio_7d_to_30d"))
    if claimed_ratio >= FRONT_LOAD_SHARE:
        result["flags"].append("front_loaded_claims")
        result["risk_score_component"] += 10

    # High recent activity (could indicate dump preparation)
    events_trend = comparison.get("events_trend")
    if events_trend == "high_recent_activity":
        result["flags"].append("high_recent_claim_activity")
        result["risk_score_component"] += 5

    # Creator claims dominating recent window
    creator_claims_7d = _safe_int(summary_7d.get("creator_claims_lamports"))
    total_7d = _safe_int(summary_7d.get("total_claimed_lamports"))
    if total_7d > 0 and creator_claims_7d / total_7d >= AGGRESSIVE_CREATOR_SHARE:
        result["flags"].append("creator_dominates_recent_claims")
        result["risk_score_component"] += 10

    return result


def analyze_lifetime_fees(token_mint: str) -> dict[str, Any]:
    """
    Analyze total lifetime fee extraction for context.
    """
    result: dict[str, Any] = {
        "token_mint": token_mint,
        "lifetime_fees": None,
        "flags": [],
    }

    if not bags_configured():
        result["error"] = "BAGS_API_KEY not configured"
        return result

    raw = get_token_lifetime_fees(token_mint)
    parsed = parse_lifetime_fees(raw)
    result["lifetime_fees"] = parsed

    sol = _safe_float(parsed.get("sol"))
    if sol >= 100:
        result["flags"].append("very_high_total_fees")
    elif sol >= 10:
        result["flags"].append("high_total_fees")

    return result


# ---------------------------------------------------------------------------
# Aggregate fee behavior report
# ---------------------------------------------------------------------------

def run_fee_behavior_analysis(token_mint: str) -> dict[str, Any]:
    """
    Full fee behavior analysis for a Bags token mint.

    Combines:
    1. Claim statistics (concentration, creator share)
    2. Claim timing (front-loading, recent activity)
    3. Lifetime fee totals

    Returns structured analysis with flags and risk score component.
    """
    report: dict[str, Any] = {
        "token_mint": token_mint,
        "claim_stats_analysis": None,
        "timing_analysis": None,
        "lifetime_fees_analysis": None,
        "combined_flags": [],
        "fee_risk_score": 0,
    }

    # 1. Claim stats
    stats = analyze_claim_stats(token_mint)
    report["claim_stats_analysis"] = stats
    report["combined_flags"].extend(stats.get("flags", []))
    report["fee_risk_score"] += stats.get("risk_score_component", 0)

    # 2. Timing
    timing = analyze_claim_timing(token_mint)
    report["timing_analysis"] = timing
    report["combined_flags"].extend(timing.get("flags", []))
    report["fee_risk_score"] += timing.get("risk_score_component", 0)

    # 3. Lifetime fees
    lifetime = analyze_lifetime_fees(token_mint)
    report["lifetime_fees_analysis"] = lifetime
    report["combined_flags"].extend(lifetime.get("flags", []))

    # Cap score at 100
    report["fee_risk_score"] = min(100, report["fee_risk_score"])

    # Deduplicate flags
    report["combined_flags"] = list(dict.fromkeys(report["combined_flags"]))

    return report
