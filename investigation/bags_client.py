"""
Bags API client for blockchain investigations (Section 1: core token intelligence).

Features:
- token creators (v3)
- token lifetime fees
- token claim events (offset/time modes)

Auth: set BAGS_API_KEY in environment.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests

BAGS_API_KEY = os.environ.get("BAGS_API_KEY", "").strip()
BAGS_BASE_URL = os.environ.get("BAGS_BASE_URL", "https://public-api-v2.bags.fm/api/v1").rstrip("/")


def is_configured() -> bool:
    """True when BAGS_API_KEY is configured."""
    return bool(BAGS_API_KEY)


def _get(path: str, params: Optional[dict[str, Any]] = None, timeout: int = 30) -> Optional[dict[str, Any]]:
    if not BAGS_API_KEY:
        return None
    try:
        r = requests.get(
            f"{BAGS_BASE_URL}{path}",
            headers={"x-api-key": BAGS_API_KEY},
            params=params or {},
            timeout=timeout,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        payload = r.json()
        if isinstance(payload, dict) and payload.get("success") is False:
            return payload
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _unwrap_response(payload: Optional[dict[str, Any]]) -> Any:
    """
    Return Bags `response` payload when available.
    Falls back to the raw payload.
    """
    if not isinstance(payload, dict):
        return None
    if "response" in payload:
        return payload.get("response")
    return payload


def get_token_creators(token_mint: str) -> Optional[dict[str, Any]]:
    """Get creators/deployers for a token launch."""
    return _get("/token-launch/creator/v3", {"tokenMint": token_mint})


def get_token_lifetime_fees(token_mint: str) -> Optional[dict[str, Any]]:
    """Get total lifetime fees (lamports) for token launch."""
    return _get("/token-launch/lifetime-fees", {"tokenMint": token_mint})


def get_token_claim_events(
    token_mint: str,
    *,
    mode: str = "offset",
    limit: int = 100,
    offset: int = 0,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    """
    Get claim events for token launch.

    mode='offset' uses limit/offset.
    mode='time' uses from_ts/to_ts.
    """
    params: dict[str, Any] = {"tokenMint": token_mint}
    if mode == "time":
        params["mode"] = "time"
        if from_ts is not None:
            params["from"] = from_ts
        if to_ts is not None:
            params["to"] = to_ts
    else:
        params["mode"] = "offset"
        params["limit"] = max(1, min(int(limit), 100))
        params["offset"] = max(0, int(offset))
    return _get("/fee-share/token/claim-events", params)


def parse_token_creators(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return normalized creator data for report usage."""
    creators = _unwrap_response(payload)
    if not isinstance(creators, list):
        creators = []
    wallets = [c.get("wallet") for c in creators if isinstance(c, dict) and c.get("wallet")]
    handles = []
    for c in creators:
        if not isinstance(c, dict):
            continue
        h = c.get("providerUsername") or c.get("twitterUsername") or c.get("bagsUsername")
        if h:
            handles.append(h)
    return {
        "count": len(creators),
        "wallets": wallets,
        "handles": handles,
        "creators": creators,
    }


def parse_lifetime_fees(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return normalized lifetime fee values (lamports + SOL)."""
    raw = _unwrap_response(payload)
    lamports = None
    if isinstance(raw, str) and raw.isdigit():
        lamports = int(raw)
    elif isinstance(raw, (int, float)):
        lamports = int(raw)
    sol = round(lamports / 1e9, 9) if lamports is not None else None
    return {
        "lamports": lamports,
        "sol": sol,
        "raw": raw,
    }


def summarize_claim_events(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Build aggregate metrics from claim events response."""
    resp = _unwrap_response(payload)
    events = []
    if isinstance(resp, dict) and isinstance(resp.get("events"), list):
        events = resp.get("events") or []
    elif isinstance(resp, list):
        events = resp
    total_lamports = 0
    unique_wallets: set[str] = set()
    creator_claims_count = 0
    creator_claims_lamports = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        wallet = ev.get("wallet")
        if isinstance(wallet, str) and wallet:
            unique_wallets.add(wallet)
        amt = ev.get("amount")
        amt_i = int(amt) if isinstance(amt, str) and amt.isdigit() else int(amt) if isinstance(amt, (int, float)) else 0
        total_lamports += amt_i
        if ev.get("isCreator") is True:
            creator_claims_count += 1
            creator_claims_lamports += amt_i
    return {
        "events_count": len(events),
        "unique_wallets_count": len(unique_wallets),
        "unique_wallets": sorted(unique_wallets),
        "total_claimed_lamports": total_lamports,
        "total_claimed_sol": round(total_lamports / 1e9, 9),
        "creator_claims_count": creator_claims_count,
        "creator_claims_lamports": creator_claims_lamports,
        "creator_claims_sol": round(creator_claims_lamports / 1e9, 9),
    }


def compare_claim_windows(
    summary_7d: Optional[dict[str, Any]],
    summary_30d: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compare 7d and 30d claim summaries.

    Produces simple trend flags plus ratio metrics to support report narratives.
    """
    s7 = summary_7d if isinstance(summary_7d, dict) else {}
    s30 = summary_30d if isinstance(summary_30d, dict) else {}

    e7 = int(s7.get("events_count") or 0)
    e30 = int(s30.get("events_count") or 0)
    l7 = int(s7.get("total_claimed_lamports") or 0)
    l30 = int(s30.get("total_claimed_lamports") or 0)
    c7 = int(s7.get("creator_claims_lamports") or 0)
    c30 = int(s30.get("creator_claims_lamports") or 0)

    def _ratio(a: int, b: int) -> Optional[float]:
        if b <= 0:
            return None
        return round(a / b, 6)

    events_ratio_7d_to_30d = _ratio(e7, e30)
    claimed_ratio_7d_to_30d = _ratio(l7, l30)
    creator_claimed_ratio_7d_to_30d = _ratio(c7, c30)

    # Simple interpretable labels for social/report output
    def _trend(r: Optional[float]) -> str:
        if r is None:
            return "insufficient_data"
        if r >= 0.6:
            return "high_recent_activity"
        if r >= 0.3:
            return "moderate_recent_activity"
        return "low_recent_activity"

    return {
        "events_ratio_7d_to_30d": events_ratio_7d_to_30d,
        "claimed_ratio_7d_to_30d": claimed_ratio_7d_to_30d,
        "creator_claimed_ratio_7d_to_30d": creator_claimed_ratio_7d_to_30d,
        "events_trend": _trend(events_ratio_7d_to_30d),
        "claimed_trend": _trend(claimed_ratio_7d_to_30d),
        "creator_claimed_trend": _trend(creator_claimed_ratio_7d_to_30d),
    }


def compare_claim_summaries(
    summary_7d: Optional[dict[str, Any]],
    summary_30d: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Backward-compatible alias for claim window comparison."""
    return compare_claim_windows(summary_7d, summary_30d)


def compare_claim_summaries(short_window: Optional[dict[str, Any]], long_window: Optional[dict[str, Any]]) -> dict[str, Any]:
    """
    Compare claim summaries (e.g. 7d vs 30d) and return trend metrics.
    """
    s = short_window or {}
    l = long_window or {}
    s_events = int(s.get("events_count") or 0)
    l_events = int(l.get("events_count") or 0)
    s_total = int(s.get("total_claimed_lamports") or 0)
    l_total = int(l.get("total_claimed_lamports") or 0)
    s_creator = int(s.get("creator_claims_lamports") or 0)
    l_creator = int(l.get("creator_claims_lamports") or 0)

    # Normalize long-window baseline to avoid divide-by-zero and to create meaningful ratios.
    # Since short window (7d) is part of long window (30d), compare to 1/4 of long window as a rough baseline.
    l_baseline = max(1, l_total // 4)
    s_to_l_baseline_ratio = round(s_total / l_baseline, 4)
    s_share_of_l = round((s_total / l_total), 4) if l_total > 0 else None

    def _trend_label(ratio: float) -> str:
        if ratio >= 1.25:
            return "accelerating"
        if ratio <= 0.75:
            return "cooling"
        return "stable"

    return {
        "short_window_events": s_events,
        "long_window_events": l_events,
        "short_window_total_claimed_lamports": s_total,
        "long_window_total_claimed_lamports": l_total,
        "short_window_total_claimed_sol": round(s_total / 1e9, 9),
        "long_window_total_claimed_sol": round(l_total / 1e9, 9),
        "short_window_creator_claims_lamports": s_creator,
        "long_window_creator_claims_lamports": l_creator,
        "delta_total_claimed_lamports": s_total - l_baseline,
        "delta_total_claimed_sol": round((s_total - l_baseline) / 1e9, 9),
        "short_vs_long_baseline_ratio": s_to_l_baseline_ratio,
        "short_share_of_long": s_share_of_l,
        "trend": _trend_label(s_to_l_baseline_ratio),
    }
