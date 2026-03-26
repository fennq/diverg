"""
Bags API client for blockchain investigations.

Section 1 — core token intelligence:
- token creators (v3), lifetime fees, claim events (offset/time)

Section 2 — liquidity / pool context:
- Bags pool by token mint (Meteora DBC + DAMM v2 keys)

Section 3 — fee-share analytics:
- per-claimer totals (`GET /token-launch/claim-stats`) with concentration metrics + reconciliation vs claim-events
- optional: `GET /fee-share/admin/list` to verify creator wallet admin scope for the mint
- optional: list all Bags pools (`GET /solana/bags/pools`) for ecosystem / migration scans

Section 4 — launch feed, Dexscreener, pool-config (state):
- `GET /token-launch/feed` — optional scan for whether this mint appears on the active launch feed
- `GET /solana/dexscreener/order-availability` — whether a Dexscreener token-info order can be placed for the mint
- `POST /token-launch/state/pool-config` — map fee-claimer vault pubkeys → Meteora DBC pool config keys (optional, when vaults known)

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


def _post_json(path: str, body: dict[str, Any], timeout: int = 30) -> Optional[dict[str, Any]]:
    if not BAGS_API_KEY:
        return None
    try:
        r = requests.post(
            f"{BAGS_BASE_URL}{path}",
            headers={"x-api-key": BAGS_API_KEY, "Content-Type": "application/json"},
            json=body,
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


def get_bags_pool_by_token_mint(token_mint: str) -> Optional[dict[str, Any]]:
    """Section 2: Meteora DBC + DAMM v2 pool keys for this token on Bags."""
    return _get("/solana/bags/pools/token-mint", {"tokenMint": token_mint})


def get_token_claim_stats(token_mint: str) -> Optional[dict[str, Any]]:
    """
    Section 3: Per-fee-claimer claim totals for a token (analytics).

    GET /token-launch/claim-stats?tokenMint=...
    """
    return _get("/token-launch/claim-stats", {"tokenMint": token_mint})


def get_bags_pools(*, only_migrated: bool = False) -> Optional[dict[str, Any]]:
    """
    Section 3 (optional): List Bags pools with DBC + DAMM v2 keys.

    Can return a large list; use sparingly (e.g. migration scans).
    GET /solana/bags/pools?onlyMigrated=...
    """
    params: dict[str, Any] = {}
    if only_migrated:
        params["onlyMigrated"] = "true"
    return _get("/solana/bags/pools", params)


def get_token_launch_feed() -> Optional[dict[str, Any]]:
    """
    Section 4: Recent/active token launches on Bags (can be a large list).

    GET /token-launch/feed
    """
    return _get("/token-launch/feed")


def get_dexscreener_order_availability(token_address: str) -> Optional[dict[str, Any]]:
    """
    Section 4: Whether a Dexscreener token-info order is available for this mint.

    GET /solana/dexscreener/order-availability?tokenAddress=...
    """
    a = (token_address or "").strip()
    if not a:
        return None
    return _get("/solana/dexscreener/order-availability", {"tokenAddress": a})


def post_pool_config_by_fee_claimer_vaults(fee_claimer_vaults: list[str]) -> Optional[dict[str, Any]]:
    """
    Section 4: First Meteora DBC pool config key per fee-claimer vault (aligned array).

    POST /token-launch/state/pool-config
    """
    vaults = [v.strip() for v in fee_claimer_vaults if isinstance(v, str) and v.strip()]
    if not vaults:
        return None
    return _post_json("/token-launch/state/pool-config", {"feeClaimerVaults": vaults})


def get_fee_share_admin_list(wallet: str) -> Optional[dict[str, Any]]:
    """
    Section 3 (optional): Token mints where this wallet is fee-share admin.

    GET /fee-share/admin/list?wallet=...
    """
    w = (wallet or "").strip()
    if not w:
        return None
    return _get("/fee-share/admin/list", {"wallet": w})


def _solscan_account_url(address: str) -> str:
    """Public Solscan deep link for a Solana account (pool, config, mint)."""
    return f"https://solscan.io/account/{address}"


def parse_bags_pool(payload: Optional[dict[str, Any]], requested_mint: Optional[str] = None) -> dict[str, Any]:
    """
    Normalize pool response for reports (Section 2).

    Adds:
    - liquidity_stage: dbc_only | migrated_to_damm_v2 | unknown
    - pool_addresses_for_tracing: copy-paste list for Bubblemaps / manual flow tracing
    - explorer_links: Solscan URLs for each relevant account
    - consistency_check: API tokenMint vs requested mint
    """
    inner = _unwrap_response(payload)
    if not isinstance(inner, dict):
        inner = {}
    damm = inner.get("dammV2PoolKey")
    dbc_pool = inner.get("dbcPoolKey")
    dbc_cfg = inner.get("dbcConfigKey")
    api_mint = inner.get("tokenMint")

    if damm:
        liquidity_stage = "migrated_to_damm_v2"
    elif dbc_pool or dbc_cfg:
        liquidity_stage = "dbc_only"
    else:
        liquidity_stage = "unknown"

    tracing: list[str] = []
    for k in (dbc_cfg, dbc_pool, damm):
        if isinstance(k, str) and k.strip():
            tracing.append(k.strip())
    if isinstance(api_mint, str) and api_mint.strip():
        m = api_mint.strip()
        if m not in tracing:
            tracing.insert(0, m)

    explorer_links: list[dict[str, str]] = []
    labels = [
        ("token_mint", api_mint),
        ("dbc_config", dbc_cfg),
        ("dbc_pool", dbc_pool),
        ("damm_v2_pool", damm),
    ]
    for label, addr in labels:
        if isinstance(addr, str) and addr.strip():
            a = addr.strip()
            explorer_links.append({"label": label, "address": a, "solscan": _solscan_account_url(a)})

    consistency: dict[str, Any] = {
        "requested_mint": requested_mint,
        "api_token_mint": api_mint,
        "mint_matches": None,
    }
    if requested_mint and api_mint:
        consistency["mint_matches"] = requested_mint.strip() == str(api_mint).strip()
    elif requested_mint and not api_mint:
        consistency["mint_matches"] = None
        consistency["note"] = "api_returned_no_token_mint"
    elif not requested_mint:
        consistency["note"] = "no_requested_mint_supplied"

    return {
        "token_mint": api_mint,
        "dbc_config_key": dbc_cfg,
        "dbc_pool_key": dbc_pool,
        "damm_v2_pool_key": damm,
        "has_damm_v2_pool": bool(damm),
        "liquidity_stage": liquidity_stage,
        "pool_addresses_for_tracing": tracing,
        "explorer_links": explorer_links,
        "consistency_check": consistency,
        "raw": inner if inner else None,
    }


def _lamports_from_claim_field(raw: Any) -> int:
    if raw is None:
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    s = str(raw).strip()
    if s.isdigit():
        return int(s)
    try:
        return int(float(s))
    except Exception:
        return 0


def parse_token_claim_stats(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    """
    Normalize Section 3 claim-stats for reports.

    Adds per-row SOL, totals, creator/non-creator splits, concentration (top1/top3/top5),
    Herfindahl-style fee concentration index, and a plain-language distribution label.
    """
    rows_in = _unwrap_response(payload)
    if not isinstance(rows_in, list):
        rows_in = []
    rows_out: list[dict[str, Any]] = []
    total_lamports = 0
    creator_lamports = 0
    admin_lamports = 0
    for row in rows_in:
        if not isinstance(row, dict):
            continue
        lam = _lamports_from_claim_field(row.get("totalClaimed"))
        total_lamports += lam
        if row.get("isCreator") is True:
            creator_lamports += lam
        if row.get("isAdmin") is True:
            admin_lamports += lam
        rows_out.append(
            {
                "wallet": row.get("wallet"),
                "username": row.get("username"),
                "provider": row.get("provider"),
                "provider_username": row.get("providerUsername"),
                "twitter_username": row.get("twitterUsername"),
                "bags_username": row.get("bagsUsername"),
                "is_creator": row.get("isCreator"),
                "is_admin": row.get("isAdmin"),
                "royalty_bps": row.get("royaltyBps"),
                "total_claimed_lamports": lam,
                "total_claimed_sol": round(lam / 1e9, 9),
                "pfp": row.get("pfp"),
            }
        )
    # Sort by claimed amount descending
    rows_out.sort(key=lambda r: int(r.get("total_claimed_lamports") or 0), reverse=True)

    sorted_lams = [int(r.get("total_claimed_lamports") or 0) for r in rows_out]
    top1 = sorted_lams[0] if sorted_lams else 0
    top3 = sum(sorted_lams[:3]) if sorted_lams else 0
    top5 = sum(sorted_lams[:5]) if sorted_lams else 0
    non_creator_lamports = max(0, total_lamports - creator_lamports)

    def _share(part: int) -> Optional[float]:
        if total_lamports <= 0:
            return None
        return round(part / total_lamports, 6)

    # Herfindahl index on fee shares (0..1); higher = more concentrated among few claimers
    hhi = None
    if total_lamports > 0 and sorted_lams:
        shares = [lam / total_lamports for lam in sorted_lams]
        hhi = round(sum(s * s for s in shares), 6)

    t1s = _share(top1) or 0.0
    t3s = _share(top3) or 0.0
    if t1s >= 0.55 or (hhi is not None and hhi >= 0.35):
        distribution_label = "highly_concentrated"
    elif t1s >= 0.35 or t3s >= 0.65 or (hhi is not None and hhi >= 0.2):
        distribution_label = "moderate"
    else:
        distribution_label = "dispersed"

    top_claimer = None
    if rows_out:
        r0 = rows_out[0]
        top_claimer = {
            "wallet": r0.get("wallet"),
            "display": r0.get("provider_username")
            or r0.get("twitter_username")
            or r0.get("bags_username")
            or r0.get("username"),
            "total_claimed_sol": r0.get("total_claimed_sol"),
            "share_of_total": _share(int(r0.get("total_claimed_lamports") or 0)),
            "is_creator": r0.get("is_creator"),
        }

    return {
        "claimers_count": len(rows_out),
        "total_claimed_lamports": total_lamports,
        "total_claimed_sol": round(total_lamports / 1e9, 9),
        "creator_claimed_lamports": creator_lamports,
        "creator_claimed_sol": round(creator_lamports / 1e9, 9),
        "non_creator_claimed_lamports": non_creator_lamports,
        "non_creator_claimed_sol": round(non_creator_lamports / 1e9, 9),
        "admin_claimed_lamports": admin_lamports,
        "admin_claimed_sol": round(admin_lamports / 1e9, 9),
        "creator_share_of_total": _share(creator_lamports),
        "non_creator_share_of_total": _share(non_creator_lamports),
        "top1_share_of_total": _share(top1),
        "top3_share_of_total": _share(top3),
        "top5_share_of_total": _share(top5),
        "fee_herfindahl_index": hhi,
        "distribution_label": distribution_label,
        "top_claimer": top_claimer,
        "claimers": rows_out,
        "raw_count": len(rows_in),
    }


def reconcile_claim_stats_with_events(
    claim_stats_parsed: Optional[dict[str, Any]],
    events_summary: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compare Bags claim-stats (full per-claimer totals) with a claim-events sample
    (first page / time window). Large gaps usually mean pagination or partial events.
    """
    cs = claim_stats_parsed if isinstance(claim_stats_parsed, dict) else {}
    ev = events_summary if isinstance(events_summary, dict) else {}
    s_tot = int(cs.get("total_claimed_lamports") or 0)
    e_tot = int(ev.get("total_claimed_lamports") or 0)
    s_count = int(cs.get("claimers_count") or 0)
    e_wallets = int(ev.get("unique_wallets_count") or 0)
    e_events = int(ev.get("events_count") or 0)

    ratio: Optional[float] = None
    if s_tot > 0:
        ratio = round(e_tot / s_tot, 6)

    notes: list[str] = []
    if e_events >= 100:
        notes.append("events_sample_may_be_capped_at_api_limit")
    if ratio is not None and ratio < 0.85 and s_tot > 0:
        notes.append("events_total_below_stats_suggest_partial_sample_or_timing_skew")

    return {
        "stats_total_claimed_lamports": s_tot,
        "events_sample_total_claimed_lamports": e_tot,
        "events_to_stats_claimed_ratio": ratio,
        "stats_claimers_count": s_count,
        "events_unique_wallets_count": e_wallets,
        "events_row_count": e_events,
        "claimers_vs_unique_wallets_delta": (s_count - e_wallets) if s_count or e_wallets else None,
        "notes": notes,
    }


def section3_fee_share_admin_for_mint(
    token_mint: str,
    creators_parsed: Optional[dict[str, Any]],
    *,
    max_wallets: int = 1,
) -> dict[str, Any]:
    """
    For up to N creator wallets, call GET /fee-share/admin/list and check whether
    this token mint appears (fee-share admin scope for that wallet).
    """
    mint = (token_mint or "").strip()
    out: dict[str, Any] = {"token_mint": mint, "checks": []}
    if not mint or not is_configured():
        return out
    wallets: list[str] = []
    if isinstance(creators_parsed, dict):
        wallets = [w for w in (creators_parsed.get("wallets") or []) if isinstance(w, str) and w][
            : max(1, int(max_wallets))
        ]
    for w in wallets:
        raw = get_fee_share_admin_list(w)
        inner = _unwrap_response(raw)
        mints: list[str] = []
        if isinstance(inner, dict) and isinstance(inner.get("tokenMints"), list):
            mints = [str(x) for x in (inner.get("tokenMints") or []) if x]
        out["checks"].append(
            {
                "wallet": w,
                "mint_in_fee_share_admin_list": mint in mints,
                "fee_share_admin_token_count": len(mints),
            }
        )
    return out


def parse_dexscreener_order_availability(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Normalize Section 4 Dexscreener order-availability response."""
    inner = _unwrap_response(payload)
    available = None
    if isinstance(inner, dict) and "available" in inner:
        available = bool(inner.get("available"))
    err = None
    if isinstance(payload, dict) and payload.get("success") is False:
        err = payload.get("error") or payload.get("response")
    return {"dexscreener_order_available": available, "error": err, "raw": inner}


def find_mint_in_token_launch_feed(
    feed_payload: Optional[dict[str, Any]],
    token_mint: str,
) -> dict[str, Any]:
    """
    Scan Section 4 launch feed for a matching tokenMint (exact string match after strip).

    Does not embed the full feed — only counts + optional matched item summary.
    """
    mint = (token_mint or "").strip()
    items = _unwrap_response(feed_payload)
    if not isinstance(items, list):
        items = []
    match: Optional[dict[str, Any]] = None
    for it in items:
        if not isinstance(it, dict):
            continue
        tm = str(it.get("tokenMint") or "").strip()
        if mint and tm == mint:
            match = {
                "token_mint": tm,
                "name": it.get("name"),
                "symbol": it.get("symbol"),
                "status": it.get("status"),
                "dbc_pool_key": it.get("dbcPoolKey"),
                "dbc_config_key": it.get("dbcConfigKey"),
                "twitter": it.get("twitter"),
                "website": it.get("website"),
                "launch_signature": it.get("launchSignature"),
            }
            break
    err = None
    if isinstance(feed_payload, dict) and feed_payload.get("success") is False:
        err = feed_payload.get("error") or feed_payload.get("response")
    return {
        "requested_mint": mint or None,
        "mint_found_in_feed": bool(match),
        "feed_item_count": len(items),
        "matched_item": match,
        "error": err,
    }


def parse_pool_config_by_vaults_response(
    payload: Optional[dict[str, Any]],
    requested_vaults: list[str],
) -> dict[str, Any]:
    """Pair fee-claimer vault inputs with returned pool config keys (Section 4)."""
    inner = _unwrap_response(payload)
    keys: list[Any] = []
    if isinstance(inner, dict) and isinstance(inner.get("poolConfigKeys"), list):
        keys = list(inner.get("poolConfigKeys") or [])
    err = None
    if isinstance(payload, dict) and payload.get("success") is False:
        err = payload.get("error") or payload.get("response")
    rows: list[dict[str, Any]] = []
    for i, v in enumerate(requested_vaults):
        k = keys[i] if i < len(keys) else None
        rows.append(
            {
                "fee_claimer_vault": v,
                "pool_config_key": k if isinstance(k, str) and k.strip() else k,
                "resolved": bool(k and str(k).strip()),
            }
        )
    return {
        "vault_count": len(requested_vaults),
        "resolved_count": sum(1 for r in rows if r.get("resolved")),
        "mappings": rows,
        "error": err,
    }


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
