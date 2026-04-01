"""
Creator forensics engine for Bags.fm token launches.

Analyzes a token creator's wallet history, previous launches on Bags,
fee claim behavior across launches, connected wallet discovery, and
funding source tracing. Produces structured intelligence for the
bags_launch_intel orchestrator.

Requires: BAGS_API_KEY, HELIUS_API_KEY (env).
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from typing import Any, Optional

from bags_client import (
    get_fee_share_admin_list,
    get_token_claim_events,
    get_token_claim_stats,
    get_token_creators,
    get_token_launch_feed,
    get_token_lifetime_fees,
    is_configured as bags_configured,
    parse_lifetime_fees,
    parse_token_claim_stats,
    parse_token_creators,
    summarize_claim_events,
    _unwrap_response,
)
from onchain_clients import (
    helius_enhanced_transactions,
    helius_transfers,
    helius_wallet_funded_by,
    helius_wallet_identity,
)

_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

MAX_PREVIOUS_LAUNCHES = int(os.environ.get("BAGS_INTEL_MAX_PREV_LAUNCHES", "10"))
MAX_CREATOR_WALLETS = int(os.environ.get("BAGS_INTEL_MAX_CREATOR_WALLETS", "3"))


def _safe_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Creator wallet profile
# ---------------------------------------------------------------------------

def build_creator_profile(creator_wallet: str) -> dict[str, Any]:
    """
    Build a wallet-level profile for a creator address:
    - Helius identity (labels, tags)
    - Funding source (who funded this wallet)
    - Recent transaction patterns (enhanced tx types)
    """
    profile: dict[str, Any] = {
        "wallet": creator_wallet,
        "identity": None,
        "funded_by": None,
        "funding_chain": [],
        "recent_tx_types": {},
        "program_ids_seen": [],
    }

    # Identity
    try:
        identity = helius_wallet_identity(creator_wallet)
        if isinstance(identity, dict):
            profile["identity"] = identity
    except Exception:
        pass

    # Funded-by (first inbound SOL)
    try:
        fb = helius_wallet_funded_by(creator_wallet)
        if isinstance(fb, dict):
            profile["funded_by"] = fb
            # One-hop deeper: who funded the funder?
            funder_addr = fb.get("funder") or fb.get("fundingWallet") or fb.get("from")
            if isinstance(funder_addr, str) and _ADDR_RE.match(funder_addr):
                try:
                    fb2 = helius_wallet_funded_by(funder_addr)
                    if isinstance(fb2, dict):
                        profile["funding_chain"].append(fb2)
                except Exception:
                    pass
    except Exception:
        pass

    # Recent enhanced transactions — program overlap + tx type histogram
    try:
        txs = helius_enhanced_transactions(creator_wallet, limit=50)
        if isinstance(txs, list):
            type_counts: dict[str, int] = defaultdict(int)
            programs: set[str] = set()
            for tx in txs:
                if not isinstance(tx, dict):
                    continue
                tt = tx.get("type") or tx.get("transactionType")
                if tt:
                    type_counts[str(tt)] += 1
                for prog in (tx.get("programIds") or tx.get("accountKeys") or []):
                    if isinstance(prog, str) and _ADDR_RE.match(prog):
                        programs.add(prog)
            profile["recent_tx_types"] = dict(type_counts)
            profile["program_ids_seen"] = sorted(programs)[:50]
    except Exception:
        pass

    return profile


# ---------------------------------------------------------------------------
# Previous launches by creator
# ---------------------------------------------------------------------------

def find_creator_previous_launches(
    creator_wallets: list[str],
    current_mint: str,
) -> dict[str, Any]:
    """
    Scan the Bags launch feed for other tokens launched by the same creator wallet(s).
    Returns launch history with fee totals.
    """
    result: dict[str, Any] = {
        "creator_wallets": creator_wallets,
        "current_mint": current_mint,
        "previous_launches": [],
        "total_previous_launches": 0,
        "total_lifetime_fees_all_launches_lamports": 0,
        "feed_scan_error": None,
    }

    if not bags_configured():
        result["feed_scan_error"] = "BAGS_API_KEY not configured"
        return result

    # Fetch the full launch feed
    feed_raw = get_token_launch_feed()
    feed_items = _unwrap_response(feed_raw)
    if not isinstance(feed_items, list):
        result["feed_scan_error"] = "Failed to fetch launch feed"
        return result

    # Build set of creator wallets for fast lookup
    wallet_set = {w.strip() for w in creator_wallets if isinstance(w, str) and w.strip()}
    current_mint_clean = (current_mint or "").strip()

    previous: list[dict[str, Any]] = []
    for item in feed_items:
        if not isinstance(item, dict):
            continue
        item_mint = str(item.get("tokenMint") or "").strip()
        if not item_mint or item_mint == current_mint_clean:
            continue

        # Check if any creator wallet matches
        item_creator = str(item.get("creator") or "").strip()
        item_creators = []
        if isinstance(item.get("creators"), list):
            item_creators = [
                str(c.get("wallet") or c if isinstance(c, dict) else c).strip()
                for c in item["creators"]
                if c
            ]
        all_item_wallets = {item_creator} | set(item_creators)
        all_item_wallets.discard("")

        if not wallet_set & all_item_wallets:
            continue

        # This is a previous launch by the same creator
        launch_info: dict[str, Any] = {
            "token_mint": item_mint,
            "name": item.get("name"),
            "symbol": item.get("symbol"),
            "status": item.get("status"),
            "twitter": item.get("twitter"),
            "website": item.get("website"),
            "launch_signature": item.get("launchSignature"),
        }

        # Fetch lifetime fees for this previous launch
        try:
            fees_raw = get_token_lifetime_fees(item_mint)
            fees_parsed = parse_lifetime_fees(fees_raw)
            launch_info["lifetime_fees_lamports"] = fees_parsed.get("lamports")
            launch_info["lifetime_fees_sol"] = fees_parsed.get("sol")
            if fees_parsed.get("lamports"):
                result["total_lifetime_fees_all_launches_lamports"] += fees_parsed["lamports"]
        except Exception:
            launch_info["lifetime_fees_lamports"] = None
            launch_info["lifetime_fees_sol"] = None

        previous.append(launch_info)
        if len(previous) >= MAX_PREVIOUS_LAUNCHES:
            break

    result["previous_launches"] = previous
    result["total_previous_launches"] = len(previous)
    return result


# ---------------------------------------------------------------------------
# Creator fee-share admin scope
# ---------------------------------------------------------------------------

def get_creator_admin_scope(creator_wallets: list[str]) -> dict[str, Any]:
    """
    For each creator wallet, check which tokens they are fee-share admin for.
    Multiple admin tokens = serial launcher pattern.
    """
    scope: dict[str, Any] = {
        "wallets_checked": [],
        "total_admin_tokens": 0,
    }

    if not bags_configured():
        return scope

    for wallet in creator_wallets[:MAX_CREATOR_WALLETS]:
        wallet = wallet.strip()
        if not wallet:
            continue
        try:
            raw = get_fee_share_admin_list(wallet)
            inner = _unwrap_response(raw)
            mints: list[str] = []
            if isinstance(inner, dict) and isinstance(inner.get("tokenMints"), list):
                mints = [str(x) for x in inner["tokenMints"] if x]
            scope["wallets_checked"].append({
                "wallet": wallet,
                "admin_token_count": len(mints),
                "admin_token_mints": mints[:20],
            })
            scope["total_admin_tokens"] += len(mints)
        except Exception:
            scope["wallets_checked"].append({
                "wallet": wallet,
                "admin_token_count": 0,
                "admin_token_mints": [],
                "error": "API call failed",
            })

    return scope


# ---------------------------------------------------------------------------
# Connected wallets via funding path
# ---------------------------------------------------------------------------

def trace_connected_wallets(creator_wallets: list[str]) -> dict[str, Any]:
    """
    Discover wallets connected to creators via funding paths.
    Uses Helius funded-by + transfers to build a 2-hop graph.
    """
    connections: dict[str, Any] = {
        "wallets_analyzed": len(creator_wallets),
        "funding_sources": [],
        "shared_funding_sources": [],
    }

    funder_to_wallets: dict[str, list[str]] = defaultdict(list)

    for wallet in creator_wallets[:MAX_CREATOR_WALLETS]:
        wallet = wallet.strip()
        if not wallet:
            continue
        try:
            fb = helius_wallet_funded_by(wallet)
            if isinstance(fb, dict):
                funder = fb.get("funder") or fb.get("fundingWallet") or fb.get("from")
                if isinstance(funder, str) and _ADDR_RE.match(funder):
                    funder_identity = None
                    try:
                        funder_identity = helius_wallet_identity(funder)
                    except Exception:
                        pass
                    connections["funding_sources"].append({
                        "creator_wallet": wallet,
                        "funder": funder,
                        "funder_identity": funder_identity,
                        "lamports": fb.get("lamports"),
                        "timestamp": fb.get("timestamp"),
                    })
                    funder_to_wallets[funder].append(wallet)
        except Exception:
            pass

    # Shared funding sources: same funder → multiple creator wallets
    for funder, wallets in funder_to_wallets.items():
        if len(wallets) > 1:
            connections["shared_funding_sources"].append({
                "funder": funder,
                "wallets_funded": wallets,
                "count": len(wallets),
            })

    return connections


# ---------------------------------------------------------------------------
# Aggregate creator intelligence
# ---------------------------------------------------------------------------

def run_creator_intel(
    token_mint: str,
    *,
    max_creator_profiles: int = 2,
) -> dict[str, Any]:
    """
    Full creator forensics for a Bags token mint.

    1. Fetch token creators from Bags API
    2. Build wallet profiles for each creator
    3. Scan for previous launches
    4. Check fee-share admin scope
    5. Trace connected wallets

    Returns structured creator intelligence dict.
    """
    intel: dict[str, Any] = {
        "token_mint": token_mint,
        "creators": None,
        "creator_profiles": [],
        "previous_launches": None,
        "admin_scope": None,
        "connected_wallets": None,
        "flags": [],
    }

    # 1. Get creators
    creators_raw = get_token_creators(token_mint)
    creators_parsed = parse_token_creators(creators_raw)
    intel["creators"] = creators_parsed

    creator_wallets = creators_parsed.get("wallets") or []
    if not creator_wallets:
        intel["flags"].append("no_creator_wallets_found")
        return intel

    # 2. Build profiles
    for wallet in creator_wallets[:max_creator_profiles]:
        profile = build_creator_profile(wallet)
        intel["creator_profiles"].append(profile)

    # 3. Previous launches
    prev = find_creator_previous_launches(creator_wallets, token_mint)
    intel["previous_launches"] = prev
    if prev.get("total_previous_launches", 0) >= 5:
        intel["flags"].append("serial_launcher")
    elif prev.get("total_previous_launches", 0) >= 2:
        intel["flags"].append("repeat_launcher")

    # 4. Admin scope
    admin_scope = get_creator_admin_scope(creator_wallets)
    intel["admin_scope"] = admin_scope
    if admin_scope.get("total_admin_tokens", 0) >= 5:
        intel["flags"].append("many_admin_tokens")

    # 5. Connected wallets
    connected = trace_connected_wallets(creator_wallets)
    intel["connected_wallets"] = connected
    if connected.get("shared_funding_sources"):
        intel["flags"].append("shared_funding_source")

    return intel
