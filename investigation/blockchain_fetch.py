"""
Generic on-chain fetch for any investigation: wallets + optional token.

Uses: Solana RPC (public), Helius (optional), Arkham (optional), FrontrunPro (optional paid API;
      without API, use address_finder_url() for Twitter → wallet), Solscan (token holders/metadata).

Import from scripts with: sys.path.insert(0, "investigation"); from blockchain_fetch import run_blockchain_research
Or run the generic CLI: python scripts/run_blockchain_research.py --wallets addr1 addr2 [--token MINT] [--out path]
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

# Assume we're run with investigation/ on path (e.g. from scripts/run_*.py)
try:
    from onchain_clients import (
        rpc_get_balance,
        rpc_get_signatures,
        helius_wallet_history,
        helius_transfers,
        helius_wallet_identity,
        helius_wallet_funded_by,
        helius_wallet_balances,
        helius_enhanced_transactions,
        helius_das_assets_by_owner,
        helius_das_asset,
        helius_batch_identity,
    )
    from solscan_client import token_holders_total, token_metadata, throttle
except ImportError:
    rpc_get_balance = rpc_get_signatures = helius_wallet_history = helius_transfers = None
    helius_wallet_identity = helius_wallet_funded_by = helius_wallet_balances = None
    helius_enhanced_transactions = helius_das_assets_by_owner = helius_das_asset = None
    helius_batch_identity = None
    token_holders_total = token_metadata = throttle = None

try:
    from arkham_client import address_intelligence_all, summarize_for_report
except ImportError:
    address_intelligence_all = None
    summarize_for_report = None

try:
    from frontrunpro_client import wallet_enrichment, is_configured as frontrunpro_configured
except ImportError:
    wallet_enrichment = None
    frontrunpro_configured = lambda: False

try:
    from bags_client import (
        get_token_creators,
        get_token_lifetime_fees,
        get_token_claim_events,
        parse_token_creators,
        parse_lifetime_fees,
        summarize_claim_events,
        compare_claim_summaries,
        is_configured as bags_configured,
    )
except ImportError:
    get_token_creators = get_token_lifetime_fees = get_token_claim_events = None
    parse_token_creators = parse_lifetime_fees = summarize_claim_events = compare_claim_summaries = None
    bags_configured = lambda: False


def fetch_wallet(addr: str) -> dict[str, Any]:
    """Fetch one wallet: RPC balance/sigs, optional Helius, Arkham, FrontrunPro."""
    out: dict[str, Any] = {"address": addr, "error": None}
    if rpc_get_balance is None:
        out["sol_balance_lamports"] = None
        out["sol_balance_sol"] = None
        out["recent_signatures"] = []
        out["recent_signatures_count"] = 0
    else:
        bal = rpc_get_balance(addr)
        out["sol_balance_lamports"] = bal
        out["sol_balance_sol"] = round(bal / 1e9, 6) if bal is not None else None
        time.sleep(0.2)
        sigs = rpc_get_signatures(addr, limit=25)
        out["recent_signatures"] = [s.get("signature") for s in sigs] if sigs else []
        out["recent_signatures_count"] = len(out["recent_signatures"])
        time.sleep(0.2)
    if os.environ.get("HELIUS_API_KEY"):
        out["helius_history"] = helius_wallet_history(addr, limit=25) if helius_wallet_history else None
        time.sleep(0.15)
        out["helius_transfers"] = helius_transfers(addr, limit=50) if helius_transfers else None
        time.sleep(0.15)
        out["helius_identity"] = helius_wallet_identity(addr) if helius_wallet_identity else None
        time.sleep(0.15)
        out["helius_funded_by"] = helius_wallet_funded_by(addr) if helius_wallet_funded_by else None
        time.sleep(0.15)
        out["helius_balances"] = helius_wallet_balances(addr, limit=50) if helius_wallet_balances else None
        time.sleep(0.15)
        out["helius_enhanced_transactions"] = (
            helius_enhanced_transactions(addr, limit=20) if helius_enhanced_transactions else None
        )
        time.sleep(0.15)
        out["helius_das_assets"] = (
            helius_das_assets_by_owner(addr, limit=50) if helius_das_assets_by_owner else None
        )
    else:
        out["helius_history"] = out["helius_transfers"] = None
        out["helius_identity"] = out["helius_funded_by"] = out["helius_balances"] = None
        out["helius_enhanced_transactions"] = out["helius_das_assets"] = None
    if address_intelligence_all:
        raw = address_intelligence_all(addr)
        out["arkham_intelligence"] = raw
        out["arkham_summary"] = summarize_for_report(raw) if summarize_for_report else {}
        time.sleep(0.3)
    else:
        out["arkham_intelligence"] = None
        out["arkham_summary"] = {}
    if wallet_enrichment and frontrunpro_configured():
        out["frontrunpro"] = wallet_enrichment(addr)
        time.sleep(0.3)
    else:
        out["frontrunpro"] = {}
    return out


def fetch_token(mint: str) -> dict[str, Any]:
    """Fetch one token: Solscan + Helius DAS + Bags Section 1."""
    out: dict[str, Any] = {"mint": mint, "error": None}
    if token_holders_total is None:
        out["holders_total"] = {}
        out["metadata"] = {}
    else:
        try:
            out["holders_total"] = token_holders_total(mint)
            if throttle:
                throttle(0.3)
        except Exception as e:
            out["holders_total"] = {"error": str(e)}
        try:
            out["metadata"] = token_metadata(mint) if token_metadata else {}
            if throttle:
                throttle(0.3)
        except Exception as e:
            out["metadata"] = {"error": str(e)}
    if os.environ.get("HELIUS_API_KEY") and helius_das_asset:
        try:
            out["helius_das_asset"] = helius_das_asset(mint)
            time.sleep(0.15)
        except Exception as e:
            out["helius_das_asset"] = {"error": str(e)}
    else:
        out["helius_das_asset"] = None
    if bags_configured():
        out["bags"] = {}
        try:
            creators_raw = get_token_creators(mint) if get_token_creators else None
            out["bags"]["creators_raw"] = creators_raw
            out["bags"]["creators"] = parse_token_creators(creators_raw) if parse_token_creators else creators_raw
            time.sleep(0.15)
        except Exception as e:
            out["bags"]["creators"] = {"error": str(e)}
        try:
            fees_raw = get_token_lifetime_fees(mint) if get_token_lifetime_fees else None
            out["bags"]["lifetime_fees_raw"] = fees_raw
            out["bags"]["lifetime_fees"] = parse_lifetime_fees(fees_raw) if parse_lifetime_fees else fees_raw
            time.sleep(0.15)
        except Exception as e:
            out["bags"]["lifetime_fees"] = {"error": str(e)}
        try:
            claim_raw = (
                get_token_claim_events(mint, mode="offset", limit=50, offset=0)
                if get_token_claim_events
                else None
            )
            out["bags"]["claim_events_raw"] = claim_raw
            out["bags"]["claim_events"] = summarize_claim_events(claim_raw) if summarize_claim_events else claim_raw
        except Exception as e:
            out["bags"]["claim_events"] = {"error": str(e)}
        # Wallet claim connections through CEX (Section 1 enhancement)
        try:
            claim_wallets = out["bags"].get("claim_events", {}).get("unique_wallets", [])
            cex_connections = {
                "wallets_analyzed": 0,
                "cex_identity_wallets": [],
                "exchange_funded_wallets": [],
                "details": [],
            }
            if (
                isinstance(claim_wallets, list)
                and claim_wallets
                and os.environ.get("HELIUS_API_KEY")
                and helius_batch_identity
            ):
                wallets = [w for w in claim_wallets if isinstance(w, str) and w][:100]
                identities = helius_batch_identity(wallets) or []
                id_by_wallet = {}
                if isinstance(identities, list):
                    for row in identities:
                        if isinstance(row, dict) and row.get("address"):
                            id_by_wallet[row["address"]] = row
                for w in wallets:
                    ident = id_by_wallet.get(w) or {}
                    category = str(ident.get("category") or "").lower()
                    name = ident.get("name")
                    # funded-by is fetched per wallet; small list from claim events so acceptable.
                    funded = helius_wallet_funded_by(w) if helius_wallet_funded_by else None
                    funder_type = (funded or {}).get("funderType") if isinstance(funded, dict) else None
                    row = {
                        "wallet": w,
                        "identity_name": name,
                        "identity_category": ident.get("category"),
                        "funder": (funded or {}).get("funder") if isinstance(funded, dict) else None,
                        "funder_name": (funded or {}).get("funderName") if isinstance(funded, dict) else None,
                        "funder_type": funder_type,
                        "cex_identity": "exchange" in category,
                        "cex_funded": funder_type == "exchange",
                    }
                    cex_connections["details"].append(row)
                    if row["cex_identity"]:
                        cex_connections["cex_identity_wallets"].append(w)
                    if row["cex_funded"]:
                        cex_connections["exchange_funded_wallets"].append(w)
                    time.sleep(0.1)
                cex_connections["wallets_analyzed"] = len(wallets)
                cex_connections["cex_identity_count"] = len(cex_connections["cex_identity_wallets"])
                cex_connections["exchange_funded_count"] = len(cex_connections["exchange_funded_wallets"])
            out["bags"]["claim_wallet_cex_connections"] = cex_connections
        except Exception as e:
            out["bags"]["claim_wallet_cex_connections"] = {"error": str(e)}
        # Time-window claim analytics (Section 1 hardening): 7d and 30d summaries
        try:
            now_ts = int(time.time())
            windows = {
                "7d": now_ts - 7 * 24 * 60 * 60,
                "30d": now_ts - 30 * 24 * 60 * 60,
            }
            out["bags"]["claim_events_windows"] = {}
            for label, from_ts in windows.items():
                win_raw = (
                    get_token_claim_events(mint, mode="time", from_ts=from_ts, to_ts=now_ts)
                    if get_token_claim_events
                    else None
                )
                out["bags"]["claim_events_windows"][label] = {
                    "from_ts": from_ts,
                    "to_ts": now_ts,
                    "raw": win_raw,
                    "summary": summarize_claim_events(win_raw) if summarize_claim_events else win_raw,
                }
                time.sleep(0.15)
            if compare_claim_summaries:
                s7 = out["bags"]["claim_events_windows"].get("7d", {}).get("summary", {})
                s30 = out["bags"]["claim_events_windows"].get("30d", {}).get("summary", {})
                out["bags"]["claim_events_window_trend"] = compare_claim_summaries(s7, s30)
        except Exception as e:
            out["bags"]["claim_events_windows"] = {"error": str(e)}
    else:
        out["bags"] = None
    return out


def run_blockchain_research(
    wallet_addresses: list[str],
    token_mint: Optional[str] = None,
    output_path: Optional[Path] = None,
    *,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Run full on-chain fetch for any investigation.

    - wallet_addresses: list of Solana wallet addresses to fetch.
    - token_mint: optional token mint to fetch (holders + metadata).
    - output_path: if set, write JSON to this path.
    - verbose: print progress.

    Returns dict with keys: wallets, token (or None), helius_used, arkham_used, frontrunpro_used.
    """
    result: dict[str, Any] = {
        "wallets": [],
        "token": None,
        "helius_used": bool(os.environ.get("HELIUS_API_KEY")),
        "arkham_used": bool(address_intelligence_all is not None and os.environ.get("ARKHAM_API_KEY")),
        "frontrunpro_used": bool(wallet_enrichment and frontrunpro_configured()),
        "bags_used": bool(bags_configured()),
    }
    n = len(wallet_addresses)
    for i, addr in enumerate(wallet_addresses, 1):
        if verbose:
            print(f"  [{i}/{n}] {addr[:12]}...")
        result["wallets"].append(fetch_wallet(addr))
    if token_mint:
        if verbose:
            print("Fetching token holders and metadata...")
        result["token"] = fetch_token(token_mint)
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        if verbose:
            print(f"Wrote {output_path}")
    return result
