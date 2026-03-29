"""
Solana token bundle snapshot: top holders + shared-funder clustering (Helius), plus
multi-signal coordination heuristics (solana_bundle_signals.compute_coordination_bundle).

Also surfaces parallel CEX-funder clusters and privacy/mixer-tagged shared funders, optional
X (Twitter) mention search per holder when X_API_BEARER_TOKEN or NITTER_BASE_URL is set
(see x_bundle_intel.py; omitted when there are no hits).

The Chrome extension runs the same logic client-side (extension/solana_bundle.js) with a
user-supplied Helius key (no X from the extension). This module is for Python callers and
the dashboard API with HELIUS_API_KEY in the environment.
"""
from __future__ import annotations

import concurrent.futures
import os
import re
import time
from collections import Counter, defaultdict
from typing import Any, Optional

from onchain_clients import (
    helius_batch_identity,
    helius_das_asset,
    helius_das_token_accounts_for_mint,
    helius_json_rpc_ex,
    helius_transfers,
    helius_wallet_balances,
    helius_wallet_funded_by,
    normalize_batch_identity_map,
    token_metadata_from_das_asset,
)
from solana_bundle_signals import (
    compute_coordination_bundle,
    effective_funder_address,
    is_cex_identity,
    is_mixer_privacy_identity,
)

# Base58 Solana address (rough)
_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _should_fetch_x_intel(include_x_intel: Optional[bool]) -> bool:
    """True when X/Nitter is configured and caller/env allow lookup."""
    if include_x_intel is False:
        return False
    v = (os.environ.get("SOLANA_BUNDLE_X_INTEL") or "auto").strip().lower()
    if include_x_intel is None and v in ("0", "false", "no", "off"):
        return False
    try:
        from x_bundle_intel import x_search_configured
    except ImportError:
        return False
    if not x_search_configured():
        return False
    if include_x_intel is True:
        return True
    # auto (default): run when X or Nitter is configured
    return True


def normalize_solana_address(s: str) -> Optional[str]:
    if not s or not isinstance(s, str):
        return None
    t = s.strip()
    if not _ADDR_RE.match(t):
        return None
    return t


def _parse_token_account_owner(acc: Optional[dict]) -> Optional[str]:
    if not acc or not isinstance(acc, dict):
        return None
    v = acc.get("value")
    if not v:
        return None
    parsed = (v.get("data") or {}).get("parsed") if isinstance(v.get("data"), dict) else None
    if not isinstance(parsed, dict):
        return None
    if parsed.get("type") != "account":
        return None
    info = parsed.get("info") or {}
    owner = info.get("owner")
    if isinstance(owner, str) and _ADDR_RE.match(owner):
        return owner
    return None


def _parse_token_account_ui_amount(acc: Optional[dict]) -> float:
    if not acc or not isinstance(acc, dict):
        return 0.0
    v = acc.get("value")
    if not v:
        return 0.0
    parsed = (v.get("data") or {}).get("parsed") if isinstance(v.get("data"), dict) else None
    if not isinstance(parsed, dict):
        return 0.0
    info = parsed.get("info") or {}
    ta = info.get("tokenAmount") or {}
    ui = ta.get("uiAmount")
    if ui is not None:
        try:
            return float(ui)
        except (TypeError, ValueError):
            pass
    amt = ta.get("amount")
    dec = int(ta.get("decimals") or 0)
    if amt is not None and dec >= 0:
        try:
            return float(amt) / (10**dec)
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    return 0.0


def _cluster_key_sources(
    wallet: str,
    funded: Optional[dict],
    transfers: Optional[dict],
    *,
    hop_funded: Optional[dict[str, Optional[dict]]] = None,
    hop_transfers: Optional[dict[str, Any]] = None,
) -> str:
    """
    Cluster by shared *ultimate* funder when 2-hop Helius data exists (hop wallet → root),
    else by direct funder; singleton if unknown.
    """
    hf = hop_funded or {}
    ht = hop_transfers or {}
    direct = effective_funder_address(funded, transfers)
    if not direct:
        return f"singleton:{wallet}"
    root = effective_funder_address(hf.get(direct), ht.get(direct))
    if root and root != wallet and root != direct:
        return f"funder:{root}"
    return f"funder:{direct}"


def _direct_and_root_funder(
    wallet: str,
    funded: Optional[dict],
    transfers: Optional[dict],
    hop_funded: dict[str, Optional[dict]],
    hop_transfers: dict[str, Any],
) -> tuple[Optional[str], Optional[str]]:
    """(direct_funder, root_funder_or_None). Root is set only when a distinct 2-hop parent exists."""
    direct = effective_funder_address(funded, transfers)
    if not direct:
        return None, None
    root = effective_funder_address(hop_funded.get(direct), hop_transfers.get(direct))
    if root and root != wallet and root != direct:
        return direct, root
    return direct, None


def _balance_ui_for_mint(owner: str, mint: str) -> Optional[float]:
    """Best-effort token balance for mint from Helius wallet balances API."""
    out = helius_wallet_balances(owner, limit=200, show_zero_balance=True)
    if not out or not isinstance(out, dict):
        return None
    tokens = out.get("tokens")
    if not isinstance(tokens, list):
        return None
    for t in tokens:
        if not isinstance(t, dict):
            continue
        m = t.get("mint") or (t.get("token") or {}).get("mint")
        if m != mint:
            continue
        ui = t.get("uiAmount")
        if ui is not None:
            try:
                return float(ui)
            except (TypeError, ValueError):
                pass
        raw = t.get("amount")
        dec = int(t.get("decimals") or 0)
        if raw is not None:
            try:
                return float(raw) / (10**dec)
            except (TypeError, ValueError, ZeroDivisionError):
                pass
    return 0.0


def _owner_amount_from_das_rows(rows: list[dict[str, Any]], decimals: int) -> dict[str, float]:
    owner_amount: dict[str, float] = defaultdict(float)
    dec = max(0, int(decimals))
    scale = float(10**dec)
    if scale <= 0:
        scale = 1.0
    for r in rows:
        owner = r.get("owner")
        amt = r.get("amount")
        if not isinstance(owner, str) or not owner or amt is None:
            continue
        try:
            owner_amount[owner] += float(int(amt)) / scale
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    return dict(owner_amount)


def _holders_via_largest_accounts(mint: str, mh: int) -> tuple[dict[str, float], Optional[str]]:
    """
    Standard RPC getTokenLargestAccounts (typically max ~20 accounts). Fallback when DAS is empty.
    """
    largest_raw, err2 = helius_json_rpc_ex("getTokenLargestAccounts", [mint])
    if err2:
        return {}, err2
    if largest_raw is None:
        return {}, "getTokenLargestAccounts returned empty"
    largest_list = largest_raw.get("value")
    if not isinstance(largest_list, list):
        return {}, "Unexpected getTokenLargestAccounts shape"

    entries = largest_list[:mh]
    token_account_addrs = [e.get("address") for e in entries if isinstance(e, dict) and e.get("address")]
    ui_from_largest: dict[str, float] = defaultdict(float)

    for e in entries:
        if not isinstance(e, dict):
            continue
        addr = e.get("address")
        if not addr:
            continue
        ui = e.get("uiAmount")
        if ui is not None:
            try:
                ui_from_largest[addr] = float(ui)
            except (TypeError, ValueError):
                ui_from_largest[addr] = 0.0

    owner_rows: list[dict[str, Any]] = []
    for i in range(0, len(token_account_addrs), 100):
        batch = token_account_addrs[i : i + 100]
        mult, m_err = helius_json_rpc_ex(
            "getMultipleAccounts",
            [batch, {"encoding": "jsonParsed"}],
        )
        if m_err:
            return {}, f"getMultipleAccounts: {m_err}"
        if not isinstance(mult, dict):
            return {}, "getMultipleAccounts unexpected result"
        acc_list = mult.get("value")
        if not isinstance(acc_list, list):
            return {}, "getMultipleAccounts missing value list"
        for j, acc in enumerate(acc_list):
            ta = batch[j] if j < len(batch) else None
            owner = _parse_token_account_owner(acc)
            ui_ta = ui_from_largest.get(ta or "")
            parsed_amt = _parse_token_account_ui_amount(acc)
            if not owner:
                continue
            try:
                uif = float(ui_ta) if ui_ta is not None and ui_ta != "" else 0.0
            except (TypeError, ValueError):
                uif = 0.0
            amount_ui = uif if uif > 0 else parsed_amt
            owner_rows.append(
                {
                    "token_account": ta,
                    "owner": owner,
                    "amount_ui": amount_ui,
                }
            )

    owner_amount: dict[str, float] = defaultdict(float)
    for row in owner_rows:
        owner_amount[row["owner"]] += float(row.get("amount_ui") or 0.0)
    return dict(owner_amount), None


def run_bundle_snapshot(
    mint: str,
    seed_wallet: Optional[str] = None,
    *,
    max_holders: Optional[int] = None,
    max_funded_by_lookups: Optional[int] = None,
    funded_by_delay_sec: float = 0.05,
    exclude_wallets: Optional[list[str]] = None,
    skip_liquidity_wallet: bool = True,
    include_x_intel: Optional[bool] = None,
) -> dict[str, Any]:
    """
    Fetch token supply, holder token accounts (Helius DAS getTokenAccounts, paginated), cluster by funder.

    - mint: SPL token mint address.
    - seed_wallet: optional wallet to focus cluster and balance stats.
    - max_holders: legacy cap when using largest-accounts fallback only (default 100).
    - max_funded_by_lookups: Helius funded-by + /transfers per distinct wallet (default 100).
    - exclude_wallets: optional owner addresses to skip in fund-by scan (e.g. known LP).
    - skip_liquidity_wallet: if True, drop the #1 holder from scans when they hold >= SOLANA_BUNDLE_LP_SKIP_MIN_PCT
      of supply (heuristic for pool/vault wallet).
    - include_x_intel: if True, search X for wallet mentions when X_API_BEARER_TOKEN or NITTER_BASE_URL is set.
      False disables; None uses env SOLANA_BUNDLE_X_INTEL (default auto = on when configured).
    """
    mint = normalize_solana_address(mint) or ""
    if not mint:
        return {"ok": False, "error": "Invalid mint address"}

    sw: Optional[str] = None
    if seed_wallet:
        sw = normalize_solana_address(seed_wallet)
        if not sw:
            return {"ok": False, "error": "Invalid wallet address"}

    mh = max_holders if max_holders is not None else int(os.environ.get("SOLANA_BUNDLE_MAX_HOLDERS", "100"))
    mf = (
        max_funded_by_lookups
        if max_funded_by_lookups is not None
        else int(os.environ.get("SOLANA_BUNDLE_MAX_FUNDED_BY", "120"))
    )
    mh = max(5, min(mh, 200))
    mf = max(5, min(mf, 150))
    # Helius Wallet API allows max 100 transfers per request (larger values error or fail open).
    tr_limit = max(1, min(int(os.environ.get("SOLANA_BUNDLE_FUNDER_TRANSFERS_LIMIT", "100")), 100))

    supply_raw, err = helius_json_rpc_ex("getTokenSupply", [mint])
    if err:
        return {"ok": False, "error": f"getTokenSupply: {err}"}
    if not supply_raw or not isinstance(supply_raw, dict):
        return {"ok": False, "error": "getTokenSupply returned empty"}

    supply_val = supply_raw.get("value") or {}
    total_ui = supply_val.get("uiAmount")
    if total_ui is None:
        try:
            amt = float(supply_val.get("amount", 0))
            dec = int(supply_val.get("decimals", 0))
            total_ui = amt / (10**dec) if dec >= 0 else 0.0
        except (TypeError, ValueError, ZeroDivisionError):
            total_ui = 0.0
    else:
        try:
            total_ui = float(total_ui)
        except (TypeError, ValueError):
            total_ui = 0.0

    if total_ui <= 0:
        return {
            "ok": False,
            "error": (
                "Token supply is zero or unreadable. This mint may be invalid, not an SPL token on mainnet, "
                "or the RPC returned no data."
            ),
        }

    supply_decimals = int(supply_val.get("decimals", 0))
    das_pages = max(1, int(os.environ.get("SOLANA_BUNDLE_DAS_MAX_PAGES", "45")))
    das_rows, das_err = helius_das_token_accounts_for_mint(
        mint, max_pages=das_pages, page_limit=100
    )
    holder_source = "das"
    owner_amount: dict[str, float] = defaultdict(float)
    if das_rows:
        owner_amount.update(_owner_amount_from_das_rows(das_rows, supply_decimals))
    if not owner_amount:
        holder_source = "largest_accounts"
        oa_fb, err_la = _holders_via_largest_accounts(mint, mh)
        if err_la:
            msg = err_la
            if das_err:
                msg = f"Holders (DAS): {das_err}; fallback: {err_la}"
            return {"ok": False, "error": msg}
        owner_amount.update(oa_fb)

    owners_sorted = sorted(owner_amount.keys(), key=lambda w: owner_amount[w], reverse=True)

    exclude_norm: set[str] = set()
    for x in exclude_wallets or []:
        ax = normalize_solana_address(x) if isinstance(x, str) else None
        if ax:
            exclude_norm.add(ax)

    excluded_lp: Optional[str] = None
    lp_min_pct = float(os.environ.get("SOLANA_BUNDLE_LP_SKIP_MIN_PCT", "12"))
    scan_exclude = set(exclude_norm)
    if skip_liquidity_wallet and owners_sorted and total_ui > 0:
        top = owners_sorted[0]
        if top not in exclude_norm:
            try:
                pct0 = 100.0 * float(owner_amount.get(top, 0.0)) / float(total_ui)
            except (TypeError, ValueError, ZeroDivisionError):
                pct0 = 0.0
            if pct0 >= lp_min_pct:
                excluded_lp = top
                scan_exclude.add(top)

    # funded-by: seed + top holders until cap (skip LP / excluded wallets for API load)
    lookup_order: list[str] = []
    if sw:
        lookup_order.append(sw)
    for w in owners_sorted:
        if w in scan_exclude:
            continue
        if w not in lookup_order:
            lookup_order.append(w)
    lookup_order = lookup_order[:mf]

    if not lookup_order:
        return {
            "ok": False,
            "error": (
                "No holder wallets to scan after liquidity / manual exclusions. "
                "Add a focus wallet, clear exclude_wallets, or set SOLANA_BUNDLE_LP_SKIP_MIN_PCT to 100+ to disable LP auto-skip."
            ),
        }

    funded_by: dict[str, Optional[dict]] = {}
    transfers_by: dict[str, Any] = {}

    def _fetch_intel(w: str) -> tuple[str, Optional[dict], Any]:
        fb = helius_wallet_funded_by(w)
        tr = helius_transfers(w, limit=tr_limit)
        fb_d = fb if isinstance(fb, dict) else None
        if isinstance(tr, dict):
            tr_o: Any = tr
        elif isinstance(tr, list):
            tr_o = tr
        else:
            tr_o = None
        return w, fb_d, tr_o

    n_w = len(lookup_order)
    if n_w == 1:
        w0 = lookup_order[0]
        ww, fb_d, tr_o = _fetch_intel(w0)
        funded_by[ww] = fb_d
        transfers_by[ww] = tr_o
    elif n_w > 1:
        workers = min(12, max(4, n_w))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_fetch_intel, w): w for w in lookup_order}
            for fut in concurrent.futures.as_completed(futs, timeout=480):
                w0 = futs[fut]
                try:
                    ww, fb_d, tr_o = fut.result(timeout=120)
                    funded_by[ww] = fb_d
                    transfers_by[ww] = tr_o
                except Exception:
                    funded_by[w0] = None
                    transfers_by[w0] = None

    hop_funded_by: dict[str, Optional[dict]] = {}
    hop_transfers_by: dict[str, Any] = {}
    hop_max = max(0, int(os.environ.get("SOLANA_BUNDLE_FUNDER_HOP2_MAX", "56")))
    hop_targets: list[str] = []
    if hop_max > 0:
        funder_counts: Counter[str] = Counter()
        for w in lookup_order:
            d = effective_funder_address(funded_by.get(w), transfers_by.get(w))
            if d:
                funder_counts[d] += 1
        hop_targets = [a for a, _ in funder_counts.most_common(hop_max)]

        def _fetch_hop_intel(addr: str) -> tuple[str, Optional[dict], Any]:
            fb = helius_wallet_funded_by(addr)
            tr = helius_transfers(addr, limit=tr_limit)
            fb_d = fb if isinstance(fb, dict) else None
            if isinstance(tr, dict):
                tr_o: Any = tr
            elif isinstance(tr, list):
                tr_o = tr
            else:
                tr_o = None
            return addr, fb_d, tr_o

        if hop_targets:
            hw = min(12, max(3, len(hop_targets)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=hw) as pool:
                hfuts = {pool.submit(_fetch_hop_intel, a): a for a in hop_targets}
                for fut in concurrent.futures.as_completed(hfuts, timeout=420):
                    a0 = hfuts[fut]
                    try:
                        aa, fb_d, tr_o = fut.result(timeout=120)
                        hop_funded_by[aa] = fb_d
                        hop_transfers_by[aa] = tr_o
                    except Exception:
                        hop_funded_by[a0] = None
                        hop_transfers_by[a0] = None

    # Build clusters (ultimate funder when 2-hop data ties intermediaries to one source)
    cluster_members: dict[str, set[str]] = defaultdict(set)
    for w in lookup_order:
        fk = _cluster_key_sources(
            w,
            funded_by.get(w),
            transfers_by.get(w),
            hop_funded=hop_funded_by,
            hop_transfers=hop_transfers_by,
        )
        cluster_members[fk].add(w)

    # Focus cluster
    focus_cluster_key: Optional[str] = None
    if sw:
        focus_cluster_key = _cluster_key_sources(
            sw,
            funded_by.get(sw),
            transfers_by.get(sw),
            hop_funded=hop_funded_by,
            hop_transfers=hop_transfers_by,
        )
    else:
        # Largest multi-wallet cluster by supply
        best_key = None
        best_supply = 0.0
        for ck, members in cluster_members.items():
            if not ck.startswith("funder:"):
                continue
            if len(members) < 2:
                continue
            s = sum(owner_amount.get(x, 0.0) for x in members)
            if s > best_supply:
                best_supply = s
                best_key = ck
        focus_cluster_key = best_key

    focus_members: set[str] = set()
    if focus_cluster_key and focus_cluster_key in cluster_members:
        focus_members = set(cluster_members[focus_cluster_key])

    seed_balance_ui: Optional[float] = None
    if sw:
        seed_balance_ui = _balance_ui_for_mint(sw, mint)
        if seed_balance_ui is None:
            seed_balance_ui = owner_amount.get(sw)
        if focus_cluster_key and sw not in focus_members:
            fk = _cluster_key_sources(
                sw,
                funded_by.get(sw),
                transfers_by.get(sw),
                hop_funded=hop_funded_by,
                hop_transfers=hop_transfers_by,
            )
            if fk == focus_cluster_key:
                focus_members.add(sw)

    def supply_pct(amount: float) -> float:
        if total_ui <= 0:
            return 0.0
        return round(100.0 * amount / total_ui, 4)

    cluster_supply_ui = 0.0
    for w in focus_members:
        bal = owner_amount.get(w, 0.0)
        if w == sw and seed_balance_ui is not None:
            bal = max(float(bal), float(seed_balance_ui))
        cluster_supply_ui += bal

    seed_pct = supply_pct(float(seed_balance_ui or 0.0)) if sw and seed_balance_ui is not None else None

    token_metadata: Optional[dict[str, Any]] = None
    try:
        das_asset = helius_das_asset(mint)
        token_metadata = token_metadata_from_das_asset(das_asset)
    except Exception:
        token_metadata = None

    id_targets: set[str] = set(focus_members)
    for w in owners_sorted[:40]:
        id_targets.add(w)
    if sw:
        id_targets.add(sw)
    id_addrs = sorted(id_targets)[:100]
    identities: Optional[list] = None
    identity_by_wallet: dict[str, dict[str, Any]] = {}
    if id_addrs:
        identities = helius_batch_identity(id_addrs)
        identity_by_wallet = normalize_batch_identity_map(identities)

    holders_out = []
    for w in owners_sorted[:20]:
        d_fund, r_fund = _direct_and_root_funder(
            w,
            funded_by.get(w),
            transfers_by.get(w),
            hop_funded_by,
            hop_transfers_by,
        )
        idrow = identity_by_wallet.get(w)
        ident_payload: Optional[dict[str, Any]] = None
        if idrow and idrow.get("primary_label"):
            ident_payload = {
                "label": idrow.get("primary_label"),
                "type": idrow.get("type"),
                "category": idrow.get("category"),
                "tags": idrow.get("tags") or [],
                "domain_names": idrow.get("domain_names") or [],
            }
        elif idrow and (idrow.get("category") or idrow.get("type")):
            ident_payload = {
                "label": (idrow.get("category") or idrow.get("type") or "")[:120],
                "type": idrow.get("type"),
                "category": idrow.get("category"),
                "tags": idrow.get("tags") or [],
                "domain_names": idrow.get("domain_names") or [],
            }
        if idrow:
            fl = {
                "cex_tagged": is_cex_identity(idrow),
                "privacy_mixer_tagged": is_mixer_privacy_identity(idrow),
            }
            if ident_payload is not None:
                ident_payload = {**ident_payload, "intel_flags": fl}
            elif fl["cex_tagged"] or fl["privacy_mixer_tagged"]:
                ident_payload = {
                    "label": None,
                    "type": idrow.get("type"),
                    "category": idrow.get("category"),
                    "tags": idrow.get("tags") or [],
                    "domain_names": idrow.get("domain_names") or [],
                    "intel_flags": fl,
                }
        holders_out.append(
            {
                "wallet": w,
                "amount_ui": round(owner_amount[w], 8),
                "pct_supply": supply_pct(owner_amount[w]),
                "funder": d_fund,
                "funder_root": r_fund,
                "in_focus_cluster": w in focus_members if focus_members else False,
                "identity": ident_payload,
            }
        )

    x_intel_by_wallet: dict[str, dict[str, Any]] = {}
    if _should_fetch_x_intel(include_x_intel):
        try:
            from x_bundle_intel import enrich_wallets_x_intel

            max_x = max(1, min(int(os.environ.get("SOLANA_BUNDLE_X_INTEL_MAX", "12")), 25))
            delay_x = float(os.environ.get("SOLANA_BUNDLE_X_INTEL_DELAY_SEC", "0.45"))
            per_w = max(5, min(int(os.environ.get("SOLANA_BUNDLE_X_INTEL_RESULTS", "10")), 30))
            x_targets: list[str] = []
            for row in holders_out[:15]:
                wa = row.get("wallet")
                if isinstance(wa, str) and _ADDR_RE.match(wa):
                    x_targets.append(wa)
            if sw and sw not in x_targets:
                x_targets.insert(0, sw)
            x_intel_by_wallet = enrich_wallets_x_intel(
                x_targets,
                max_wallets=max_x,
                max_results_per_wallet=per_w,
                delay_sec=delay_x,
            )
            for row in holders_out:
                wa = row.get("wallet")
                if isinstance(wa, str) and wa in x_intel_by_wallet:
                    row["x_intel"] = x_intel_by_wallet[wa]
        except Exception:
            pass

    disclaimer = (
        "Heuristic only: clusters prefer a shared *2-hop* ultimate funder when Helius returns funding data "
        "for intermediate wallets (otherwise direct first inbound SOL / funded-by). Coordination signals "
        "sample more transfers and enhanced txs by default (slower, deeper). Not financial advice."
    )

    focus_note: Optional[str] = None
    if not focus_cluster_key and not sw:
        focus_note = (
            "No multi-wallet cluster with a shared ultimate funder in this sample. "
            "Optional: enter a wallet to focus that address’s funder-linked group."
        )

    funder_root_by_wallet: dict[str, Optional[str]] = {}
    for w in lookup_order:
        _d_f, _r_f = _direct_and_root_funder(
            w,
            funded_by.get(w),
            transfers_by.get(w),
            hop_funded_by,
            hop_transfers_by,
        )
        funder_root_by_wallet[w] = _r_f if (_r_f and _d_f and _r_f != _d_f) else None

    bundle_signals: Optional[dict[str, Any]] = None
    try:
        bundle_signals = compute_coordination_bundle(
            lookup_wallets=lookup_order,
            funded_by=funded_by,
            owner_amount=dict(owner_amount),
            mint=mint,
            focus_wallets=sorted(focus_members),
            transfers_cache_preload=transfers_by,
            funder_root_by_wallet=funder_root_by_wallet,
        )
    except Exception as e:
        bundle_signals = {
            "coordination_score": 0.0,
            "coordination_reasons": [],
            "error": str(e),
        }


    cross_chain: Optional[dict[str, Any]] = None
    try:
        from cross_chain_hints import lookup_solana_mint, summarize_cross_chain_payload

        _sym = (token_metadata or {}).get("symbol") if isinstance(token_metadata, dict) else None
        _nm = (token_metadata or {}).get("name") if isinstance(token_metadata, dict) else None
        cross_chain = lookup_solana_mint(
            mint, token_symbol=_sym if isinstance(_sym, str) else None,
            token_name=_nm if isinstance(_nm, str) else None,
        )
        if isinstance(cross_chain, dict):
            cross_chain = dict(cross_chain)
            cross_chain["summary"] = summarize_cross_chain_payload(cross_chain)
    except Exception as _xc_err:
        cross_chain = {
            "mint": mint, "candidates": [], "sources": [],
            "error": str(_xc_err),
            "summary": {"kind": "error", "error": str(_xc_err), "candidate_count": 0, "sources": [], "explorer_links": [], "has_high_tier": False},
        }


    return {
        "ok": True,
        "mint": mint,
        "token_metadata": token_metadata,
        "token_supply_ui": total_ui,
        "seed_wallet": sw,
        "seed_balance_ui": round(float(seed_balance_ui), 8) if seed_balance_ui is not None else None,
        "seed_pct_supply": seed_pct,
        "focus_cluster_key": focus_cluster_key,
        "focus_cluster_wallets": sorted(focus_members),
        "focus_cluster_supply_ui": round(cluster_supply_ui, 8),
        "focus_cluster_pct_supply": supply_pct(cluster_supply_ui),
        "focus_cluster_note": focus_note,
        "top_holders": holders_out,
        "identities": identities,
        "excluded_liquidity_wallet": excluded_lp,
        "params": {
            "max_holders": mh,
            "max_funded_by_lookups": mf,
            "funder_transfers_limit": tr_limit,
            "holder_fetch_source": holder_source,
            "das_max_pages": das_pages,
            "das_token_account_rows": len(das_rows) if holder_source == "das" else 0,
            "unique_holders_sampled": len(owners_sorted),
            "lp_skip_min_pct": lp_min_pct,
            "funder_hop2_max": hop_max,
            "funder_hop2_wallets_fetched": len(hop_targets),
            "deep_bundle_scan": True,
            "include_x_intel": include_x_intel,
            "x_intel_wallets_with_hits": len(x_intel_by_wallet),
        },
        "disclaimer": disclaimer,
        "pnl_note": "PnL not computed here; use an explorer or portfolio tool for full buy/sell history.",
        "cross_chain": cross_chain,
        "bundle_signals": bundle_signals,
    }
