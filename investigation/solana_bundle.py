"""
Solana token bundle snapshot: top holders + shared-funder clustering (Helius), plus
multi-signal coordination heuristics (solana_bundle_signals.compute_coordination_bundle).

Also surfaces parallel CEX-funder clusters and privacy/mixer-tagged shared funders, optional
X (Twitter) mention search per holder when X_API_BEARER_TOKEN or NITTER_BASE_URL is set
(see x_bundle_intel.py; omitted when there are no hits).

The Chrome extension runs the same logic client-side (extension/solana_bundle.js) with a
user-supplied Helius key (no X from the extension). This module is for Python callers and
the dashboard API with HELIUS_API_KEY in the environment.

Cross-chain bundle intel: `cross_chain_bundle` merges Wormhole/CoinGecko-style mint mappings with
bridge/mixer signals (including optional `SOLANA_BUNDLE_FUNDER_BRIDGE_ENHANCED_MAX` funder tx samples
for bridge program IDs on funding paths; set to 0 to disable extra calls).
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
_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
_TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
_LP_STRONG_MARKERS = (
    "liquidity pool",
    "amm pool",
    "pool vault",
    "lp vault",
    "whirlpool",
    "clmm",
    "concentrated liquidity",
)
_LP_POOL_WORDS = ("pool", "liquidity", "amm", "lp", "vault", "whirlpool", "clmm")
_LP_DEX_WORDS = ("raydium", "orca", "meteora", "saber", "lifinity", "goosefx", "fluxbeam")


def _extract_token2022_security_signals(das_asset: Optional[dict]) -> dict[str, Any]:
    """
    Parse DAS asset payload for token program and extension-linked risk indicators.

    Returns a normalized object:
      {
        "program_id": str|None,
        "token_standard": "spl-token"|"token-2022"|"unknown",
        "extensions": [str, ...],
        "authority_signals": [str, ...],
        "risk_flags": [str, ...],
        "risk_level": "low"|"medium"|"high",
        "notes": [str, ...],
      }
    """
    out: dict[str, Any] = {
        "program_id": None,
        "token_standard": "unknown",
        "extensions": [],
        "authority_signals": [],
        "risk_flags": [],
        "risk_level": "low",
        "notes": [],
    }
    if not isinstance(das_asset, dict):
        return out

    token_info = das_asset.get("token_info") if isinstance(das_asset.get("token_info"), dict) else {}
    mint_extensions = (
        token_info.get("extensions")
        if isinstance(token_info.get("extensions"), list)
        else token_info.get("token_extensions")
        if isinstance(token_info.get("token_extensions"), list)
        else []
    )
    ext_norm: list[str] = []
    for ex in mint_extensions[:40]:
        if isinstance(ex, str) and ex.strip():
            ext_norm.append(ex.strip()[:80])
        elif isinstance(ex, dict):
            name = ex.get("name") or ex.get("extension") or ex.get("type")
            if isinstance(name, str) and name.strip():
                ext_norm.append(name.strip()[:80])
    out["extensions"] = sorted(set(ext_norm))

    ownership = das_asset.get("ownership") if isinstance(das_asset.get("ownership"), dict) else {}
    authorities = token_info.get("authorities") if isinstance(token_info.get("authorities"), dict) else {}
    mint_authority = (
        authorities.get("mint_authority")
        or token_info.get("mint_authority")
        or token_info.get("mintAuthority")
    )
    freeze_authority = (
        authorities.get("freeze_authority")
        or token_info.get("freeze_authority")
        or token_info.get("freezeAuthority")
    )
    close_authority = (
        authorities.get("close_authority")
        or token_info.get("close_authority")
        or token_info.get("closeAuthority")
    )
    permanent_delegate = (
        authorities.get("permanent_delegate")
        or token_info.get("permanent_delegate")
        or token_info.get("permanentDelegate")
    )
    default_account_state = (
        token_info.get("default_account_state")
        or token_info.get("defaultAccountState")
        or authorities.get("default_account_state")
    )

    if isinstance(mint_authority, str) and mint_authority:
        out["authority_signals"].append("mint_authority_set")
    if isinstance(freeze_authority, str) and freeze_authority:
        out["authority_signals"].append("freeze_authority_set")
    if isinstance(close_authority, str) and close_authority:
        out["authority_signals"].append("close_authority_set")
    if isinstance(permanent_delegate, str) and permanent_delegate:
        out["authority_signals"].append("permanent_delegate_set")
    if isinstance(default_account_state, str) and default_account_state.strip():
        out["authority_signals"].append(f"default_account_state:{default_account_state.strip().lower()[:24]}")

    interface = str(das_asset.get("interface") or "").strip().lower()
    prog = (
        token_info.get("token_program")
        or token_info.get("program_id")
        or token_info.get("programId")
        or ownership.get("owner")
        or ""
    )
    prog_s = str(prog).strip()
    if prog_s:
        out["program_id"] = prog_s

    if prog_s == _TOKEN_2022_PROGRAM_ID or "token-2022" in interface or "token_2022" in interface:
        out["token_standard"] = "token-2022"
    elif prog_s == _TOKEN_PROGRAM_ID or "fungible" in interface or "token" in interface:
        out["token_standard"] = "spl-token"

    ext_low = [e.lower() for e in out["extensions"]]
    risky_ext_markers = (
        "transferfee",
        "transfer_fee",
        "permanentdelegate",
        "permanent_delegate",
        "defaultaccountstate",
        "default_account_state",
        "metadata_pointer",
        "group_pointer",
        "closeauthority",
        "close_authority",
    )
    for m in risky_ext_markers:
        if any(m in e for e in ext_low):
            out["risk_flags"].append(f"extension:{m}")
    for s in out["authority_signals"]:
        if s in {"mint_authority_set", "freeze_authority_set", "permanent_delegate_set"}:
            out["risk_flags"].append(f"authority:{s}")

    score = len(out["risk_flags"])
    if score >= 4:
        out["risk_level"] = "high"
    elif score >= 2:
        out["risk_level"] = "medium"
    else:
        out["risk_level"] = "low"

    if out["token_standard"] == "token-2022":
        out["notes"].append(
            "Token-2022 extensions can change transfer/authority assumptions; validate extension behavior before trust decisions."
        )
    if "mint_authority_set" in out["authority_signals"]:
        out["notes"].append("Mint authority is still set; additional minting remains possible unless revoked.")
    if "freeze_authority_set" in out["authority_signals"]:
        out["notes"].append("Freeze authority is set; holders can be frozen if authority is misused.")
    return out


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


def _identity_blob(ident: Optional[dict]) -> str:
    if not ident or not isinstance(ident, dict):
        return ""
    parts: list[str] = []
    for k in ("primary_label", "label", "name", "displayName", "type", "category", "entityName"):
        v = ident.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.strip().lower())
    tags = ident.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, str) and t.strip():
                parts.append(t.strip().lower())
    domains = ident.get("domain_names")
    if isinstance(domains, list):
        for d in domains:
            if isinstance(d, str) and d.strip():
                parts.append(d.strip().lower())
    return " | ".join(parts)


def _looks_like_liquidity_pool_identity(ident: Optional[dict]) -> bool:
    blob = _identity_blob(ident)
    if not blob:
        return False
    if any(mark in blob for mark in _LP_STRONG_MARKERS):
        return True
    has_pool_word = any(w in blob for w in _LP_POOL_WORDS)
    has_dex_word = any(w in blob for w in _LP_DEX_WORDS)
    if has_pool_word and has_dex_word:
        return True
    cat = str((ident or {}).get("category") or "").strip().lower()
    typ = str((ident or {}).get("type") or "").strip().lower()
    if any(x in cat for x in ("pool", "liquidity", "amm", "vault")):
        return has_pool_word or has_dex_word
    if any(x in typ for x in ("pool", "liquidity", "amm", "vault")):
        return has_pool_word or has_dex_word
    return False


def holder_supply_cluster_key(wallet: str, funder_chain: list[str]) -> str:
    """
    Cluster holders by shared *direct* first funder (first inbound hop), not the multi-hop terminal.

    Using chain[-1] over-merges holders who only share a distant CEX/mixer and mislabels focus
    clusters versus common 'same funder' holder tooling; direct funder matches token-holder triage.
    """
    ch = funder_chain if isinstance(funder_chain, list) else []
    if len(ch) >= 2:
        direct = ch[1]
        if isinstance(direct, str) and direct and direct != wallet and _ADDR_RE.match(direct):
            return f"funder:{direct}"
    return f"singleton:{wallet}"


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
    scan_all_holders: bool = False,
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
    - scan_all_holders: when True, scan all discovered holder wallets after exclusions.
    - exclude_wallets: optional owner addresses to skip in fund-by scan (e.g. known LP).
    - skip_liquidity_wallet: if True, skip probable LP wallets from scans:
      (a) #1 holder when it owns >= SOLANA_BUNDLE_LP_SKIP_MIN_PCT of supply
      (b) identity-tagged pool/vault/AMM wallets above SOLANA_BUNDLE_LP_IDENTITY_SKIP_MIN_PCT.
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
    mf_raw = (
        max_funded_by_lookups
        if max_funded_by_lookups is not None
        else int(os.environ.get("SOLANA_BUNDLE_MAX_FUNDED_BY", "120"))
    )
    mh = max(5, min(mh, 200))
    # default mode is still bounded; explicit per-call values can be larger
    mf = max(5, min(int(mf_raw), 5000))
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
    excluded_lp_wallets: set[str] = set()
    excluded_lp_reasons: dict[str, str] = {}
    lp_min_pct = float(os.environ.get("SOLANA_BUNDLE_LP_SKIP_MIN_PCT", "12"))
    lp_identity_min_pct = float(os.environ.get("SOLANA_BUNDLE_LP_IDENTITY_SKIP_MIN_PCT", "0.2"))
    lp_identity_probe_n = max(10, min(int(os.environ.get("SOLANA_BUNDLE_LP_IDENTITY_PROBE_N", "60")), 120))
    scan_exclude = set(exclude_norm)
    prefetched_identity_by_wallet: dict[str, dict[str, Any]] = {}
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
                excluded_lp_wallets.add(top)
                excluded_lp_reasons[top] = f"top_holder_pct>={round(lp_min_pct, 4)}"

    if skip_liquidity_wallet and owners_sorted:
        probe_targets = owners_sorted[:lp_identity_probe_n]
        try:
            prefetched_identity_by_wallet = normalize_batch_identity_map(helius_batch_identity(probe_targets))
        except Exception:
            prefetched_identity_by_wallet = {}
        for w in probe_targets:
            if w in exclude_norm or w in scan_exclude:
                continue
            try:
                wpct = 100.0 * float(owner_amount.get(w, 0.0)) / float(total_ui)
            except (TypeError, ValueError, ZeroDivisionError):
                wpct = 0.0
            if wpct < lp_identity_min_pct:
                continue
            if _looks_like_liquidity_pool_identity(prefetched_identity_by_wallet.get(w)):
                scan_exclude.add(w)
                excluded_lp_wallets.add(w)
                excluded_lp_reasons[w] = f"identity_lp_pool_tag_pct>={round(lp_identity_min_pct, 4)}"
                if excluded_lp is None:
                    excluded_lp = w

    # funded-by: seed + top holders until cap (skip LP / excluded wallets for API load)
    lookup_order: list[str] = []
    if sw:
        lookup_order.append(sw)
    for w in owners_sorted:
        if w in scan_exclude:
            continue
        if w not in lookup_order:
            lookup_order.append(w)
    holders_eligible_n = len(lookup_order)
    if scan_all_holders:
        mf = max(mf, holders_eligible_n)
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
            all_timeout = max(480, n_w * 8)
            for fut in concurrent.futures.as_completed(futs, timeout=all_timeout):
                w0 = futs[fut]
                try:
                    ww, fb_d, tr_o = fut.result(timeout=180)
                    funded_by[ww] = fb_d
                    transfers_by[ww] = tr_o
                except Exception:
                    funded_by[w0] = None
                    transfers_by[w0] = None

    # N-hop recursive funder chain walk (replaces fixed 2-hop)
    max_hops = max(1, min(int(os.environ.get("SOLANA_BUNDLE_FUNDER_MAX_HOPS", "4")), 6))
    hop_budget = max(0, int(os.environ.get("SOLANA_BUNDLE_FUNDER_HOP2_MAX", "56")))

    all_funded_by: dict[str, Optional[dict]] = dict(funded_by)
    all_transfers_by: dict[str, Any] = dict(transfers_by)

    funder_chain_by_wallet: dict[str, list[str]] = {}
    for w in lookup_order:
        chain: list[str] = [w]
        d = effective_funder_address(all_funded_by.get(w), all_transfers_by.get(w))
        if d and d != w:
            chain.append(d)
        funder_chain_by_wallet[w] = chain

    total_hop_fetches = 0
    for _hop_level in range(2, max_hops + 1):
        if hop_budget <= 0:
            break
        tip_counts: Counter[str] = Counter()
        for _cw, _chain in funder_chain_by_wallet.items():
            if len(_chain) < _hop_level:
                continue
            tip = _chain[-1]
            if tip not in all_funded_by:
                tip_counts[tip] += 1
        if not tip_counts:
            break
        tips_to_fetch = [a for a, _ in tip_counts.most_common(hop_budget)]
        if not tips_to_fetch:
            break

        def _fetch_hop_n(addr: str) -> tuple[str, Optional[dict], Any]:
            fb = helius_wallet_funded_by(addr)
            tr = helius_transfers(addr, limit=tr_limit)
            fb_d = fb if isinstance(fb, dict) else None
            tr_o: Any = tr if isinstance(tr, (dict, list)) else None
            return addr, fb_d, tr_o

        if len(tips_to_fetch) == 1:
            _ha, _hfb, _htr = _fetch_hop_n(tips_to_fetch[0])
            all_funded_by[_ha] = _hfb
            all_transfers_by[_ha] = _htr
        else:
            _hw = min(12, max(3, len(tips_to_fetch)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=_hw) as pool:
                _hfuts = {pool.submit(_fetch_hop_n, a): a for a in tips_to_fetch}
                for fut in concurrent.futures.as_completed(_hfuts, timeout=max(420, len(tips_to_fetch) * 8)):
                    _a0 = _hfuts[fut]
                    try:
                        _ha, _hfb, _htr = fut.result(timeout=180)
                        all_funded_by[_ha] = _hfb
                        all_transfers_by[_ha] = _htr
                    except Exception:
                        all_funded_by[_a0] = None
                        all_transfers_by[_a0] = None
        total_hop_fetches += len(tips_to_fetch)

        for _cw, _chain in funder_chain_by_wallet.items():
            if len(_chain) < _hop_level:
                continue
            tip = _chain[-1]
            nxt = effective_funder_address(all_funded_by.get(tip), all_transfers_by.get(tip))
            if nxt and nxt not in set(_chain):
                _chain.append(nxt)

    # Backward-compat dicts for legacy helpers
    hop_funded_by: dict[str, Optional[dict]] = {k: v for k, v in all_funded_by.items() if k not in funded_by}
    hop_transfers_by: dict[str, Any] = {k: v for k, v in all_transfers_by.items() if k not in transfers_by}

    # Build holder clusters by direct first funder (see holder_supply_cluster_key)
    cluster_members: dict[str, set[str]] = defaultdict(set)
    for w in lookup_order:
        _ch = funder_chain_by_wallet.get(w, [w])
        _ck = holder_supply_cluster_key(w, _ch)
        cluster_members[_ck].add(w)

    focus_cluster_key: Optional[str] = None
    if sw:
        _sw_ch = funder_chain_by_wallet.get(sw, [sw])
        focus_cluster_key = holder_supply_cluster_key(sw, _sw_ch)
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
            _swc = funder_chain_by_wallet.get(sw, [sw])
            if holder_supply_cluster_key(sw, _swc) == focus_cluster_key:
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
    token_program_analysis: dict[str, Any] = {
        "program_id": None,
        "token_standard": "unknown",
        "extensions": [],
        "authority_signals": [],
        "risk_flags": [],
        "risk_level": "low",
        "notes": [],
    }
    try:
        das_asset = helius_das_asset(mint)
        token_metadata = token_metadata_from_das_asset(das_asset)
        token_program_analysis = _extract_token2022_security_signals(das_asset)
    except Exception:
        token_metadata = None
        token_program_analysis = {
            "program_id": None,
            "token_standard": "unknown",
            "extensions": [],
            "authority_signals": [],
            "risk_flags": [],
            "risk_level": "low",
            "notes": [],
        }

    id_targets: set[str] = set(focus_members)
    for w in owners_sorted[:40]:
        id_targets.add(w)
    if sw:
        id_targets.add(sw)
    id_addrs = sorted(id_targets)[:100]
    identities: Optional[list] = None
    identity_by_wallet: dict[str, dict[str, Any]] = dict(prefetched_identity_by_wallet)
    if id_addrs:
        missing_id_addrs = [a for a in id_addrs if a not in identity_by_wallet]
        if missing_id_addrs:
            identities = helius_batch_identity(missing_id_addrs)
            identity_by_wallet.update(normalize_batch_identity_map(identities))

    holders_out = []
    for w in owners_sorted[:20]:
        _hch = funder_chain_by_wallet.get(w, [w])
        d_fund = _hch[1] if len(_hch) >= 2 else None
        r_fund = _hch[-1] if len(_hch) >= 3 and _hch[-1] != _hch[1] else None
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
                "funder_chain": _hch[1:] if len(_hch) >= 2 else [],
                "funder_chain_depth": len(_hch) - 1,
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
        "Heuristic only: the \"focus cluster\" and per-holder cluster flag group wallets by the same "
        "*direct* first inbound SOL funder (first hop from Helius transfers / funded-by). "
        f"Deeper funder walks (up to {max_hops} hops) still run for coordination scoring and chain fields only. "
        "Coordination signals may sample more transfers by default (slower). Not financial advice."
    )

    focus_note: Optional[str] = None
    if not focus_cluster_key and not sw:
        focus_note = (
            "No multi-wallet cluster with a shared direct funder in this sample. "
            "Optional: enter a wallet to focus that address’s funder-linked group."
        )

    funder_root_by_wallet: dict[str, Optional[str]] = {}
    for w in lookup_order:
        _rch = funder_chain_by_wallet.get(w, [w])
        if len(_rch) >= 3:
            funder_root_by_wallet[w] = _rch[-1]
        else:
            funder_root_by_wallet[w] = None

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
            funder_chain_by_wallet=funder_chain_by_wallet,
            token_program_analysis=token_program_analysis,
            token_supply_ui=total_ui,
            top_holders=holders_out,
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

    # Fetch live Wormhole bridge transfer history for bridge-adjacent + funder chain addresses
    _bridge_transfers: dict[str, Any] = {}
    try:
        from wormhole_scan_client import resolve_counterparties as _wh_resolve

        _bridge_adj: list[str] = []
        if isinstance(bundle_signals, dict):
            _fc_raw = bundle_signals.get("funding_cluster_bridge_mixer")
            if isinstance(_fc_raw, dict):
                _bridge_adj = list(_fc_raw.get("bridge_adjacent_wallets") or [])
        _funder_chain_addrs: set[str] = set()
        for _fch in funder_chain_by_wallet.values():
            for _fa in _fch[1:]:
                _funder_chain_addrs.add(_fa)
        _wh_targets = list(dict.fromkeys(_bridge_adj + sorted(_funder_chain_addrs)))
        if _wh_targets:
            _bridge_transfers = _wh_resolve(_wh_targets)
    except Exception:
        _bridge_transfers = {}

    cross_chain_bundle: Optional[dict[str, Any]] = None
    try:
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        _fc = (bundle_signals or {}).get("funding_cluster_bridge_mixer") if isinstance(bundle_signals, dict) else None
        cross_chain_bundle = build_cross_chain_bundle_intel(
            mint=mint,
            cross_chain=cross_chain if isinstance(cross_chain, dict) else None,
            funding_cluster_bridge_mixer=_fc if isinstance(_fc, dict) else {},
            bridge_transfers=_bridge_transfers if _bridge_transfers else None,
        )
    except Exception:
        cross_chain_bundle = None

    return {
        "ok": True,
        "mint": mint,
        "token_metadata": token_metadata,
        "token_program_analysis": token_program_analysis,
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
        "excluded_liquidity_wallets": sorted(excluded_lp_wallets),
        "excluded_liquidity_wallet_reasons": excluded_lp_reasons,
        "funder_chain_by_wallet": {w: ch[1:] for w, ch in funder_chain_by_wallet.items() if len(ch) >= 2},
        "funder_chain_max_depth": max((len(ch) - 1 for ch in funder_chain_by_wallet.values()), default=0),
        "params": {
            "max_holders": mh,
            "max_funded_by_lookups": mf,
            "scan_all_holders": bool(scan_all_holders),
            "holders_eligible_after_exclusions": holders_eligible_n,
            "holders_scanned_for_funders": len(lookup_order),
            "holders_scan_coverage_pct": round((100.0 * len(lookup_order) / holders_eligible_n), 2) if holders_eligible_n else 0.0,
            "funder_transfers_limit": tr_limit,
            "holder_fetch_source": holder_source,
            "das_max_pages": das_pages,
            "das_token_account_rows": len(das_rows) if holder_source == "das" else 0,
            "unique_holders_sampled": len(owners_sorted),
            "lp_skip_min_pct": lp_min_pct,
            "lp_identity_skip_min_pct": lp_identity_min_pct,
            "lp_identity_probe_n": lp_identity_probe_n,
            "funder_max_hops": max_hops,
            "funder_hop_budget": hop_budget,
            "funder_hop_fetches_total": total_hop_fetches,
            "deep_bundle_scan": True,
            "include_x_intel": include_x_intel,
            "x_intel_wallets_with_hits": len(x_intel_by_wallet),
        },
        "disclaimer": disclaimer,
        "pnl_note": "PnL not computed here; use an explorer or portfolio tool for full buy/sell history.",
        "cross_chain": cross_chain,
        "cross_chain_bundle": cross_chain_bundle,
        "bundle_signals": bundle_signals,
    }
