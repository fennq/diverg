"""
Solana token bundle snapshot: top holders + shared-funder clustering (Helius).
Inspired by wallet-intel / bundle-detection flows; server-side only (API keys stay on backend).
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from typing import Any, Optional

from onchain_clients import (
    helius_batch_identity,
    helius_json_rpc_ex,
    helius_wallet_balances,
    helius_wallet_funded_by,
)

# Base58 Solana address (rough)
_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


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


def _funder_address(funded: Optional[dict]) -> Optional[str]:
    if not funded or not isinstance(funded, dict):
        return None
    f = funded.get("funder")
    if isinstance(f, str) and _ADDR_RE.match(f):
        return f
    return None


def _cluster_key(wallet: str, funded: Optional[dict]) -> str:
    f = _funder_address(funded)
    if f:
        return f"funder:{f}"
    return f"singleton:{wallet}"


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


def run_bundle_snapshot(
    mint: str,
    seed_wallet: Optional[str] = None,
    *,
    max_holders: Optional[int] = None,
    max_funded_by_lookups: Optional[int] = None,
    funded_by_delay_sec: float = 0.05,
) -> dict[str, Any]:
    """
    Fetch token supply, largest accounts, resolve owners, cluster by shared direct funder.

    - mint: SPL token mint address.
    - seed_wallet: optional wallet to focus cluster and balance stats.
    - max_holders: cap largest accounts analyzed (default env SOLANA_BUNDLE_MAX_HOLDERS or 50).
    - max_funded_by_lookups: cap Helius funded-by calls (default env or 40).
    """
    mint = normalize_solana_address(mint) or ""
    if not mint:
        return {"ok": False, "error": "Invalid mint address"}

    sw: Optional[str] = None
    if seed_wallet:
        sw = normalize_solana_address(seed_wallet)
        if not sw:
            return {"ok": False, "error": "Invalid wallet address"}

    mh = max_holders if max_holders is not None else int(os.environ.get("SOLANA_BUNDLE_MAX_HOLDERS", "50"))
    mf = (
        max_funded_by_lookups
        if max_funded_by_lookups is not None
        else int(os.environ.get("SOLANA_BUNDLE_MAX_FUNDED_BY", "40"))
    )
    mh = max(5, min(mh, 100))
    mf = max(5, min(mf, 100))

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

    largest_raw, err2 = helius_json_rpc_ex("getTokenLargestAccounts", [mint])
    if err2:
        return {"ok": False, "error": f"getTokenLargestAccounts: {err2}"}
    if largest_raw is None:
        return {"ok": False, "error": "getTokenLargestAccounts returned empty"}

    largest_list = largest_raw.get("value")
    if not isinstance(largest_list, list):
        return {"ok": False, "error": "Unexpected getTokenLargestAccounts shape"}

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

    # Resolve owners via getMultipleAccounts (batches of 100)
    owner_rows: list[dict[str, Any]] = []
    for i in range(0, len(token_account_addrs), 100):
        batch = token_account_addrs[i : i + 100]
        mult, m_err = helius_json_rpc_ex(
            "getMultipleAccounts",
            [batch, {"encoding": "jsonParsed"}],
        )
        if m_err:
            return {"ok": False, "error": f"getMultipleAccounts: {m_err}"}
        if not isinstance(mult, dict):
            return {"ok": False, "error": "getMultipleAccounts unexpected result"}
        acc_list = mult.get("value")
        if not isinstance(acc_list, list):
            return {"ok": False, "error": "getMultipleAccounts missing value list"}
        for j, acc in enumerate(acc_list):
            ta = batch[j] if j < len(batch) else None
            owner = _parse_token_account_owner(acc)
            ui_ta = ui_from_largest.get(ta or "", 0.0)
            if not owner:
                continue
            owner_rows.append(
                {
                    "token_account": ta,
                    "owner": owner,
                    "amount_ui": ui_ta if ui_ta else _parse_token_account_ui_amount(acc),
                }
            )

    owner_amount: dict[str, float] = defaultdict(float)
    for row in owner_rows:
        owner_amount[row["owner"]] += float(row.get("amount_ui") or 0.0)

    owners_sorted = sorted(owner_amount.keys(), key=lambda w: owner_amount[w], reverse=True)

    # funded-by: prioritize seed + top holders until cap
    lookup_order: list[str] = []
    if sw:
        lookup_order.append(sw)
    for w in owners_sorted:
        if w not in lookup_order:
            lookup_order.append(w)
    lookup_order = lookup_order[:mf]

    funded_by: dict[str, Optional[dict]] = {}
    for w in lookup_order:
        fb = helius_wallet_funded_by(w)
        funded_by[w] = fb if isinstance(fb, dict) else None
        time.sleep(funded_by_delay_sec)

    # Build clusters (shared direct funder only)
    cluster_members: dict[str, set[str]] = defaultdict(set)
    for w in lookup_order:
        fk = _cluster_key(w, funded_by.get(w))
        cluster_members[fk].add(w)

    # Focus cluster
    focus_cluster_key: Optional[str] = None
    if sw:
        focus_cluster_key = _cluster_key(sw, funded_by.get(sw))
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
            fk = _cluster_key(sw, funded_by.get(sw))
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

    identities: Optional[list] = None
    id_addrs = list(focus_members)[:100]
    if id_addrs:
        identities = helius_batch_identity(id_addrs)

    holders_out = []
    for w in owners_sorted[:20]:
        holders_out.append(
            {
                "wallet": w,
                "amount_ui": round(owner_amount[w], 8),
                "pct_supply": supply_pct(owner_amount[w]),
                "funder": _funder_address(funded_by.get(w)),
                "in_focus_cluster": w in focus_members if focus_members else False,
            }
        )

    disclaimer = (
        "Heuristic only: clusters use the same *direct* funder from Helius funded-by. "
        "Wallets not in the sampled top holders may be missing. Not financial advice."
    )

    focus_note: Optional[str] = None
    if not focus_cluster_key and not sw:
        focus_note = (
            "No multi-wallet cluster with a shared direct funder in this sample. "
            "Optional: enter a wallet to focus that address’s funder-linked group."
        )

    return {
        "ok": True,
        "mint": mint,
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
        "params": {"max_holders": mh, "max_funded_by_lookups": mf},
        "disclaimer": disclaimer,
        "pnl_note": "PnL not computed here; use an explorer or portfolio tool for full buy/sell history.",
    }
