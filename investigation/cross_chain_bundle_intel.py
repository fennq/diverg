"""Merge token-level cross-chain hints with bundle bridge/mixer signals for one UI/API object.

All strings are investigative context only — not proof of misconduct or same person across chains.
"""
from __future__ import annotations

from typing import Any, Optional


def build_cross_chain_bundle_intel(
    *,
    mint: str,
    cross_chain: Optional[dict[str, Any]],
    funding_cluster_bridge_mixer: Optional[dict[str, Any]],
    bridge_transfers: Optional[dict[str, list[dict[str, Any]]]] = None,
) -> dict[str, Any]:
    cc = cross_chain if isinstance(cross_chain, dict) else {}
    summary = cc.get("summary") if isinstance(cc.get("summary"), dict) else {}
    fc = funding_cluster_bridge_mixer if isinstance(funding_cluster_bridge_mixer, dict) else {}
    bt = bridge_transfers if isinstance(bridge_transfers, dict) else {}

    explorer_links = summary.get("explorer_links") if isinstance(summary.get("explorer_links"), list) else []
    candidate_count = int(summary.get("candidate_count") or 0)
    if not candidate_count and isinstance(cc.get("candidates"), list):
        candidate_count = len(cc["candidates"])

    has_foreign = candidate_count > 0 or bool(explorer_links)
    tier = str(fc.get("bridge_mixer_confidence_tier") or "low")
    bridge_n = int(fc.get("bridge_adjacent_wallet_count") or 0)
    shared_bridge = fc.get("shared_bridge_programs_multi_wallet")
    n_shared_bridge = len(shared_bridge) if isinstance(shared_bridge, list) else 0
    mixer_strict = int(fc.get("strict_mixer_cluster_max_wallets") or 0)
    any_mixer_funder = bool(fc.get("any_mixer_tagged_funder"))
    mixer_path_w = int(fc.get("wallets_with_mixer_touching_funder") or 0)
    mixer_funders_n = int(fc.get("mixer_service_funder_count") or 0)
    funder_bridge_w = int(fc.get("wallets_with_bridge_touching_funder") or 0)
    bridge_funders_n = int(fc.get("bridge_program_funder_count") or 0)

    # EVM counterparty addresses from live Wormhole Scan bridge history
    try:
        from wormhole_scan_client import extract_counterparty_evm_addresses
        counterparty_evm_addrs = extract_counterparty_evm_addresses(bt) if bt else []
    except Exception:
        counterparty_evm_addrs = []

    # bridge transfer ops trimmed to 5 per wallet to keep response lean
    bridge_transfers_by_wallet: dict[str, list[dict[str, Any]]] = {
        addr: ops[:5] for addr, ops in bt.items() if isinstance(ops, list)
    }

    investigator_notes: list[str] = []
    if has_foreign:
        investigator_notes.append(
            "This mint has registry or metadata hints on other chains — compare holder timing on Solana "
            "with wrapped/bridged supply and destination-chain explorers (official bridge docs only)."
        )
    if bridge_n >= 2 or n_shared_bridge > 0:
        investigator_notes.append(
            "Multiple sampled wallets touched known Solana bridge program IDs in recent activity — "
            "funds may have entered via cross-chain routes; trace each wallet on Solscan."
        )
    elif bridge_n == 1:
        investigator_notes.append(
            "At least one sampled wallet shows bridge-program interaction — check that wallet’s full history for inbound bridge flows."
        )
    if funder_bridge_w >= 2:
        investigator_notes.append(
            "Several holders trace (directly or via 2-hop root) to funders whose recent txs include bridge programs — "
            "possible common cross-chain on-ramp; verify on-chain, not by assumption."
        )
    elif bridge_funders_n >= 1 and funder_bridge_w >= 1:
        investigator_notes.append(
            "A sampled funder path includes bridge-program activity — expand funder analysis on explorers."
        )
    if mixer_strict >= 2 or any_mixer_funder:
        investigator_notes.append(
            "Mixer- or privacy-tagged funding appears in the sample — combine with bridge context carefully; "
            "these are independent heuristics."
        )
    if mixer_path_w >= 2:
        investigator_notes.append(
            "Multiple holders map (directly or via root) to funder paths with mixer/privacy tags — "
            "treat as risk context and verify each hop."
        )
    elif mixer_funders_n >= 1 and mixer_path_w >= 1:
        investigator_notes.append(
            "A sampled funder path includes mixer/privacy-tagged addresses — expand the funding path review."
        )
    if counterparty_evm_addrs:
        investigator_notes.append(
            f"Bridge transfers found: wallets in this sample sent/received funds to "
            f"{len(counterparty_evm_addrs)} distinct EVM address(es) via Wormhole — "
            "inspect each on Etherscan."
        )
    if has_foreign and (bridge_n >= 1 or funder_bridge_w >= 1) and (mixer_strict >= 2 or any_mixer_funder):
        investigator_notes.append(
            "Stacked signals: foreign token mapping + bridge-adjacent wallets + mixer-tagged paths — "
            "manual correlation recommended; no automatic 'same actor' conclusion."
        )

    mixer_signal = (mixer_strict >= 2 or any_mixer_funder or mixer_path_w >= 1)
    combined_escalation = (
        (
            has_foreign
            and (bridge_n >= 2 or n_shared_bridge > 0 or funder_bridge_w >= 2)
            and mixer_signal
        )
        or (
            bool(counterparty_evm_addrs)
            and (bridge_n >= 1 or funder_bridge_w >= 1)
            and mixer_signal
        )
    )

    return {
        "mint": mint,
        "has_foreign_token_candidates": has_foreign,
        "foreign_candidate_count": candidate_count,
        "foreign_explorer_links": explorer_links[:16],
        "cross_chain_sources": summary.get("sources") if isinstance(summary.get("sources"), list) else cc.get("sources"),
        "bridge_mixer_tier": tier,
        "bridge_adjacent_holder_wallet_count": bridge_n,
        "shared_bridge_program_groups": shared_bridge[:10] if isinstance(shared_bridge, list) else [],
        "strict_mixer_cluster_max_wallets": mixer_strict,
        "any_mixer_tagged_funder": any_mixer_funder,
        "wallets_with_mixer_touching_funder": mixer_path_w,
        "mixer_service_funder_count": mixer_funders_n,
        "mixer_path_hits": fc.get("mixer_path_hits") if isinstance(fc.get("mixer_path_hits"), list) else [],
        "bridge_program_funder_count": bridge_funders_n,
        "wallets_with_bridge_touching_funder": funder_bridge_w,
        "funder_bridge_hits": fc.get("funder_bridge_hits") if isinstance(fc.get("funder_bridge_hits"), list) else [],
        "bridge_transfers_by_wallet": bridge_transfers_by_wallet,
        "counterparty_evm_addresses": counterparty_evm_addrs[:20],
        "investigator_notes": investigator_notes[:8],
        "combined_escalation": combined_escalation,
        "disclaimer": (
            "Hints only: registry rows, program IDs, and Wormhole transfer records do not prove shared control, "
            "laundering, or bundle coordination across chains."
        ),
    }
