"""
Multi-signal bundle / coordination heuristics for Solana wallets (Helius).

Signals (all optional; best-effort from available API fields):
1) Funding time sync — wallets whose first inbound SOL lands in the same time bucket (seconds).
2) Same funding amount — first inbound SOL lamports match (exact keys, plus fuzzy merge within rel_tol).
3) CEX-tagged funder — funder has exchange-like identity (tags/name/category).
4) Parallel CEX cluster — two or more sampled wallets share the same CEX-tagged first funder.
5) Privacy/mixer-tagged funder — Helius labels suggest mixer or privacy service.
6) Privacy/mixer shared funder — multiple sampled wallets share that funder path.
7) Shared inbound counterparties — same sender appears as source for multiple wallets.
8) Mint co-movement — token activity for the target mint in the same slot (sampled txs).
9) Program overlap — Jaccard-like overlap of program IDs from parsed transactions.

Not financial advice; all scores are heuristics.
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from typing import Any, Optional

# Solana base58 address (rough)
_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
# Wrapped SOL mint — treat as inbound SOL for "who funded" (matches explorers / Axiom-style views)
_WSOL_MINT = "So11111111111111111111111111111111111111112"

from onchain_clients import (
    helius_enhanced_transactions,
    helius_transfers,
    helius_wallet_identity,
)

# Tunables via env (defaults tuned for deeper always-on bundle analysis; slower, more API calls)
FUNDING_TIME_BUCKET_SEC = float(os.environ.get("SOLANA_BUNDLE_FUNDING_BUCKET_SEC", "5"))
LAMPORTS_REL_TOL = float(os.environ.get("SOLANA_BUNDLE_LAMPORTS_REL_TOL", "0.002"))  # 0.2%
MAX_TRANSFER_FETCH = int(os.environ.get("SOLANA_BUNDLE_MAX_TRANSFER_FETCH", "72"))
MAX_ENHANCED_FETCH = int(os.environ.get("SOLANA_BUNDLE_MAX_ENHANCED_FETCH", "32"))
MAX_FUNDER_IDENTITY = int(os.environ.get("SOLANA_BUNDLE_MAX_FUNDER_IDENTITY", "56"))
# Helius enhanced txs per wallet when sampling mint co-movement / program overlap
ENHANCED_TX_LIMIT = int(os.environ.get("SOLANA_BUNDLE_ENHANCED_TX_LIMIT", "55"))
# Extra /transfers fetch during coordination pass (Helius max 100)
SIGNAL_TRANSFERS_LIMIT = max(1, min(int(os.environ.get("SOLANA_BUNDLE_SIGNAL_TRANSFERS_LIMIT", "100")), 100))


def _safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except (TypeError, ValueError):
        return None


def _safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(float(x))
    except (TypeError, ValueError):
        return None


def parse_funded_by_row(fb: Optional[dict]) -> dict[str, Any]:
    """Normalize Helius funded-by payload (field names vary)."""
    out: dict[str, Any] = {
        "funder": None,
        "lamports": None,
        "signature": None,
        "timestamp_unix": None,
        "slot": None,
    }
    if not fb or not isinstance(fb, dict):
        return out
    for k in ("funder", "fundingWallet", "funding_wallet", "from", "fromAddress", "from_address", "sender", "fundingAddress"):
        v = fb.get(k)
        if isinstance(v, str) and _ADDR_RE.match(v):
            out["funder"] = v
            break
    for k in ("lamports", "amountLamports", "amount_lamports"):
        lp = _safe_int(fb.get(k))
        if lp is not None:
            out["lamports"] = lp
            break
    if out["lamports"] is None:
        sol = _safe_float(fb.get("amountSol") or fb.get("solAmount") or fb.get("amount"))
        if sol is not None:
            out["lamports"] = int(round(sol * 1_000_000_000))
    out["signature"] = fb.get("signature") if isinstance(fb.get("signature"), str) else None
    ts = fb.get("timestamp") or fb.get("blockTime") or fb.get("time")
    if isinstance(ts, (int, float)):
        out["timestamp_unix"] = int(ts / 1000) if ts > 1e12 else int(ts)
    out["slot"] = _safe_int(fb.get("slot"))
    return out


def _iter_transfer_rows(raw: Any) -> list[dict]:
    """Normalize Helius /transfers payloads (array root, data[], or native+token arrays)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if not isinstance(raw, dict):
        return []
    for key in ("transfers", "data", "items", "results"):
        v = raw.get(key)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return [x for x in v if isinstance(x, dict)]
    merged: list[dict] = []
    for key in ("nativeTransfers", "tokenTransfers"):
        v = raw.get(key)
        if isinstance(v, list):
            merged.extend(x for x in v if isinstance(x, dict))
    if merged:
        return merged
    return []


def _mint_from_transfer_row(t: dict) -> str:
    m = t.get("mint")
    if isinstance(m, dict):
        m = m.get("mint") or m.get("address")
    elif not isinstance(m, str):
        m = None
    tok = t.get("token")
    if isinstance(tok, dict):
        m = m or tok.get("mint") or tok.get("address")
    elif isinstance(tok, str):
        m = m or tok
    return str(m or "").strip()


def extract_first_inbound_sol_from_transfers(raw: Optional[dict]) -> Optional[dict]:
    """
    Best-effort: find earliest inbound native SOL (or wSOL) transfer from Helius /transfers payload.
    Prefer this over funded-by alone — aligns with explorer / Axiom "funded by" graphs.
    Returns {lamports, timestamp_unix, signature, from_address} or None.
    """
    rows = _iter_transfer_rows(raw)
    candidates: list[dict[str, Any]] = []
    wsol_l = _WSOL_MINT.lower()
    for t in rows:
        direction = (t.get("direction") or t.get("type") or t.get("transferType") or "").lower()
        if direction in ("out", "outgoing", "sent", "send", "withdraw"):
            continue
        mint_s = _mint_from_transfer_row(t).lower()
        sym = (t.get("symbol") or "").upper()
        tok_o = t.get("token")
        if isinstance(tok_o, dict):
            tok_s = str(tok_o.get("symbol") or tok_o.get("mint") or "").lower()
        else:
            tok_s = str(tok_o or "").lower()
        is_sol = (
            t.get("isNative") is True
            or t.get("native") is True
            or sym == "SOL"
            or "sol" in tok_s
            or mint_s == wsol_l
            or (not mint_s and not t.get("mint"))
            or (not mint_s and direction in ("in", "incoming", "received", "receive"))
        )
        if not is_sol and mint_s and mint_s != wsol_l:
            continue
        if direction not in (
            "in",
            "incoming",
            "received",
            "receive",
            "inbound",
            "credit",
            "",
            "transfer",
            "unknown",
            "nft",
        ):
            if direction not in ("",) and not is_sol:
                continue
        ts = t.get("timestamp") or t.get("blockTime") or t.get("time")
        tu: Optional[int] = None
        if isinstance(ts, (int, float)):
            tu = int(ts)
            if tu > 1e12:
                tu = int(tu / 1000)
        lam = _safe_int(t.get("lamports") or t.get("amountLamports"))
        if lam is None and t.get("amountRaw") is not None:
            try:
                raw_s = str(t.get("amountRaw")).strip()
                lam = int(raw_s.split(".", 1)[0])
            except (TypeError, ValueError):
                lam = None
        if lam is None:
            amt = _safe_float(t.get("amount") or t.get("uiAmount") or t.get("tokenAmount"))
            dec = _safe_int(t.get("decimals"))
            if amt is not None:
                if dec is not None and dec >= 0:
                    lam = int(round(amt * (10 ** min(dec, 18))))
                else:
                    lam = int(round(amt * 1_000_000_000))
        sig = t.get("signature") or t.get("tx") or t.get("transactionSignature")
        # Helius Wallet API v1: counterparty = sender when direction is "in", recipient when "out"
        from_a = (
            t.get("from")
            or t.get("fromUserAccount")
            or t.get("fromAddress")
            or t.get("fromUser")
            or t.get("sender")
            or t.get("source")
            or t.get("sourceAccount")
            or t.get("counterparty")
        )
        if isinstance(from_a, dict):
            from_a = from_a.get("address") or from_a.get("pubkey")
        if lam is None or tu is None:
            continue
        if not isinstance(from_a, str) or not _ADDR_RE.match(from_a):
            continue
        candidates.append(
            {
                "lamports": lam,
                "timestamp_unix": tu,
                "signature": sig if isinstance(sig, str) else None,
                "from_address": from_a,
            }
        )
    if not candidates:
        return None
    candidates.sort(key=lambda x: x["timestamp_unix"])
    return candidates[0]


def expanded_funder_from_api(funded: Optional[dict]) -> Optional[str]:
    """Helius funded-by field names vary; normalize to one address."""
    if not funded or not isinstance(funded, dict):
        return None
    for key in (
        "funder",
        "fundingWallet",
        "funding_wallet",
        "from",
        "fromAddress",
        "from_address",
        "sender",
        "fundingAddress",
    ):
        f = funded.get(key)
        if isinstance(f, str) and _ADDR_RE.match(f):
            return f
    return None


def effective_funder_address(
    funded_by_row: Optional[dict],
    transfers_raw: Optional[dict],
) -> Optional[str]:
    """
    Prefer first inbound SOL sender from /transfers (on-chain), then Helius funded-by fields.
    Use this for bundle clustering so results match typical "same funder" views (e.g. Axiom).
    """
    ex = extract_first_inbound_sol_from_transfers(transfers_raw)
    if ex:
        fa = ex.get("from_address")
        if isinstance(fa, str) and _ADDR_RE.match(fa):
            return fa
    return expanded_funder_from_api(funded_by_row)


def enrich_wallet_funding(
    wallet: str,
    funded_by_row: Optional[dict],
    transfers_raw: Optional[dict],
) -> dict[str, Any]:
    fb = parse_funded_by_row(funded_by_row)
    ex = extract_first_inbound_sol_from_transfers(transfers_raw)
    lamports = fb["lamports"]
    ts = fb["timestamp_unix"]
    if ex:
        if lamports is None:
            lamports = ex.get("lamports")
        if ts is None:
            ts = ex.get("timestamp_unix")
    eff = None
    if ex and isinstance(ex.get("from_address"), str) and _ADDR_RE.match(ex["from_address"]):
        eff = ex["from_address"]
    if not eff:
        eff = expanded_funder_from_api(funded_by_row)
    return {
        "wallet": wallet,
        "funder": eff,
        "first_fund_lamports": lamports,
        "first_fund_timestamp_unix": ts,
        "first_fund_signature": fb.get("signature") or (ex or {}).get("signature"),
        "first_inbound_from_transfer": (ex or {}).get("from_address"),
    }


def time_bucket(ts: Optional[int], bucket_sec: float) -> Optional[int]:
    if ts is None:
        return None
    return int(ts // float(bucket_sec))


def lamports_close(a: Optional[int], b: Optional[int], rel_tol: float) -> bool:
    if a is None or b is None or a <= 0 or b <= 0:
        return False
    return abs(a - b) / max(a, b) <= rel_tol


def cluster_wallets_by_time_bucket(
    meta_by_wallet: dict[str, dict[str, Any]],
    bucket_sec: float,
) -> list[dict[str, Any]]:
    by_bucket: dict[str, list[str]] = defaultdict(list)
    for w, m in meta_by_wallet.items():
        ts = m.get("first_fund_timestamp_unix")
        b = time_bucket(ts, bucket_sec) if ts is not None else None
        if b is None:
            continue
        key = str(b)
        by_bucket[key].append(w)
    out: list[dict[str, Any]] = []
    for bid, wallets in by_bucket.items():
        if len(wallets) >= 2:
            out.append(
                {
                    "bucket_id": bid,
                    "bucket_sec": bucket_sec,
                    "wallets": sorted(wallets),
                    "count": len(wallets),
                }
            )
    out.sort(key=lambda x: -x["count"])
    return out


def cluster_wallets_by_same_lamports(
    meta_by_wallet: dict[str, dict[str, Any]],
    rel_tol: float,
) -> list[dict[str, Any]]:
    by_lam: dict[int, list[str]] = defaultdict(list)
    for w, m in meta_by_wallet.items():
        lp = m.get("first_fund_lamports")
        if lp is None:
            continue
        by_lam[int(lp)].append(w)
    # fuzzy groups: merge lamports within rel_tol of a representative
    reps: list[tuple[int, list[str]]] = []
    used: set[int] = set()
    sorted_lams = sorted(by_lam.keys())
    for lam in sorted_lams:
        if lam in used:
            continue
        group = list(by_lam[lam])
        for other in sorted_lams:
            if other <= lam or other in used:
                continue
            if lamports_close(lam, other, rel_tol):
                group.extend(by_lam[other])
                used.add(other)
        reps.append((lam, sorted(set(group))))
        used.add(lam)
    out: list[dict[str, Any]] = []
    for lam, wallets in reps:
        if len(wallets) >= 2:
            out.append({"lamports": lam, "wallets": wallets, "count": len(wallets)})
    out.sort(key=lambda x: -x["count"])
    return out


def fetch_funder_identities(funders: list[str]) -> dict[str, Optional[dict]]:
    out: dict[str, Optional[dict]] = {}
    slice_f = funders[:MAX_FUNDER_IDENTITY]
    for i, f in enumerate(slice_f):
        if not f:
            continue
        out[f] = helius_wallet_identity(f)
        if i < len(slice_f) - 1:
            time.sleep(0.04)
    return out


def _identity_text_blob(ident: Optional[dict]) -> str:
    """Flatten Helius identity (single-wallet or batch-normalized row) for keyword checks."""
    if not ident or not isinstance(ident, dict):
        return ""
    parts: list[str] = []
    for k in ("name", "displayName", "label", "category", "type", "primary_label"):
        v = ident.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.lower())
    tags = ident.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if t is not None and str(t).strip():
                parts.append(str(t).lower())
    return " ".join(parts)


def is_cex_identity(ident: Optional[dict]) -> bool:
    blob = _identity_text_blob(ident)
    if not blob:
        return False
    if "exchange" in blob or re.search(r"\bcex\b", blob) or "custody" in blob:
        return True
    # Major venues + generic patterns (Helius naming varies)
    venues = (
        "binance",
        "coinbase",
        "kraken",
        "okx",
        "bybit",
        "kucoin",
        "gate.io",
        "gate io",
        "gemini",
        "bitfinex",
        "mexc",
        "htx",
        "huobi",
        "crypto.com",
        "bitstamp",
        "upbit",
        "bitget",
        "deribit",
        "bingx",
        "withdraw",
        "deposit wallet",
        "hot wallet",
        "cold wallet",
    )
    return any(v in blob for v in venues)


def is_mixer_privacy_identity(ident: Optional[dict]) -> bool:
    """Privacy pools, mixers, tumblers, obfuscation services (best-effort from labels)."""
    blob = _identity_text_blob(ident)
    if not blob:
        return False
    if re.search(r"\bmixer\b", blob) or "tumbler" in blob or "tornado" in blob:
        return True
    if "privacy" in blob and any(x in blob for x in ("pool", "cash", "protocol", "bridge", "service")):
        return True
    if any(x in blob for x in ("obfuscat", "blender", "sanction", "laundr", "anon surf")):
        return True
    if "relayer" in blob and "privacy" in blob:
        return True
    return False


def shared_inbound_senders(meta_by_wallet: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Count how many sampled wallets share the same first inbound counterparty (excluding self)."""
    sender_counts: dict[str, list[str]] = defaultdict(list)
    for w, m in meta_by_wallet.items():
        s = m.get("first_inbound_from_transfer") or m.get("funder")
        if isinstance(s, str) and len(s) > 32:
            sender_counts[s].append(w)
    hot = {k: sorted(v) for k, v in sender_counts.items() if len(v) >= 2}
    return {"shared_sender_to_wallets": hot, "top_shared": sorted(hot.keys(), key=lambda k: -len(hot[k]))[:12]}


def shared_outbound_receivers(
    lookup_wallets: list[str],
    transfers_cache: dict[str, Optional[dict]],
) -> dict[str, Any]:
    """Find receiver addresses that collect outbound transfers from multiple sampled wallets."""
    recv_to_wallets: dict[str, set[str]] = defaultdict(set)
    for w in lookup_wallets:
        rows = _iter_transfer_rows(transfers_cache.get(w))
        if not rows:
            continue
        seen_for_wallet: set[str] = set()
        for t in rows:
            direction = str(t.get("direction") or t.get("type") or t.get("transferType") or "").lower()
            if direction not in ("out", "outgoing", "sent", "send", "withdraw"):
                continue
            to_a = (
                t.get("to")
                or t.get("toUserAccount")
                or t.get("toAddress")
                or t.get("toUser")
                or t.get("recipient")
                or t.get("destination")
                or t.get("destinationAccount")
                or t.get("counterparty")
            )
            if isinstance(to_a, dict):
                to_a = to_a.get("address") or to_a.get("pubkey")
            if not isinstance(to_a, str) or not _ADDR_RE.match(to_a):
                continue
            if to_a == w or to_a in seen_for_wallet:
                continue
            recv_to_wallets[to_a].add(w)
            seen_for_wallet.add(to_a)
    hot = {k: sorted(v) for k, v in recv_to_wallets.items() if len(v) >= 2}
    top = sorted(hot.keys(), key=lambda k: -len(hot[k]))[:20]
    return {"shared_receiver_to_wallets": hot, "top_shared_receivers": top}


def _programs_from_enhanced(tx: dict) -> set[str]:
    progs: set[str] = set()

    def _from_instruction_list(arr: Any) -> None:
        if not isinstance(arr, list):
            return
        for ins in arr:
            if not isinstance(ins, dict):
                continue
            pid = ins.get("programId") or ins.get("program")
            if isinstance(pid, str):
                progs.add(pid)

    for key in ("instructions", "parsedInstructions"):
        _from_instruction_list(tx.get(key))
    inner = tx.get("innerInstructions")
    if isinstance(inner, list):
        for block in inner:
            if isinstance(block, dict):
                _from_instruction_list(block.get("instructions"))
    return progs


def enhanced_co_movement_mint(
    wallet: str,
    mint: str,
    limit: int = 40,
) -> Optional[dict[str, Any]]:
    txs = helius_enhanced_transactions(wallet, limit=limit)
    if not isinstance(txs, list):
        return None
    slots: list[int] = []
    programs: set[str] = set()
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        slot = _safe_int(tx.get("slot"))
        # tokenTransfers often include mint
        tts = tx.get("tokenTransfers")
        hit = False
        if isinstance(tts, list):
            for tt in tts:
                if not isinstance(tt, dict):
                    continue
                m = tt.get("mint") or tt.get("tokenMint")
                if m == mint:
                    hit = True
                    break
        if hit and slot is not None:
            slots.append(slot)
        programs |= _programs_from_enhanced(tx)
    return {
        "wallet": wallet,
        "mint_touch_slots": sorted(set(slots))[:20],
        "programs_sample": sorted(programs)[:40],
    }


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def compute_coordination_bundle(
    *,
    lookup_wallets: list[str],
    funded_by: dict[str, Optional[dict]],
    owner_amount: dict[str, float],
    mint: str,
    focus_wallets: list[str],
    transfers_cache_preload: Optional[dict[str, Optional[dict]]] = None,
) -> dict[str, Any]:
    """
    Run all signals; return structured report + score 0–100.
    If transfers_cache_preload is set (e.g. from run_bundle_snapshot), reuse it to avoid duplicate /transfers calls.
    """
    meta_by_wallet: dict[str, dict[str, Any]] = {}
    transfers_cache: dict[str, Optional[dict]] = {}
    if transfers_cache_preload:
        transfers_cache.update(transfers_cache_preload)

    n_fetch = min(len(lookup_wallets), MAX_TRANSFER_FETCH)
    pending = [w for w in lookup_wallets[:n_fetch] if transfers_cache.get(w) is None]
    for i, w in enumerate(pending):
        transfers_cache[w] = helius_transfers(w, limit=SIGNAL_TRANSFERS_LIMIT)
        if i < len(pending) - 1:
            time.sleep(0.045)

    for w in lookup_wallets:
        meta_by_wallet[w] = enrich_wallet_funding(w, funded_by.get(w), transfers_cache.get(w))

    time_clusters = cluster_wallets_by_time_bucket(meta_by_wallet, FUNDING_TIME_BUCKET_SEC)
    amount_clusters = cluster_wallets_by_same_lamports(meta_by_wallet, LAMPORTS_REL_TOL)

    funders = sorted({meta_by_wallet[w]["funder"] for w in lookup_wallets if meta_by_wallet[w].get("funder")})
    funder_idents = fetch_funder_identities(funders)
    cex_funders = {f: is_cex_identity(funder_idents.get(f)) for f in funders}
    funder_mixer_flags = {f: is_mixer_privacy_identity(funder_idents.get(f)) for f in funders}

    cex_funder_to_wallets: dict[str, list[str]] = defaultdict(list)
    mixer_funder_to_wallets: dict[str, list[str]] = defaultdict(list)
    for w in lookup_wallets:
        f = meta_by_wallet[w].get("funder")
        if not isinstance(f, str):
            continue
        if cex_funders.get(f):
            cex_funder_to_wallets[f].append(w)
        if funder_mixer_flags.get(f):
            mixer_funder_to_wallets[f].append(w)

    def _funder_groups(counter: dict[str, list[str]]) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        for fnd, ws in counter.items():
            u = sorted(set(ws))
            if len(u) >= 2:
                groups.append({"funder": fnd, "wallet_count": len(u), "wallets": u[:40]})
        groups.sort(key=lambda x: -x["wallet_count"])
        return groups

    parallel_cex_funding = _funder_groups(cex_funder_to_wallets)
    privacy_mixer_funding = _funder_groups(mixer_funder_to_wallets)

    shared_inc = shared_inbound_senders(meta_by_wallet)
    shared_out = shared_outbound_receivers(lookup_wallets, transfers_cache)

    enhanced_sample: dict[str, Any] = {}
    co_slots_by_w: dict[str, list[int]] = {}
    program_sets: dict[str, set[str]] = {}
    mw = [w for w in (focus_wallets or lookup_wallets) if w in meta_by_wallet][:MAX_ENHANCED_FETCH]
    for i, w in enumerate(mw):
        em = enhanced_co_movement_mint(w, mint, limit=ENHANCED_TX_LIMIT)
        if em:
            co_slots_by_w[w] = em.get("mint_touch_slots") or []
            program_sets[w] = set(em.get("programs_sample") or [])
        if i < len(mw) - 1:
            time.sleep(0.085)
    enhanced_sample = {"wallets_analyzed": mw, "mint_touch_slots_by_wallet": co_slots_by_w}

    # Same-slot mint touch: wallets that appear in same slot for mint-related txs (any pair)
    slot_to_w: dict[int, list[str]] = defaultdict(list)
    for w, slots in co_slots_by_w.items():
        for s in slots:
            slot_to_w[s].append(w)
    co_move_pairs: list[dict[str, Any]] = []
    for s, ws in slot_to_w.items():
        u = sorted(set(ws))
        if len(u) >= 2:
            co_move_pairs.append({"slot": s, "wallets": u})

    # Program overlap among focus wallets
    p_overlap: list[dict[str, Any]] = []
    keys = list(program_sets.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            p_overlap.append(
                {
                    "wallet_a": a,
                    "wallet_b": b,
                    "program_jaccard": round(jaccard(program_sets.get(a, set()), program_sets.get(b, set())), 4),
                }
            )
    p_overlap.sort(key=lambda x: -x["program_jaccard"])

    # --- Score 0-100 (cap)
    score = 0.0
    reasons: list[str] = []

    if time_clusters:
        score += min(22, 6 + max(0, len(time_clusters[0]["wallets"]) - 2) * 4)
        reasons.append("funding_time_sync")
    if amount_clusters:
        score += min(18, 5 + max(0, len(amount_clusters[0]["wallets"]) - 2) * 3)
        reasons.append("same_first_fund_amount")
    if any(cex_funders.values()):
        score += 12
        reasons.append("cex_tagged_funder_present")
    if parallel_cex_funding:
        top_n = parallel_cex_funding[0]["wallet_count"]
        score += min(16, 6 + max(0, top_n - 2) * 3)
        reasons.append("parallel_cex_funder_cluster")
    if privacy_mixer_funding:
        top_m = privacy_mixer_funding[0]["wallet_count"]
        score += min(14, 5 + max(0, top_m - 2) * 2)
        reasons.append("privacy_mixer_shared_funder")
    if shared_inc.get("top_shared"):
        score += min(15, 5 + len(shared_inc["top_shared"]) * 2)
        reasons.append("shared_inbound_counterparty")
    if shared_out.get("top_shared_receivers"):
        score += min(16, 6 + len(shared_out["top_shared_receivers"]) * 2)
        reasons.append("shared_outbound_receiver")
    if co_move_pairs:
        score += min(18, 6 + min(len(co_move_pairs), 4) * 3)
        reasons.append("mint_activity_same_slot")
    if p_overlap and p_overlap[0]["program_jaccard"] >= 0.15:
        score += min(15, 5 + p_overlap[0]["program_jaccard"] * 40)
        reasons.append("program_fingerprint_overlap")

    score = round(min(100.0, score), 2)

    archetype_hints: list[str] = []
    if parallel_cex_funding:
        archetype_hints.append(
            "Parallel CEX pattern: two or more sampled wallets share a CEX-tagged first funder (common withdrawal routing)."
        )
    if privacy_mixer_funding:
        archetype_hints.append(
            "Privacy / mixer pattern: multiple sampled wallets share a mixer- or privacy-tagged funder path."
        )

    return {
        "funding_metadata_by_wallet": meta_by_wallet,
        "funding_time_clusters": time_clusters,
        "funding_same_amount_clusters": amount_clusters,
        "funder_cex_flags": cex_funders,
        "funder_mixer_flags": funder_mixer_flags,
        "parallel_cex_funding": parallel_cex_funding[:12],
        "privacy_mixer_funding": privacy_mixer_funding[:12],
        "bundle_archetype_hints": archetype_hints,
        "shared_inbound_senders": shared_inc,
        "shared_outbound_receivers": shared_out,
        "mint_co_movement": {"same_slot_groups": co_move_pairs[:15], "enhanced": enhanced_sample},
        "program_overlap_pairs": p_overlap[:20],
        "coordination_score": score,
        "coordination_reasons": reasons,
        "params": {
            "funding_bucket_sec": FUNDING_TIME_BUCKET_SEC,
            "lamports_rel_tol": LAMPORTS_REL_TOL,
            "max_transfer_fetch": n_fetch,
            "max_enhanced_fetch": len(mw),
            "signal_transfers_limit": SIGNAL_TRANSFERS_LIMIT,
            "enhanced_tx_limit": ENHANCED_TX_LIMIT,
        },
    }
