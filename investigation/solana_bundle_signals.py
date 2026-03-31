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
10) Optional JSON overrides — wallet allow/deny lists and extra label markers (`SOLANA_BUNDLE_INTEL_OVERRIDES_PATH`).
11) Strict parallel funding — `dual` corroboration mode and optional max timestamp spread between paired wallets.
12) Enhanced tx type overlap — similar Helius `type` / `transactionType` labels across wallets on mint-touch samples.

Not financial advice; all scores are heuristics.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from bundle_intel_overrides import load_bundle_intel_overrides

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
# Extra identity lookups for 2-hop root funders (CEX/mixer path when direct funder is unlabeled)
MAX_FUNDER_ROOT_IDENTITY = int(os.environ.get("SOLANA_BUNDLE_FUNDER_ROOT_IDENTITY_MAX", "24"))
# Enhanced tx samples for *funder/root* addresses: detect bridge programs on funding path (0 = off).
SOLANA_BUNDLE_FUNDER_BRIDGE_ENHANCED_MAX = max(
    0, min(int(os.environ.get("SOLANA_BUNDLE_FUNDER_BRIDGE_ENHANCED_MAX", "24")), 64)
)
# Helius enhanced txs per wallet when sampling mint co-movement / program overlap
ENHANCED_TX_LIMIT = int(os.environ.get("SOLANA_BUNDLE_ENHANCED_TX_LIMIT", "55"))
# Extra /transfers fetch during coordination pass (Helius max 100)
SIGNAL_TRANSFERS_LIMIT = max(1, min(int(os.environ.get("SOLANA_BUNDLE_SIGNAL_TRANSFERS_LIMIT", "100")), 100))
# parallel strict: "either" = same time bucket OR close lamports; "dual" = both required for a pair
PARALLEL_CORROBORATION_MODE = (os.environ.get("SOLANA_BUNDLE_PARALLEL_CORROBORATION_MODE") or "either").strip().lower()
# Max |ts_a - ts_b| for funding alignment (0 = disabled). Applies to bucket pairs and lamports pairs when both timestamps exist.
FUNDING_MAX_SPREAD_SEC = float(os.environ.get("SOLANA_BUNDLE_FUNDING_MAX_SPREAD_SEC", "0"))
# Minimum Jaccard on Helius enhanced tx *type* strings (e.g. SWAP) across wallet pairs to add a small score bump
ENHANCED_TYPE_OVERLAP_MIN = float(os.environ.get("SOLANA_BUNDLE_ENHANCED_TYPE_OVERLAP_MIN", "0.35"))


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
    for k in (
        "name",
        "displayName",
        "label",
        "category",
        "type",
        "primary_label",
        "entity_type",
        "entityType",
    ):
        v = ident.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.lower())
    tags = ident.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if t is not None and str(t).strip():
                parts.append(str(t).lower())
    return " ".join(parts)


def _identity_label_blob(ident: Optional[dict]) -> str:
    """Name / display fields only (for venue match — avoids tag noise)."""
    if not ident or not isinstance(ident, dict):
        return ""
    parts: list[str] = []
    for k in ("name", "displayName", "label", "primary_label"):
        v = ident.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.lower())
    return " ".join(parts)


# Venue strings for *strong* CEX only when they appear in label/name (not tag-only withdraw/hot-wallet noise)
_CEX_VENUE_LABEL_MARKERS = (
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
)

# DEX / aggregator noise: weak mixer rules must not fire on these
_MIXER_DEX_BLOCKLIST = (
    "jupiter",
    "raydium",
    "orca",
    "uniswap",
    "meteora",
    "phoenix",
    "lifinity",
    "pump.fun",
    "pumpswap",
    "curve",
    "balancer",
)


def _dex_label_noise(vl: str) -> bool:
    """True if this field reads as DEX/AMM, not a centralized venue (avoid 'Decentralized Exchange' → CEX)."""
    if not vl or not isinstance(vl, str):
        return False
    s = vl.lower()
    if "decentralized" in s:
        return True
    if re.search(r"\bdex\b", s):
        return True
    if re.search(r"\bamm\b", s) or "automated market" in s:
        return True
    if "liquidity pool" in s or "swap pool" in s:
        return True
    return False


def _structural_cex_hit(ident: dict) -> Optional[str]:
    """True if type/category/entity tags clearly indicate centralized exchange (strong)."""
    for k in ("type", "category", "entity_type", "entityType"):
        v = ident.get(k)
        if not isinstance(v, str) or not v.strip():
            continue
        vl = v.lower()
        if _dex_label_noise(v):
            continue
        if "exchange" in vl or re.search(r"\bcex\b", vl) or "custodial" in vl:
            return f"struct:{k}"
    tags = ident.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if not isinstance(t, str) or not t.strip():
                continue
            tl = t.lower()
            if _dex_label_noise(t):
                continue
            if "exchange" in tl or re.search(r"\bcex\b", tl) or "custodial" in tl:
                return "struct:tag"
    return None


def classify_cex_tier(
    ident: Optional[dict],
    *,
    extra_venue_markers: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    """
    none | weak | strong. reason_codes are short tokens for debugging/UI.
    Strong: structured exchange type/category/tags, or known venue in display name.
    Weak: generic custodial language only (hot/cold wallet, withdraw) — needs corroboration for parallel scoring.
    extra_venue_markers: optional substrings (from JSON overrides) matched in label/name only.
    """
    reasons: list[str] = []
    if not ident or not isinstance(ident, dict):
        return "none", reasons
    hit = _structural_cex_hit(ident)
    if hit:
        reasons.append(hit)
        return "strong", reasons
    lbl = _identity_label_blob(ident)
    for v in _CEX_VENUE_LABEL_MARKERS + tuple(extra_venue_markers):
        if v and v in lbl:
            reasons.append(f"venue:{v}")
            return "strong", reasons
    blob = _identity_text_blob(ident)
    # Word-safe weak custodial tokens (avoid matching unrelated substrings)
    if re.search(r"\b(hot wallet|cold wallet|deposit wallet)\b", blob):
        reasons.append("weak_custodial_language")
        return "weak", reasons
    if re.search(r"\bwithdraw(?:al)?s?\b", blob):
        reasons.append("weak_custodial_language")
        return "weak", reasons
    if re.search(r"\bdeposit\b", blob) and "exchange" not in blob:
        reasons.append("weak_deposit_keyword")
        return "weak", reasons
    return "none", reasons


def classify_mixer_tier(
    ident: Optional[dict],
    *,
    extra_strong_blob_markers: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    """
    none | weak | strong. Drops privacy+protocol/bridge (high false-positive); DEX blocklist kills weak tier.
    extra_strong_blob_markers: optional substrings (overrides); if present in blob → strong.
    """
    reasons: list[str] = []
    if not ident or not isinstance(ident, dict):
        return "none", reasons
    blob = _identity_text_blob(ident)
    for m in extra_strong_blob_markers:
        if m and m in blob:
            reasons.append(f"override_marker:{m[:32]}")
            return "strong", reasons
    dex_noise = any(x in blob for x in _MIXER_DEX_BLOCKLIST)
    if re.search(r"\bmixer\b", blob) or "tumbler" in blob or "tornado" in blob:
        reasons.append("mixer_keyword")
        return "strong", reasons
    if any(x in blob for x in ("obfuscat", "blender", "sanction", "laundr", "anon surf")):
        reasons.append("obfuscation_sanction_language")
        return "strong", reasons
    if "privacy pool" in blob or ("privacy" in blob and "shield" in blob):
        reasons.append("privacy_pool_or_shield")
        return "strong", reasons
    if "relayer" in blob and "privacy" in blob:
        reasons.append("privacy_relayer")
        return "strong", reasons
    if dex_noise:
        return "none", reasons
    if "privacy" in blob and any(x in blob for x in ("pool", "cash", "shield")):
        reasons.append("privacy_companion_weak")
        return "weak", reasons
    return "none", reasons


def is_cex_identity(ident: Optional[dict]) -> bool:
    """
    Strong or weak CEX signal. Set SOLANA_BUNDLE_CEX_STRICT=1 to require strong tier only.
    """
    tier, _ = classify_cex_tier(ident)
    if (os.environ.get("SOLANA_BUNDLE_CEX_STRICT") or "").strip().lower() in ("1", "true", "yes"):
        return tier == "strong"
    return tier in ("weak", "strong")


def is_mixer_privacy_identity(ident: Optional[dict]) -> bool:
    """
    Strong or weak mixer/privacy signal. Set SOLANA_BUNDLE_MIXER_STRICT=1 for strong only.
    """
    tier, _ = classify_mixer_tier(ident)
    if (os.environ.get("SOLANA_BUNDLE_MIXER_STRICT") or "").strip().lower() in ("1", "true", "yes"):
        return tier == "strong"
    return tier in ("weak", "strong")


def classify_cex_tier_for_funder(
    address: str,
    ident: Optional[dict],
    ov: dict[str, Any],
) -> tuple[str, list[str]]:
    """CEX tier for a funder address with JSON allow/deny lists and extra venue markers."""
    addr = (address or "").strip()
    if addr in ov.get("wallet_cex_denylist", set()):
        return "none", ["override:wallet_cex_denylist"]
    if addr in ov.get("wallet_cex_allowlist", set()):
        return "strong", ["override:wallet_cex_allowlist"]
    extra = tuple(ov.get("cex_extra_label_markers") or ())
    return classify_cex_tier(ident, extra_venue_markers=extra)


def classify_mixer_tier_for_funder(
    address: str,
    ident: Optional[dict],
    ov: dict[str, Any],
) -> tuple[str, list[str]]:
    """Mixer tier for a funder address with JSON allow/deny lists and extra blob markers."""
    addr = (address or "").strip()
    if addr in ov.get("wallet_mixer_denylist", set()):
        return "none", ["override:wallet_mixer_denylist"]
    if addr in ov.get("wallet_mixer_allowlist", set()):
        return "strong", ["override:wallet_mixer_allowlist"]
    extra = tuple(ov.get("mixer_extra_label_markers") or ())
    return classify_mixer_tier(ident, extra_strong_blob_markers=extra)


def _spread_ok(ts_a: Optional[int], ts_b: Optional[int], max_spread_sec: float) -> bool:
    if max_spread_sec <= 0:
        return True
    if ts_a is None or ts_b is None:
        return True
    return abs(int(ts_a) - int(ts_b)) <= max_spread_sec


def wallets_funding_corroborated(
    wallets: list[str],
    meta_by_wallet: dict[str, dict[str, Any]],
    bucket_sec: float,
    rel_tol: float,
    *,
    mode: str = "either",
    max_spread_sec: float = 0.0,
) -> set[str]:
    """
    Wallets aligned on first-fund signals.
    mode=either: same time bucket OR close lamports (pairwise), optional max_spread on timestamps.
    mode=dual: exists another wallet with same bucket AND close lamports (and spread when set).
    """
    corroborated: set[str] = set()
    wset = list(dict.fromkeys(wallets))
    if len(wset) < 2:
        return corroborated

    mode_l = (mode or "either").strip().lower()
    if mode_l == "dual":
        for i in range(len(wset)):
            for j in range(i + 1, len(wset)):
                wa, wb = wset[i], wset[j]
                ma, mb = meta_by_wallet.get(wa) or {}, meta_by_wallet.get(wb) or {}
                ts_a = ma.get("first_fund_timestamp_unix")
                ts_b = mb.get("first_fund_timestamp_unix")
                b_a = time_bucket(ts_a, bucket_sec) if ts_a is not None else None
                b_b = time_bucket(ts_b, bucket_sec) if ts_b is not None else None
                if b_a is None or b_b is None or b_a != b_b:
                    continue
                if not _spread_ok(ts_a, ts_b, max_spread_sec):
                    continue
                la = ma.get("first_fund_lamports")
                lb = mb.get("first_fund_lamports")
                if la is None or lb is None:
                    continue
                try:
                    ia, ib = int(la), int(lb)
                except (TypeError, ValueError):
                    continue
                if lamports_close(ia, ib, rel_tol):
                    corroborated.add(wa)
                    corroborated.add(wb)
        return corroborated

    # --- either ---
    by_bucket: dict[int, list[str]] = defaultdict(list)
    for w in wset:
        m = meta_by_wallet.get(w) or {}
        ts = m.get("first_fund_timestamp_unix")
        b = time_bucket(ts, bucket_sec) if ts is not None else None
        if b is not None:
            by_bucket[b].append(w)
    for ws in by_bucket.values():
        uniq = list(dict.fromkeys(ws))
        if len(uniq) < 2:
            continue
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                wa, wb = uniq[i], uniq[j]
                ma, mb = meta_by_wallet.get(wa) or {}, meta_by_wallet.get(wb) or {}
                ts_a = ma.get("first_fund_timestamp_unix")
                ts_b = mb.get("first_fund_timestamp_unix")
                if _spread_ok(ts_a, ts_b, max_spread_sec):
                    corroborated.add(wa)
                    corroborated.add(wb)
    lams: list[tuple[str, int, Optional[int]]] = []
    for w in wset:
        m = meta_by_wallet.get(w) or {}
        lp = m.get("first_fund_lamports")
        ts = m.get("first_fund_timestamp_unix")
        if lp is not None:
            try:
                lams.append((w, int(lp), ts if isinstance(ts, (int, float)) else None))
            except (TypeError, ValueError):
                pass
    for i in range(len(lams)):
        for j in range(i + 1, len(lams)):
            if not lamports_close(lams[i][1], lams[j][1], rel_tol):
                continue
            ts_a, ts_b = lams[i][2], lams[j][2]
            if max_spread_sec > 0 and ts_a is not None and ts_b is not None:
                if not _spread_ok(ts_a, ts_b, max_spread_sec):
                    continue
            corroborated.add(lams[i][0])
            corroborated.add(lams[j][0])
    return corroborated


def _wallet_tagged_cluster_key(
    wallet: str,
    meta_by_wallet: dict[str, dict[str, Any]],
    funder_root_by_wallet: dict[str, Optional[str]],
    funder_idents: dict[str, Optional[dict]],
    tier_fn,
) -> Optional[str]:
    """
    Address to cluster by for CEX/mixer: direct funder if tagged, else 2-hop root if tagged.
    tier_fn(funder_address: str, ident: Optional[dict]) -> none|weak|strong
    """
    d = meta_by_wallet.get(wallet, {}).get("funder")
    if isinstance(d, str) and tier_fn(d, funder_idents.get(d)) != "none":
        return d
    r = funder_root_by_wallet.get(wallet)
    if isinstance(r, str) and tier_fn(r, funder_idents.get(r)) != "none":
        return r
    return None


def _build_tagged_parallel_groups(
    lookup_wallets: list[str],
    meta_by_wallet: dict[str, dict[str, Any]],
    funder_root_by_wallet: dict[str, Optional[str]],
    funder_idents: dict[str, Optional[dict]],
    tier_fn,
) -> list[dict[str, Any]]:
    """Loose groups: >=2 wallets sharing the same tagged funder address (direct or root)."""
    key_to_wallets: dict[str, list[str]] = defaultdict(list)
    for w in lookup_wallets:
        k = _wallet_tagged_cluster_key(
            w, meta_by_wallet, funder_root_by_wallet, funder_idents, tier_fn
        )
        if k:
            key_to_wallets[k].append(w)
    groups: list[dict[str, Any]] = []
    for fnd, ws in key_to_wallets.items():
        u = sorted(set(ws))
        if len(u) >= 2:
            tier = tier_fn(fnd, funder_idents.get(fnd))
            groups.append(
                {
                    "funder": fnd,
                    "wallet_count": len(u),
                    "wallets": u[:40],
                    "funder_tier": tier,
                }
            )
    groups.sort(key=lambda x: -x["wallet_count"])
    return groups


def _strict_from_loose(
    loose: list[dict[str, Any]],
    meta_by_wallet: dict[str, dict[str, Any]],
    bucket_sec: float,
    rel_tol: float,
    *,
    corroboration_mode: str = "either",
    max_spread_sec: float = 0.0,
) -> list[dict[str, Any]]:
    """Keep only wallets corroborated per SOLANA_BUNDLE_PARALLEL_CORROBORATION_MODE and spread."""
    strict: list[dict[str, Any]] = []
    for g in loose:
        ws = g.get("wallets") or []
        if not isinstance(ws, list):
            continue
        corr = wallets_funding_corroborated(
            ws,
            meta_by_wallet,
            bucket_sec,
            rel_tol,
            mode=corroboration_mode,
            max_spread_sec=max_spread_sec,
        )
        if len(corr) < 2:
            continue
        u = sorted(corr)
        strict.append(
            {
                "funder": g["funder"],
                "wallet_count": len(u),
                "wallets": u[:40],
                "funder_tier": g.get("funder_tier"),
                "confidence": "high",
                "corroboration_mode": corroboration_mode,
            }
        )
    strict.sort(key=lambda x: -x["wallet_count"])
    return strict


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


def build_cex_split_pattern(
    *,
    lookup_wallets: list[str],
    meta_by_wallet: dict[str, dict[str, Any]],
    root_map: dict[str, Optional[str]],
    funder_cex_tier: dict[str, str],
    shared_outbound: dict[str, Any],
    eligible_wallets: Optional[list[str]] = None,
    bucket_sec: float = FUNDING_TIME_BUCKET_SEC,
) -> dict[str, Any]:
    """
    Detect CEX-routed split/fan-out behavior heuristically.
    This is attribution support only (not ownership proof).
    """
    eligible = set(eligible_wallets or lookup_wallets)
    cex_path_hits: list[dict[str, Any]] = []
    by_funder: dict[str, list[str]] = defaultdict(list)
    cex_wallets: set[str] = set()

    for w in lookup_wallets:
        if w not in eligible:
            continue
        m = meta_by_wallet.get(w) or {}
        d = m.get("funder")
        r = root_map.get(w)
        best: Optional[tuple[str, str, str]] = None  # (via, addr, tier)
        for via, addr in (("direct", d), ("root", r)):
            if not isinstance(addr, str) or not addr:
                continue
            tier = str(funder_cex_tier.get(addr) or "none")
            if tier == "none":
                continue
            if best is None:
                best = (via, addr, tier)
            elif best[2] != "strong" and tier == "strong":
                best = (via, addr, tier)
        if not best:
            continue
        via, addr, tier = best
        cex_wallets.add(w)
        by_funder[addr].append(w)
        cex_path_hits.append({"wallet": w, "via": via, "funder_address": addr, "tier": tier})

    shared_funder_groups = []
    for faddr, ws in by_funder.items():
        uniq = sorted(set(ws))
        if len(uniq) >= 2:
            shared_funder_groups.append(
                {
                    "funder": faddr,
                    "wallet_count": len(uniq),
                    "wallets": uniq[:30],
                    "tier": str(funder_cex_tier.get(faddr) or "none"),
                }
            )
    shared_funder_groups.sort(key=lambda x: -x["wallet_count"])

    # repeated first-fund denominations among cex-path wallets
    lam_groups = []
    by_lam: dict[int, list[str]] = defaultdict(list)
    for w in sorted(cex_wallets):
        lp = (meta_by_wallet.get(w) or {}).get("first_fund_lamports")
        try:
            ilp = int(lp)
        except (TypeError, ValueError):
            continue
        if ilp > 0:
            by_lam[ilp].append(w)
    for lam, ws in by_lam.items():
        uniq = sorted(set(ws))
        if len(uniq) >= 2:
            lam_groups.append({"lamports": lam, "wallet_count": len(uniq), "wallets": uniq[:30]})
    lam_groups.sort(key=lambda x: -x["wallet_count"])

    # synchronized first-fund time buckets among cex-path wallets
    bucket_groups = []
    by_bucket: dict[int, list[str]] = defaultdict(list)
    for w in sorted(cex_wallets):
        ts = (meta_by_wallet.get(w) or {}).get("first_fund_timestamp_unix")
        if ts is None:
            continue
        b = time_bucket(ts, bucket_sec)
        if b is not None:
            by_bucket[b].append(w)
    for b, ws in by_bucket.items():
        uniq = sorted(set(ws))
        if len(uniq) >= 2:
            bucket_groups.append({"bucket_id": str(b), "wallet_count": len(uniq), "wallets": uniq[:30]})
    bucket_groups.sort(key=lambda x: -x["wallet_count"])

    # shared outbound receivers touched by >=2 cex-path wallets
    shared_receiver_hits = []
    recv_map = shared_outbound.get("shared_receiver_to_wallets") if isinstance(shared_outbound, dict) else {}
    if isinstance(recv_map, dict):
        for recv, ws in recv_map.items():
            if not isinstance(ws, list):
                continue
            inter = sorted(set(ws) & cex_wallets)
            if len(inter) >= 2:
                shared_receiver_hits.append(
                    {"receiver": recv, "wallet_count": len(inter), "wallets": inter[:30]}
                )
    shared_receiver_hits.sort(key=lambda x: -x["wallet_count"])

    confidence = "low"
    top_shared = shared_funder_groups[0]["wallet_count"] if shared_funder_groups else 0
    top_lam = lam_groups[0]["wallet_count"] if lam_groups else 0
    top_bucket = bucket_groups[0]["wallet_count"] if bucket_groups else 0
    recv_n = len(shared_receiver_hits)
    if top_shared >= 3 and (top_lam >= 2 or top_bucket >= 2) and recv_n >= 1:
        confidence = "high"
    elif top_shared >= 2 and (top_lam >= 2 or top_bucket >= 2 or recv_n >= 1):
        confidence = "medium"
    elif len(cex_wallets) >= 2:
        confidence = "low"
    else:
        confidence = "none"

    risk_lines: list[str] = []
    if top_shared >= 2:
        risk_lines.append(
            f"{top_shared} wallet(s) share the same CEX-tagged funding path (direct/root)."
        )
    if top_lam >= 2:
        risk_lines.append(
            f"{top_lam} wallet(s) received matching first-fund lamport sizes on CEX-tagged paths."
        )
    if top_bucket >= 2:
        risk_lines.append(
            f"{top_bucket} wallet(s) were first-funded in the same time bucket on CEX-tagged paths."
        )
    if recv_n >= 1:
        risk_lines.append(
            f"{recv_n} shared outbound receiver(s) collect funds from multiple CEX-path wallets."
        )

    return {
        "confidence_tier": confidence,
        "cex_path_wallet_count": len(cex_wallets),
        "cex_path_hits": cex_path_hits[:40],
        "shared_cex_funder_groups": shared_funder_groups[:20],
        "repeated_first_fund_lamports": lam_groups[:20],
        "time_bucket_groups": bucket_groups[:20],
        "shared_outbound_receivers": shared_receiver_hits[:20],
        "risk_lines": risk_lines[:8],
    }


def _outbound_receivers_by_wallet(
    wallets: list[str],
    transfers_cache: dict[str, Optional[dict]],
) -> dict[str, set[str]]:
    """Per-wallet outbound receiver sets from cached transfer rows."""
    out: dict[str, set[str]] = {}
    for w in wallets:
        rows = _iter_transfer_rows(transfers_cache.get(w))
        if not rows:
            continue
        recv: set[str] = set()
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
            if to_a == w:
                continue
            recv.add(to_a)
        if recv:
            out[w] = recv
    return out


def _native_transfers_from_enhanced(txs: list[dict]) -> list[dict[str, Any]]:
    """Extract SOL flow edges {from, to, lamports, signature} from enhanced tx nativeTransfers."""
    edges: list[dict[str, Any]] = []
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        sig = tx.get("signature") or ""
        nts = tx.get("nativeTransfers")
        if not isinstance(nts, list):
            continue
        for nt in nts:
            if not isinstance(nt, dict):
                continue
            frm = nt.get("fromUserAccount")
            to = nt.get("toUserAccount")
            lam = _safe_int(nt.get("amount"))
            if (
                isinstance(frm, str)
                and isinstance(to, str)
                and _ADDR_RE.match(frm)
                and _ADDR_RE.match(to)
                and lam is not None
                and lam > 0
                and frm != to
            ):
                edges.append({"from": frm, "to": to, "lamports": lam, "signature": sig[:90]})
    return edges


def detect_wash_flow_patterns(
    funder_native_flows: dict[str, list[dict[str, Any]]],
    funder_chains: dict[str, list[str]],
    bridge_programs: Optional[dict[str, str]] = None,
    mixer_programs: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Detect circular, split-merge, and relay wash patterns from native SOL flow graphs."""
    bp = bridge_programs or {}
    mp = mixer_programs or {}
    all_chain_addrs: set[str] = set()
    for ch in funder_chains.values():
        for a in ch:
            all_chain_addrs.add(a)

    # Build adjacency from all collected flows
    out_edges: dict[str, list[tuple[str, int]]] = defaultdict(list)
    in_edges: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for addr, flows in funder_native_flows.items():
        for e in flows:
            f, t = e.get("from", ""), e.get("to", "")
            lam = e.get("lamports", 0)
            if f and t and lam > 0:
                out_edges[f].append((t, lam))
                in_edges[t].append((f, lam))

    # 1) Circular flows: A→B→...→A where all nodes are in funder chains
    circular_hits: list[dict[str, Any]] = []
    visited_cycles: set[str] = set()
    for start in sorted(all_chain_addrs)[:200]:
        if start not in out_edges:
            continue
        stack: list[list[str]] = [[start]]
        while stack:
            path = stack.pop()
            if len(path) > 5:
                continue
            tip = path[-1]
            for nxt, _ in out_edges.get(tip, []):
                if nxt == start and len(path) >= 3:
                    cycle_key = "->".join(sorted(path))
                    if cycle_key not in visited_cycles:
                        visited_cycles.add(cycle_key)
                        circular_hits.append({
                            "type": "circular",
                            "cycle": path + [start],
                            "depth": len(path),
                        })
                elif nxt not in set(path) and nxt in all_chain_addrs and len(path) < 5:
                    stack.append(path + [nxt])
            if len(circular_hits) >= 20:
                break

    # 2) Split-and-merge: single source fans out to N wallets that converge to one dest
    split_merge_hits: list[dict[str, Any]] = []
    for src in sorted(all_chain_addrs)[:200]:
        dests = {t for t, _ in out_edges.get(src, [])}
        if len(dests) < 3:
            continue
        convergence: dict[str, set[str]] = defaultdict(set)
        for d in dests:
            for final_dest, _ in out_edges.get(d, []):
                if final_dest != src:
                    convergence[final_dest].add(d)
        for final_d, intermediaries in convergence.items():
            if len(intermediaries) >= 3:
                split_merge_hits.append({
                    "type": "split_merge",
                    "source": src,
                    "intermediaries": sorted(intermediaries)[:15],
                    "destination": final_d,
                    "fan_out": len(dests),
                    "converge_count": len(intermediaries),
                })
        if len(split_merge_hits) >= 15:
            break

    # 3) Relay: address receives from bridge/mixer program then sends to a chain address
    relay_hits: list[dict[str, Any]] = []
    program_addrs = set(bp.keys()) | set(mp.keys())
    for addr in sorted(all_chain_addrs)[:200]:
        inbound_from_program = False
        program_label = None
        for src, _ in in_edges.get(addr, []):
            if src in program_addrs:
                inbound_from_program = True
                program_label = bp.get(src) or mp.get(src) or "program"
                break
        if not inbound_from_program:
            continue
        outbound_to_chain = []
        for dest, lam in out_edges.get(addr, []):
            if dest in all_chain_addrs and dest != addr:
                outbound_to_chain.append(dest)
        if outbound_to_chain:
            relay_hits.append({
                "type": "relay",
                "relay_address": addr,
                "program_source": program_label,
                "forwarded_to": sorted(set(outbound_to_chain))[:10],
            })
        if len(relay_hits) >= 15:
            break

    all_patterns = circular_hits[:10] + split_merge_hits[:10] + relay_hits[:10]
    confidence = "none"
    if circular_hits and (split_merge_hits or relay_hits):
        confidence = "high"
    elif len(circular_hits) >= 2 or len(split_merge_hits) >= 2:
        confidence = "high"
    elif circular_hits or split_merge_hits or relay_hits:
        confidence = "medium"

    risk_lines: list[str] = []
    if circular_hits:
        risk_lines.append(f"{len(circular_hits)} circular SOL flow cycle(s) detected in funder chain graph.")
    if split_merge_hits:
        risk_lines.append(f"{len(split_merge_hits)} split-and-merge pattern(s): single source fans out then converges.")
    if relay_hits:
        risk_lines.append(f"{len(relay_hits)} relay pattern(s): bridge/mixer program → relay → holder funder chain.")

    return {
        "confidence": confidence,
        "circular_flows": circular_hits[:10],
        "split_merge_flows": split_merge_hits[:10],
        "relay_flows": relay_hits[:10],
        "all_patterns": all_patterns[:20],
        "pattern_count": len(all_patterns),
        "risk_lines": risk_lines,
    }


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

_BRIDGE_JSON = Path(__file__).resolve().parent / "bridge_programs_solana.json"
_MIXER_INTEL_JSON = Path(__file__).resolve().parent / "mixer_service_intel.json"
_bridge_pid_to_label: dict[str, str] = {}
_mixer_pid_to_label: dict[str, str] = {}


def load_bridge_program_allowlist() -> dict[str, str]:
    global _bridge_pid_to_label
    if _bridge_pid_to_label:
        return dict(_bridge_pid_to_label)
    m: dict[str, str] = {}
    try:
        if _BRIDGE_JSON.exists():
            raw = json.loads(_BRIDGE_JSON.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for row in raw:
                    if not isinstance(row, dict):
                        continue
                    pid = row.get("id")
                    lbl = row.get("label") or row.get("category") or "bridge"
                    if isinstance(pid, str) and pid:
                        m[pid] = str(lbl)[:120]
    except Exception:
        pass
    _bridge_pid_to_label = m
    return dict(m)


def load_mixer_program_allowlist() -> dict[str, str]:
    """Load known Solana mixer/privacy program IDs from mixer_service_intel.json."""
    global _mixer_pid_to_label
    if _mixer_pid_to_label:
        return dict(_mixer_pid_to_label)
    m: dict[str, str] = {}
    _tier_rank = {"unverified_candidate": 0, "verified_analytics": 1, "verified_primary": 2}
    _min_rank = _tier_rank.get(
        (os.environ.get("DIVERG_MIXER_MIN_TIER") or "verified_analytics").strip().lower(),
        1,
    )
    try:
        if _MIXER_INTEL_JSON.exists():
            raw = json.loads(_MIXER_INTEL_JSON.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                progs = raw.get("solana_mixer_programs")
                if isinstance(progs, list):
                    for row in progs:
                        if not isinstance(row, dict):
                            continue
                        pid = row.get("id")
                        lbl = row.get("label") or "mixer_program"
                        tier = str(row.get("tier") or "unverified_candidate").strip().lower()
                        if isinstance(pid, str) and pid and _tier_rank.get(tier, 0) >= _min_rank:
                            m[pid] = str(lbl)[:120]
    except Exception:
        pass
    _mixer_pid_to_label = m
    return dict(m)


def build_funding_cluster_bridge_mixer(
    *,
    program_sets: dict[str, set[str]],
    lookup_wallets: list[str],
    privacy_mixer_funding_strict: list[dict[str, Any]],
    funder_mixer_flags: dict[str, bool],
    bridge_count_eligible_wallets: Optional[list[str]] = None,
    funder_program_sets: Optional[dict[str, set[str]]] = None,
    meta_by_wallet: Optional[dict[str, dict[str, Any]]] = None,
    root_map: Optional[dict[str, Optional[str]]] = None,
    funder_cex_tier: Optional[dict[str, str]] = None,
    shared_outbound: Optional[dict[str, Any]] = None,
    transfers_cache: Optional[dict[str, Optional[dict]]] = None,
    funder_chain_by_wallet: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """
    bridge_count_eligible_wallets: when non-empty, only these wallets count toward bridge_adjacent_* and
    shared_bridge_programs (focus-cluster–scoped signal). When None/empty, all lookup_wallets are eligible.
    """
    allow = load_bridge_program_allowlist()
    mixer_allow = load_mixer_program_allowlist()
    chains = funder_chain_by_wallet if isinstance(funder_chain_by_wallet, dict) else {}
    eligible: Optional[set[str]] = None
    if bridge_count_eligible_wallets:
        eligible = {str(x).strip() for x in bridge_count_eligible_wallets if x and str(x).strip()}
    risk_lines: list[str] = []
    wallet_hits: list[dict[str, Any]] = []
    bridge_touch_wallets: list[str] = []
    for w in lookup_wallets:
        if eligible is not None and w not in eligible:
            continue
        progs = program_sets.get(w) or set()
        hits = []
        for pid in progs:
            if pid in allow:
                hits.append({"program_id": pid, "label": allow[pid]})
        if hits:
            bridge_touch_wallets.append(w)
            wallet_hits.append({
                "wallet": w,
                "bridge_program_hits": hits[:8],
                "note": "Bridge-related program observed in sampled Helius enhanced txs (not proof of cross-chain wash).",
            })
    if bridge_touch_wallets:
        risk_lines.append(
            f"{len(bridge_touch_wallets)} sampled wallet(s) touched known bridge-program IDs in recent tx sample."
        )
    mixer_wallet_count = 0
    for grp in privacy_mixer_funding_strict or []:
        try:
            mixer_wallet_count = max(mixer_wallet_count, int(grp.get("wallet_count") or 0))
        except (TypeError, ValueError):
            continue
    if mixer_wallet_count >= 2:
        risk_lines.append(
            "Privacy/mixer-tagged shared funder cluster (strict): multiple wallets share tagged funder path."
        )
    elif any(funder_mixer_flags.values()):
        risk_lines.append("At least one sampled funder has mixer/privacy-style tags (Helius identity).")
    if bridge_touch_wallets and (mixer_wallet_count >= 2 or any(funder_mixer_flags.values())):
        risk_lines.append(
            "Bridge-touched wallets and mixer-tagged funding paths both appear in sample — manual trace recommended."
        )
    by_prog: dict[str, list[str]] = defaultdict(list)
    for w in bridge_touch_wallets:
        for pid in (program_sets.get(w) or set()):
            if pid in allow:
                by_prog[pid].append(w)
    shared_program_hits = [
        {
            "program_id": pid,
            "label": allow.get(pid, ""),
            "wallet_count": len(set(ws)),
            "wallets_sample": sorted(set(ws))[:12],
        }
        for pid, ws in by_prog.items()
        if len(set(ws)) >= 2
    ]
    bridge_mixer_confidence_tier = "low"
    if shared_program_hits:
        bridge_mixer_confidence_tier = "high"
    elif bridge_touch_wallets and (mixer_wallet_count >= 2 or any(funder_mixer_flags.values())):
        bridge_mixer_confidence_tier = "medium"
    elif bridge_touch_wallets:
        bridge_mixer_confidence_tier = "low"

    # --- On-chain mixer program detection (wallet-level + funder-level) ---
    mixer_program_wallet_hits: list[dict[str, Any]] = []
    mixer_program_touch_wallets: list[str] = []
    for w in lookup_wallets:
        if eligible is not None and w not in eligible:
            continue
        progs = program_sets.get(w) or set()
        mhits = [{"program_id": pid, "label": mixer_allow[pid]} for pid in progs if pid in mixer_allow]
        if mhits:
            mixer_program_touch_wallets.append(w)
            mixer_program_wallet_hits.append({"wallet": w, "mixer_program_hits": mhits[:8]})
    funder_mixer_program_hits: list[dict[str, Any]] = []
    mixer_program_funder_count = 0
    if funder_program_sets:
        for addr, progs in funder_program_sets.items():
            if not isinstance(addr, str) or not progs:
                continue
            mhits = [{"program_id": pid, "label": mixer_allow[pid]} for pid in progs if pid in mixer_allow]
            if mhits:
                mixer_program_funder_count += 1
                funder_mixer_program_hits.append({"funder": addr, "mixer_program_hits": mhits[:8]})
    # Check all addresses in funder chains for mixer program interaction
    wallets_with_mixer_program_touch: list[str] = []
    mixer_funder_addrs = {h["funder"] for h in funder_mixer_program_hits if isinstance(h.get("funder"), str)}
    if mixer_funder_addrs and meta_by_wallet is not None:
        rm = root_map if isinstance(root_map, dict) else {}
        for w in lookup_wallets:
            if eligible is not None and w not in eligible:
                continue
            chain_addrs = set(chains.get(w, [])[1:]) if chains else set()
            if not chain_addrs:
                meta = (meta_by_wallet or {}).get(w) or {}
                fund = meta.get("funder")
                root = rm.get(w)
                if isinstance(fund, str):
                    chain_addrs.add(fund)
                if isinstance(root, str):
                    chain_addrs.add(root)
            if chain_addrs & mixer_funder_addrs:
                wallets_with_mixer_program_touch.append(w)
    if mixer_program_touch_wallets:
        risk_lines.append(
            f"{len(mixer_program_touch_wallets)} wallet(s) interacted with known mixer/privacy program IDs on-chain."
        )
        if bridge_mixer_confidence_tier in ("low", "medium"):
            bridge_mixer_confidence_tier = "high"
    if mixer_program_funder_count:
        risk_lines.append(
            f"{mixer_program_funder_count} funder address(es) show mixer/privacy program interaction in enhanced tx sample."
        )

    # --- Funder / root path: bridge programs in sampled enhanced txs (cross-chain on-ramp hint) ---
    funder_bridge_hits: list[dict[str, Any]] = []
    bridge_program_funder_count = 0
    wallets_with_bridge_touching_funder: list[str] = []
    allow_keys = set(allow.keys())
    if funder_program_sets:
        for addr, progs in funder_program_sets.items():
            if not isinstance(addr, str) or not progs:
                continue
            hits = [{"program_id": pid, "label": allow[pid]} for pid in progs if pid in allow]
            if hits:
                bridge_program_funder_count += 1
                funder_bridge_hits.append(
                    {"funder": addr, "bridge_program_hits": hits[:8], "note": "Bridge program in funder/root tx sample."}
                )
    bridge_funder_addrs = {h["funder"] for h in funder_bridge_hits if isinstance(h.get("funder"), str)}
    if bridge_funder_addrs and meta_by_wallet is not None and root_map is not None:
        rm = root_map
        for w in lookup_wallets:
            if eligible is not None and w not in eligible:
                continue
            meta = meta_by_wallet.get(w) or {}
            fund = meta.get("funder")
            root = rm.get(w)
            matched = False
            if isinstance(fund, str) and fund in bridge_funder_addrs:
                matched = True
            if isinstance(root, str) and root in bridge_funder_addrs:
                matched = True
            if matched:
                wallets_with_bridge_touching_funder.append(w)
    w_bf = sorted(set(wallets_with_bridge_touching_funder))[:40]
    w_bf_n = len(w_bf)
    if w_bf_n >= 2:
        risk_lines.append(
            f"{w_bf_n} focus-path wallet(s) funded (direct or 2-hop root) by address(es) with bridge-program hits in sample."
        )
        if bridge_mixer_confidence_tier == "low":
            bridge_mixer_confidence_tier = "medium"
    elif w_bf_n == 1 and bridge_program_funder_count:
        risk_lines.append(
            "One sampled wallet’s funder path shows bridge-program activity in enhanced tx sample."
        )

    # --- CEX-routed split/fanout pattern (behavioral proxy for aggregator/CEX routing) ---
    cex_tier_map = funder_cex_tier if isinstance(funder_cex_tier, dict) else {}
    sh = shared_outbound if isinstance(shared_outbound, dict) else {}
    shared_recv_map = sh.get("shared_receiver_to_wallets") if isinstance(sh.get("shared_receiver_to_wallets"), dict) else {}
    cex_path_wallets: set[str] = set()
    cex_path_funders: set[str] = set()
    cex_path_hits: list[dict[str, Any]] = []
    for w in lookup_wallets:
        if eligible is not None and w not in eligible:
            continue
        meta = (meta_by_wallet or {}).get(w) if isinstance(meta_by_wallet, dict) else {}
        if not isinstance(meta, dict):
            continue
        direct = meta.get("funder")
        root = root_map.get(w) if isinstance(root_map, dict) else None
        candidates: list[tuple[str, str, str]] = []
        if isinstance(direct, str) and direct:
            tier = str(cex_tier_map.get(direct) or "none")
            if tier != "none":
                candidates.append(("direct", direct, tier))
        if isinstance(root, str) and root and root != direct:
            tier = str(cex_tier_map.get(root) or "none")
            if tier != "none":
                candidates.append(("root", root, tier))
        if not candidates:
            continue
        chosen = sorted(candidates, key=lambda x: (0 if x[2] == "strong" else 1, 0 if x[0] == "direct" else 1))[0]
        via, funder_addr, tier = chosen
        cex_path_wallets.add(w)
        cex_path_funders.add(funder_addr)
        cex_path_hits.append(
            {
                "wallet": w,
                "via": via,
                "funder_address": funder_addr,
                "tier": tier,
            }
        )

    cex_wallet_set = set(cex_path_wallets)
    shared_recv_hits: list[dict[str, Any]] = []
    for recv, ws in shared_recv_map.items():
        if not isinstance(recv, str):
            continue
        if not isinstance(ws, list):
            continue
        cset = sorted({x for x in ws if x in cex_wallet_set})
        if len(cset) >= 2:
            shared_recv_hits.append(
                {"receiver": recv, "wallet_count": len(cset), "wallets_sample": cset[:10]}
            )
    shared_recv_hits.sort(key=lambda x: -x["wallet_count"])

    fanout_avg = 0.0
    fanout_max = 0
    if transfers_cache:
        outbound_map = _outbound_receivers_by_wallet(sorted(cex_wallet_set), transfers_cache)
        fanouts = [len(v) for v in outbound_map.values() if isinstance(v, set)]
        if fanouts:
            fanout_avg = round(sum(fanouts) / float(len(fanouts)), 3)
            fanout_max = max(fanouts)

    cex_split_conf = "none"
    cex_w_n = len(cex_wallet_set)
    shared_recv_n = len(shared_recv_hits)
    if cex_w_n >= 3 and (shared_recv_n >= 2 or fanout_avg >= 3.0 or fanout_max >= 5):
        cex_split_conf = "high"
    elif cex_w_n >= 2 and (shared_recv_n >= 1 or fanout_avg >= 2.0 or fanout_max >= 3):
        cex_split_conf = "medium"
    elif cex_w_n >= 1:
        cex_split_conf = "low"

    if cex_split_conf in ("high", "medium"):
        risk_lines.append(
            f"CEX-routed split pattern ({cex_split_conf}): {cex_w_n} wallet(s) trace to CEX funder paths with outbound fanout/shared receivers."
        )

    return {
        "bridge_adjacent_wallet_count": len(set(bridge_touch_wallets)),
        "bridge_adjacent_wallets": sorted(set(bridge_touch_wallets))[:40],
        "wallet_bridge_hits": wallet_hits[:30],
        "shared_bridge_programs_multi_wallet": shared_program_hits[:15],
        "strict_mixer_cluster_max_wallets": mixer_wallet_count,
        "any_mixer_tagged_funder": any(funder_mixer_flags.values()),
        "risk_lines": risk_lines,
        "bridge_mixer_confidence_tier": bridge_mixer_confidence_tier,
        "bridge_signal_scope": "focus_cluster" if eligible else "all_sampled_wallets",
        "bridge_program_funder_count": bridge_program_funder_count,
        "funder_bridge_hits": funder_bridge_hits[:20],
        "wallets_with_bridge_touching_funder": w_bf_n,
        "wallets_with_bridge_touching_funder_sample": w_bf,
        "mixer_program_wallet_hits": mixer_program_wallet_hits[:30],
        "mixer_program_touch_wallet_count": len(mixer_program_touch_wallets),
        "funder_mixer_program_hits": funder_mixer_program_hits[:20],
        "mixer_program_funder_count": mixer_program_funder_count,
        "wallets_with_mixer_program_touch": sorted(set(wallets_with_mixer_program_touch))[:40],
        "cex_split_pattern_confidence": cex_split_conf,
        "cex_split_wallet_count": cex_w_n,
        "cex_split_funder_count": len(cex_path_funders),
        "cex_split_shared_receiver_count": shared_recv_n,
        "cex_split_fanout_avg": fanout_avg,
        "cex_split_fanout_max": fanout_max,
        "cex_split_path_hits": cex_path_hits[:30],
        "cex_split_shared_receiver_hits": shared_recv_hits[:20],
    }



def _enhanced_tx_type_str(tx: dict) -> Optional[str]:
    for k in ("type", "transactionType", "source", "txType"):
        v = tx.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()[:64]
    return None


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
    tx_types: set[str] = set()
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
        tt = _enhanced_tx_type_str(tx)
        if tt:
            tx_types.add(tt)
    return {
        "wallet": wallet,
        "mint_touch_slots": sorted(set(slots))[:20],
        "programs_sample": sorted(programs)[:40],
        "transaction_types_sample": sorted(tx_types)[:32],
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
    funder_root_by_wallet: Optional[dict[str, Optional[str]]] = None,
    funder_chain_by_wallet: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """
    Run all signals; return structured report + score 0–100.
    If transfers_cache_preload is set (e.g. from run_bundle_snapshot), reuse it to avoid duplicate /transfers calls.
    funder_root_by_wallet: optional N-hop root funder per wallet (deepest in chain); enables CEX/mixer
    attribution via root when direct funder is unlabeled.
    funder_chain_by_wallet: full funder chain per wallet (holder first, then each hop).
    """
    root_map: dict[str, Optional[str]] = funder_root_by_wallet if funder_root_by_wallet else {}
    chain_map: dict[str, list[str]] = funder_chain_by_wallet if funder_chain_by_wallet else {}

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

    root_addrs = sorted(
        {
            r
            for r in root_map.values()
            if isinstance(r, str) and r and r not in funder_idents
        }
    )[: max(0, MAX_FUNDER_ROOT_IDENTITY)]
    for i, ra in enumerate(root_addrs):
        funder_idents[ra] = helius_wallet_identity(ra)
        if i < len(root_addrs) - 1:
            time.sleep(0.04)

    ov = load_bundle_intel_overrides()

    def _cex_tier_str(addr: str, ident: Optional[dict]) -> str:
        return classify_cex_tier_for_funder(addr, ident, ov)[0]

    def _mixer_tier_str(addr: str, ident: Optional[dict]) -> str:
        return classify_mixer_tier_for_funder(addr, ident, ov)[0]

    funder_cex_tier: dict[str, str] = {}
    funder_mixer_tier: dict[str, str] = {}
    funder_cex_intel: dict[str, dict[str, Any]] = {}
    funder_mixer_intel: dict[str, dict[str, Any]] = {}
    for addr in funder_idents:
        ct, cr = classify_cex_tier_for_funder(addr, funder_idents.get(addr), ov)
        funder_cex_tier[addr] = ct
        funder_cex_intel[addr] = {"tier": ct, "reasons": cr}
        mt, mr = classify_mixer_tier_for_funder(addr, funder_idents.get(addr), ov)
        funder_mixer_tier[addr] = mt
        funder_mixer_intel[addr] = {"tier": mt, "reasons": mr}

    cex_funders = {f: _cex_tier_str(f, funder_idents.get(f)) != "none" for f in funders}
    funder_mixer_flags = {f: _mixer_tier_str(f, funder_idents.get(f)) != "none" for f in funders}

    _corr_mode = PARALLEL_CORROBORATION_MODE if PARALLEL_CORROBORATION_MODE in ("either", "dual") else "either"
    _spread = max(0.0, FUNDING_MAX_SPREAD_SEC)

    parallel_cex_funding_loose = _build_tagged_parallel_groups(
        lookup_wallets,
        meta_by_wallet,
        root_map,
        funder_idents,
        _cex_tier_str,
    )
    parallel_cex_funding = _strict_from_loose(
        parallel_cex_funding_loose,
        meta_by_wallet,
        FUNDING_TIME_BUCKET_SEC,
        LAMPORTS_REL_TOL,
        corroboration_mode=_corr_mode,
        max_spread_sec=_spread,
    )
    privacy_mixer_funding_loose = _build_tagged_parallel_groups(
        lookup_wallets,
        meta_by_wallet,
        root_map,
        funder_idents,
        _mixer_tier_str,
    )
    privacy_mixer_funding = _strict_from_loose(
        privacy_mixer_funding_loose,
        meta_by_wallet,
        FUNDING_TIME_BUCKET_SEC,
        LAMPORTS_REL_TOL,
        corroboration_mode=_corr_mode,
        max_spread_sec=_spread,
    )

    shared_inc = shared_inbound_senders(meta_by_wallet)
    shared_out = shared_outbound_receivers(lookup_wallets, transfers_cache)
    cex_split_pattern = build_cex_split_pattern(
        lookup_wallets=lookup_wallets,
        meta_by_wallet=meta_by_wallet,
        root_map=root_map,
        funder_cex_tier=funder_cex_tier,
        shared_outbound=shared_out,
        eligible_wallets=list(focus_wallets) if focus_wallets else None,
    )

    enhanced_sample: dict[str, Any] = {}
    co_slots_by_w: dict[str, list[int]] = {}
    program_sets: dict[str, set[str]] = {}
    type_sets: dict[str, set[str]] = {}
    mw = [w for w in (focus_wallets or lookup_wallets) if w in meta_by_wallet][:MAX_ENHANCED_FETCH]
    for i, w in enumerate(mw):
        em = enhanced_co_movement_mint(w, mint, limit=ENHANCED_TX_LIMIT)
        if em:
            co_slots_by_w[w] = em.get("mint_touch_slots") or []
            program_sets[w] = set(em.get("programs_sample") or [])
            ts = em.get("transaction_types_sample") or []
            if isinstance(ts, list):
                type_sets[w] = {str(x).strip().upper()[:64] for x in ts if x is not None and str(x).strip()}
        if i < len(mw) - 1:
            time.sleep(0.085)
    tx_types_by_wallet = {w: sorted(type_sets.get(w, set()))[:24] for w in mw if w in type_sets}
    enhanced_sample = {
        "wallets_analyzed": mw,
        "mint_touch_slots_by_wallet": co_slots_by_w,
        "transaction_types_by_wallet": tx_types_by_wallet,
    }

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

    type_overlap: list[dict[str, Any]] = []
    tkeys = list(type_sets.keys())
    for i in range(len(tkeys)):
        for j in range(i + 1, len(tkeys)):
            a, b = tkeys[i], tkeys[j]
            jt = jaccard(type_sets.get(a, set()), type_sets.get(b, set()))
            if jt > 0:
                type_overlap.append(
                    {"wallet_a": a, "wallet_b": b, "type_jaccard": round(jt, 4)}
                )
    type_overlap.sort(key=lambda x: -x["type_jaccard"])

    # --- Score 0-100 (cap)
    score = 0.0
    reasons: list[str] = []

    def _sample_funder_addrs() -> set[str]:
        s: set[str] = set()
        for w in lookup_wallets:
            ch = chain_map.get(w, [])
            for addr in ch[1:] if len(ch) >= 2 else []:
                if isinstance(addr, str):
                    s.add(addr)
            d = meta_by_wallet.get(w, {}).get("funder")
            if isinstance(d, str):
                s.add(d)
            r = root_map.get(w)
            if isinstance(r, str):
                s.add(r)
        return s

    sample_addrs = _sample_funder_addrs()
    funder_program_sets: dict[str, set[str]] = {}
    funder_native_flows: dict[str, list[dict[str, Any]]] = {}
    _fb_max = SOLANA_BUNDLE_FUNDER_BRIDGE_ENHANCED_MAX
    if _fb_max > 0:
        fund_pool = sorted(
            a for a in sample_addrs if isinstance(a, str) and _ADDR_RE.match(a)
        )[:_fb_max]
        for i, fa in enumerate(fund_pool):
            txs = helius_enhanced_transactions(fa, limit=min(40, ENHANCED_TX_LIMIT))
            if isinstance(txs, list):
                acc: set[str] = set()
                for tx in txs:
                    if isinstance(tx, dict):
                        acc |= _programs_from_enhanced(tx)
                if acc:
                    funder_program_sets[fa] = acc
                flows = _native_transfers_from_enhanced(txs)
                if flows:
                    funder_native_flows[fa] = flows[:200]
            if i < len(fund_pool) - 1:
                time.sleep(0.06)

    wash_flow_patterns = detect_wash_flow_patterns(
        funder_native_flows,
        chain_map,
        bridge_programs=load_bridge_program_allowlist(),
        mixer_programs=load_mixer_program_allowlist(),
    )

    any_strong_cex = any(funder_cex_tier.get(a) == "strong" for a in sample_addrs)
    any_cex = any(funder_cex_tier.get(a) in ("weak", "strong") for a in sample_addrs)

    if time_clusters:
        score += min(22, 6 + max(0, len(time_clusters[0]["wallets"]) - 2) * 4)
        reasons.append("funding_time_sync")
    if amount_clusters:
        score += min(18, 5 + max(0, len(amount_clusters[0]["wallets"]) - 2) * 3)
        reasons.append("same_first_fund_amount")
    if any_strong_cex:
        score += 10
        reasons.append("cex_strong_funder_in_sample")
    elif any_cex:
        score += 4
        reasons.append("cex_weak_funder_in_sample")
    if parallel_cex_funding:
        top_g = parallel_cex_funding[0]
        top_n = top_g["wallet_count"]
        ft = str(top_g.get("funder_tier") or "")
        if ft == "strong":
            score += min(16, 6 + max(0, top_n - 2) * 3)
            reasons.append("parallel_cex_funder_cluster_strict")
        else:
            score += min(10, 4 + max(0, top_n - 2) * 2)
            reasons.append("parallel_cex_funder_cluster_strict_weak_tier")
    elif parallel_cex_funding_loose:
        top_l = parallel_cex_funding_loose[0]["wallet_count"]
        score += min(6, 2 + max(0, top_l - 2) * 2)
        reasons.append("parallel_cex_funder_cluster_loose_only")
    if privacy_mixer_funding:
        top_gm = privacy_mixer_funding[0]
        top_m = top_gm["wallet_count"]
        mt = str(top_gm.get("funder_tier") or "")
        if mt == "strong":
            score += min(14, 5 + max(0, top_m - 2) * 2)
            reasons.append("privacy_mixer_shared_funder_strict")
        else:
            score += min(9, 3 + max(0, top_m - 2) * 2)
            reasons.append("privacy_mixer_shared_funder_strict_weak_tier")
    elif privacy_mixer_funding_loose:
        top_ml = privacy_mixer_funding_loose[0]["wallet_count"]
        score += min(5, 2 + max(0, top_ml - 2))
        reasons.append("privacy_mixer_funder_cluster_loose_only")
    if shared_inc.get("top_shared"):
        score += min(15, 5 + len(shared_inc["top_shared"]) * 2)
        reasons.append("shared_inbound_counterparty")
    if shared_out.get("top_shared_receivers"):
        score += min(16, 6 + len(shared_out["top_shared_receivers"]) * 2)
        reasons.append("shared_outbound_receiver")
    if co_move_pairs:
        score += min(18, 6 + min(len(co_move_pairs), 4) * 3)
        reasons.append("mint_activity_same_slot")
    if type_overlap and type_overlap[0]["type_jaccard"] >= ENHANCED_TYPE_OVERLAP_MIN:
        score += min(10, 4 + type_overlap[0]["type_jaccard"] * 14)
        reasons.append("enhanced_transaction_type_overlap")
    if p_overlap and p_overlap[0]["program_jaccard"] >= 0.15:
        score += min(15, 5 + p_overlap[0]["program_jaccard"] * 40)
        reasons.append("program_fingerprint_overlap")


    _bridge_eligible = list(focus_wallets) if focus_wallets else None
    funding_cluster_bridge_mixer = build_funding_cluster_bridge_mixer(
        program_sets=program_sets,
        lookup_wallets=list(lookup_wallets),
        privacy_mixer_funding_strict=privacy_mixer_funding[:12],
        funder_mixer_flags=funder_mixer_flags,
        bridge_count_eligible_wallets=_bridge_eligible,
        funder_program_sets=funder_program_sets,
        meta_by_wallet=meta_by_wallet,
        root_map=root_map,
        funder_cex_tier=funder_cex_tier,
        shared_outbound=shared_out,
        transfers_cache=transfers_cache,
        funder_chain_by_wallet=chain_map if chain_map else None,
    )

    # Funder/root path parity for mixer signals (same spirit as bridge-path signals)
    _eligible_wallets = set(_bridge_eligible) if _bridge_eligible else set(lookup_wallets)
    _mixer_path_hits: list[dict[str, Any]] = []
    _wallets_with_mixer_path: set[str] = set()
    _mixer_path_funders: set[str] = set()
    for _w in sorted(_eligible_wallets):
        _m = meta_by_wallet.get(_w) if isinstance(meta_by_wallet, dict) else None
        if not isinstance(_m, dict):
            continue
        _direct = _m.get("funder")
        _root = root_map.get(_w) if isinstance(root_map, dict) else None
        _cands: list[tuple[str, str]] = []
        if isinstance(_direct, str) and _direct:
            _cands.append(("direct", _direct))
        if isinstance(_root, str) and _root and _root != _direct:
            _cands.append(("root", _root))

        _chosen: Optional[tuple[str, str, str, list[str]]] = None
        for _via, _addr in _cands:
            _tier = str(funder_mixer_tier.get(_addr) or "none")
            if _tier == "none":
                continue
            _reasons = list((funder_mixer_intel.get(_addr) or {}).get("reasons") or [])
            if _chosen is None:
                _chosen = (_via, _addr, _tier, _reasons)
            elif _chosen[2] != "strong" and _tier == "strong":
                _chosen = (_via, _addr, _tier, _reasons)
        if _chosen:
            _via, _addr, _tier, _reasons = _chosen
            _wallets_with_mixer_path.add(_w)
            _mixer_path_funders.add(_addr)
            _mixer_path_hits.append(
                {
                    "wallet": _w,
                    "via": _via,
                    "funder_address": _addr,
                    "tier": _tier,
                    "reasons": _reasons[:4],
                }
            )

    funding_cluster_bridge_mixer["wallets_with_mixer_touching_funder"] = len(_wallets_with_mixer_path)
    funding_cluster_bridge_mixer["mixer_service_funder_count"] = len(_mixer_path_funders)
    funding_cluster_bridge_mixer["mixer_path_hits"] = _mixer_path_hits[:30]
    funding_cluster_bridge_mixer["any_strong_mixer_path"] = any(h.get("tier") == "strong" for h in _mixer_path_hits)
    if len(_wallets_with_mixer_path) >= 2:
        funding_cluster_bridge_mixer["risk_lines"] = (funding_cluster_bridge_mixer.get("risk_lines") or []) + [
            f"{len(_wallets_with_mixer_path)} focus-path wallet(s) map to funder/root addresses with mixer/privacy tags."
        ]
        if funding_cluster_bridge_mixer.get("bridge_mixer_confidence_tier") == "low":
            funding_cluster_bridge_mixer["bridge_mixer_confidence_tier"] = "medium"
    funding_cluster_bridge_mixer["cex_split_pattern"] = cex_split_pattern
    _cex_hits = list(cex_split_pattern.get("cex_path_hits") or [])
    _cex_recv_hits = list(cex_split_pattern.get("shared_outbound_receivers") or [])
    _fanouts: list[float] = []
    for _g in list(cex_split_pattern.get("shared_cex_funder_groups") or []):
        try:
            _fanouts.append(float(_g.get("wallet_count") or 0.0))
        except (TypeError, ValueError):
            continue
    _fanout_avg = (sum(_fanouts) / len(_fanouts)) if _fanouts else 0.0
    # Flat aliases kept for downstream UI/renderers that already read these keys.
    funding_cluster_bridge_mixer["cex_split_pattern_confidence"] = str(
        cex_split_pattern.get("confidence_tier") or "none"
    )
    funding_cluster_bridge_mixer["cex_split_wallet_count"] = int(
        cex_split_pattern.get("cex_path_wallet_count") or 0
    )
    funding_cluster_bridge_mixer["cex_split_shared_receiver_count"] = len(_cex_recv_hits)
    funding_cluster_bridge_mixer["cex_split_fanout_avg"] = round(_fanout_avg, 3)
    funding_cluster_bridge_mixer["cex_split_path_hits"] = _cex_hits[:30]
    funding_cluster_bridge_mixer["cex_split_shared_receiver_hits"] = _cex_recv_hits[:20]
    if cex_split_pattern.get("risk_lines"):
        funding_cluster_bridge_mixer["risk_lines"] = (
            funding_cluster_bridge_mixer.get("risk_lines") or []
        ) + list(cex_split_pattern.get("risk_lines") or [])
    if funding_cluster_bridge_mixer.get("shared_bridge_programs_multi_wallet"):
        score += min(8.0, 3.0 + 2.0 * len(funding_cluster_bridge_mixer["shared_bridge_programs_multi_wallet"]))
        reasons.append("bridge_program_multi_wallet_sample")
    elif funding_cluster_bridge_mixer.get("bridge_adjacent_wallet_count", 0) >= 2:
        score += min(5.0, 2.0 + 0.5 * funding_cluster_bridge_mixer["bridge_adjacent_wallet_count"])
        reasons.append("bridge_program_touched_multiple_holders")
    _w_bf = int(funding_cluster_bridge_mixer.get("wallets_with_bridge_touching_funder") or 0)
    if _w_bf >= 2:
        score += min(6.0, 2.0 + 0.5 * _w_bf)
        reasons.append("bridge_program_on_shared_funder_path")
    _w_mf = int(funding_cluster_bridge_mixer.get("wallets_with_mixer_touching_funder") or 0)
    if _w_mf >= 2:
        score += min(7.0, 2.5 + 0.6 * _w_mf)
        reasons.append("mixer_tag_on_shared_funder_path")
    elif _w_mf == 1:
        score += 1.0
        reasons.append("mixer_tag_on_single_funder_path")
    _mp_w = int(funding_cluster_bridge_mixer.get("mixer_program_touch_wallet_count") or 0)
    _mp_f = int(funding_cluster_bridge_mixer.get("mixer_program_funder_count") or 0)
    if _mp_w >= 2:
        score += min(12.0, 5.0 + 1.5 * _mp_w)
        reasons.append("mixer_program_onchain_multi_wallet")
    elif _mp_w == 1:
        score += 3.0
        reasons.append("mixer_program_onchain_single_wallet")
    if _mp_f >= 1:
        score += min(8.0, 3.0 + 1.0 * _mp_f)
        reasons.append("mixer_program_on_funder_path")
    _wash_conf = str(wash_flow_patterns.get("confidence") or "none")
    if _wash_conf == "high":
        score += 12.0
        reasons.append("wash_flow_pattern_high")
    elif _wash_conf == "medium":
        score += 6.0
        reasons.append("wash_flow_pattern_medium")
    _cex_split_tier = str(cex_split_pattern.get("confidence_tier") or "none")
    if _cex_split_tier == "high":
        score += 9.0
        reasons.append("cex_split_pattern_high")
    elif _cex_split_tier == "medium":
        score += 6.0
        reasons.append("cex_split_pattern_medium")
    elif _cex_split_tier == "low":
        score += 2.0
        reasons.append("cex_split_pattern_low")

    score = round(min(100.0, score), 2)

    archetype_hints: list[str] = []
    if parallel_cex_funding:
        _strict_hint = (
            "same time bucket and similar first-fund SOL (dual mode)."
            if _corr_mode == "dual"
            else "aligned first-fund time bucket or similar first-fund SOL amount"
        )
        if _spread > 0:
            _strict_hint += f"; timestamps within {_spread:.0f}s where both known."
        archetype_hints.append(
            f"High-confidence parallel CEX: shared CEX-labeled funder (direct or 2-hop root) plus {_strict_hint}."
        )
    elif parallel_cex_funding_loose:
        archetype_hints.append(
            "Loose parallel CEX: same CEX-tagged funder among sampled wallets without funding-time/amount corroboration."
        )
    if privacy_mixer_funding:
        archetype_hints.append(
            "High-confidence privacy/mixer cluster: shared tagged funder plus aligned first-fund timing or lamports."
        )
    elif privacy_mixer_funding_loose:
        archetype_hints.append(
            "Loose privacy/mixer: same tagged funder path without funding corroboration."
        )
    if type_overlap and type_overlap[0]["type_jaccard"] >= ENHANCED_TYPE_OVERLAP_MIN:
        archetype_hints.append(
            "Enhanced tx types: sampled mint-touch transactions show similar Helius type labels across wallets."
        )
    if funding_cluster_bridge_mixer.get("risk_lines"):
        for line in funding_cluster_bridge_mixer["risk_lines"][:4]:
            archetype_hints.append(line)
    if wash_flow_patterns.get("risk_lines"):
        for line in wash_flow_patterns["risk_lines"][:3]:
            archetype_hints.append(line)

    tier_export_keys = sorted(sample_addrs | set(funders) | set(root_addrs))

    return {
        "funding_metadata_by_wallet": meta_by_wallet,
        "funding_time_clusters": time_clusters,
        "funding_same_amount_clusters": amount_clusters,
        "funder_cex_flags": cex_funders,
        "funder_mixer_flags": funder_mixer_flags,
        "funder_cex_tier": {k: funder_cex_tier[k] for k in tier_export_keys if k in funder_cex_tier},
        "funder_mixer_tier": {k: funder_mixer_tier[k] for k in tier_export_keys if k in funder_mixer_tier},
        "funder_cex_intel": {k: funder_cex_intel[k] for k in tier_export_keys if k in funder_cex_intel},
        "funder_mixer_intel": {k: funder_mixer_intel[k] for k in tier_export_keys if k in funder_mixer_intel},
        "parallel_cex_funding": parallel_cex_funding[:12],
        "parallel_cex_funding_loose": parallel_cex_funding_loose[:12],
        "privacy_mixer_funding": privacy_mixer_funding[:12],
        "privacy_mixer_funding_loose": privacy_mixer_funding_loose[:12],
        "bundle_archetype_hints": archetype_hints,
        "shared_inbound_senders": shared_inc,
        "shared_outbound_receivers": shared_out,
        "mint_co_movement": {"same_slot_groups": co_move_pairs[:15], "enhanced": enhanced_sample},
        "enhanced_tx_type_overlap_pairs": type_overlap[:20],
        "program_overlap_pairs": p_overlap[:20],
        "funding_cluster_bridge_mixer": funding_cluster_bridge_mixer,
        "cex_split_pattern": cex_split_pattern,
        "wash_flow_patterns": wash_flow_patterns,
        "coordination_score": score,
        "coordination_reasons": reasons,
        "params": {
            "funding_bucket_sec": FUNDING_TIME_BUCKET_SEC,
            "lamports_rel_tol": LAMPORTS_REL_TOL,
            "max_transfer_fetch": n_fetch,
            "max_enhanced_fetch": len(mw),
            "signal_transfers_limit": SIGNAL_TRANSFERS_LIMIT,
            "enhanced_tx_limit": ENHANCED_TX_LIMIT,
            "funder_root_identity_lookups": len(root_addrs),
            "parallel_corroboration_mode": _corr_mode,
            "funding_max_spread_sec": _spread,
            "enhanced_type_overlap_min": ENHANCED_TYPE_OVERLAP_MIN,
            "intel_overrides_loaded": bool((os.environ.get("SOLANA_BUNDLE_INTEL_OVERRIDES_PATH") or "").strip()),
            "funder_bridge_enhanced_max": SOLANA_BUNDLE_FUNDER_BRIDGE_ENHANCED_MAX,
            "funder_bridge_wallets_sampled": len(funder_program_sets),
            "funder_chain_depths": {w: len(ch) - 1 for w, ch in chain_map.items() if len(ch) >= 2},
        },
    }
