"""
EVM wallet investigation pipeline (public-data first, no paid key required).

Primary source: Ethplorer public API (`freekey`) for wallet info, token history, and tx info.
Optional enrichment: Etherscan v2 txlist when ETHERSCAN_API_KEY is configured.

Outputs:
- origin funder tracing (native + token)
- timestamped flow graph (in/out edges)
- pass-through / wash heuristics
- linked wallets around observed timestamps
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ETHPLORER_BASE = "https://api.ethplorer.io"
ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"

STABLE_SYMBOLS = {"USDC", "USDT", "DAI", "BUSD", "USDE", "TUSD", "USDP", "USDD", "FDUSD"}


def _http_get_json(url: str, *, headers: dict[str, str] | None = None, timeout: int = 30) -> Any:
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _ethplorer(path: str, params: dict[str, Any] | None = None) -> Any:
    q = {"apiKey": "freekey"}
    if params:
        q.update(params)
    url = f"{ETHPLORER_BASE}{path}?{urlencode(q)}"
    for attempt in range(3):
        try:
            return _http_get_json(url)
        except HTTPError as e:
            # Ethplorer freekey has stricter limits on some endpoints.
            if e.code == 429:
                time.sleep(1.2 * (attempt + 1))
                continue
            if isinstance(params, dict) and "limit" in params:
                fallback = dict(params)
                fallback["limit"] = min(int(params.get("limit") or 50), 50)
                q2 = {"apiKey": "freekey"}
                q2.update(fallback)
                try:
                    return _http_get_json(f"{ETHPLORER_BASE}{path}?{urlencode(q2)}")
                except HTTPError as e2:
                    if e2.code == 429:
                        time.sleep(1.2 * (attempt + 1))
                        continue
                    break
            break
    return {}


def _etherscan_v2(params: dict[str, Any]) -> Any:
    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        return None
    q = {"chainid": 1, "apikey": api_key}
    q.update(params)
    out = _http_get_json(f"{ETHERSCAN_V2_BASE}?{urlencode(q)}")
    if isinstance(out, dict) and out.get("status") == "1":
        return out.get("result")
    return None


@dataclass
class FlowEdge:
    timestamp: int
    tx_hash: str
    direction: str  # inbound | outbound
    wallet: str
    counterparty: str
    token_symbol: str
    token_contract: str
    amount_raw: str
    amount_decimals: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tx_hash": self.tx_hash,
            "direction": self.direction,
            "wallet": self.wallet,
            "counterparty": self.counterparty,
            "token_symbol": self.token_symbol,
            "token_contract": self.token_contract,
            "amount_raw": self.amount_raw,
            "amount_decimals": self.amount_decimals,
        }


def _safe_float_from_raw(raw: str | int | float | None, decimals: int | None) -> float | None:
    if raw is None or decimals is None:
        return None
    try:
        return float(raw) / (10 ** int(decimals))
    except Exception:
        return None


def _norm_addr(a: str | None) -> str:
    return (a or "").lower()


def get_address_info(address: str) -> dict[str, Any]:
    out = _ethplorer(f"/getAddressInfo/{address}")
    return out if isinstance(out, dict) else {}


def get_token_history(address: str, limit: int = 120) -> list[dict[str, Any]]:
    out = _ethplorer(f"/getAddressHistory/{address}", {"limit": limit})
    ops = out.get("operations") if isinstance(out, dict) else None
    return ops if isinstance(ops, list) else []


def get_native_transactions(address: str, limit: int = 120) -> list[dict[str, Any]]:
    # Prefer Etherscan v2 when available for fuller native history.
    txs = _etherscan_v2(
        {
            "module": "account",
            "action": "txlist",
            "address": address,
            "page": 1,
            "offset": limit,
            "sort": "asc",
        }
    )
    if isinstance(txs, list):
        normalized = []
        for t in txs:
            normalized.append(
                {
                    "timestamp": int(t.get("timeStamp") or 0),
                    "from": t.get("from"),
                    "to": t.get("to"),
                    "hash": t.get("hash"),
                    "rawValue": int(t.get("value") or 0),
                    "value": (float(t.get("value") or 0) / 1e18),
                    "success": (t.get("isError") == "0"),
                }
            )
        return normalized

    # Fallback: Ethplorer native tx view (often short history in freekey mode)
    out = _ethplorer(f"/getAddressTransactions/{address}", {"limit": min(limit, 50)})
    return out if isinstance(out, list) else []


def _extract_token_edges(address: str, ops: list[dict[str, Any]]) -> list[FlowEdge]:
    addr = _norm_addr(address)
    edges: list[FlowEdge] = []
    for o in ops:
        from_addr = _norm_addr(o.get("from"))
        to_addr = _norm_addr(o.get("to"))
        if from_addr != addr and to_addr != addr:
            continue
        token = o.get("tokenInfo") or {}
        symbol = token.get("symbol") or "UNKNOWN"
        token_addr = token.get("address") or ""
        decimals = token.get("decimals")
        try:
            dec_i = int(decimals) if decimals is not None else None
        except Exception:
            dec_i = None
        raw_val = str(o.get("value", "0"))
        direction = "inbound" if to_addr == addr else "outbound"
        counterparty = from_addr if direction == "inbound" else to_addr
        edges.append(
            FlowEdge(
                timestamp=int(o.get("timestamp") or 0),
                tx_hash=o.get("transactionHash") or "",
                direction=direction,
                wallet=addr,
                counterparty=counterparty,
                token_symbol=symbol,
                token_contract=token_addr,
                amount_raw=raw_val,
                amount_decimals=_safe_float_from_raw(raw_val, dec_i),
            )
        )
    edges.sort(key=lambda x: x.timestamp)
    return edges


def _origin_funders(address: str, native_txs: list[dict[str, Any]], token_ops: list[dict[str, Any]]) -> dict[str, Any]:
    addr = _norm_addr(address)
    native = sorted(native_txs, key=lambda x: int(x.get("timestamp") or 0))
    token_sorted = sorted(token_ops, key=lambda x: int(x.get("timestamp") or 0))

    first_native = None
    for tx in native:
        to_addr = _norm_addr(tx.get("to"))
        from_addr = _norm_addr(tx.get("from"))
        raw_val = tx.get("rawValue")
        if to_addr == addr and from_addr and from_addr != addr and (raw_val or 0) > 0:
            first_native = tx
            break

    first_token = None
    for op in token_sorted:
        to_addr = _norm_addr(op.get("to"))
        from_addr = _norm_addr(op.get("from"))
        if to_addr == addr and from_addr and from_addr != addr:
            first_token = op
            break

    return {
        "first_native_funder": {
            "address": _norm_addr(first_native.get("from")) if first_native else None,
            "tx_hash": first_native.get("hash") if first_native else None,
            "timestamp": first_native.get("timestamp") if first_native else None,
            "value_eth": first_native.get("value") if first_native else None,
        },
        "first_token_funder": {
            "address": _norm_addr(first_token.get("from")) if first_token else None,
            "tx_hash": first_token.get("transactionHash") if first_token else None,
            "timestamp": first_token.get("timestamp") if first_token else None,
            "token_symbol": ((first_token or {}).get("tokenInfo") or {}).get("symbol"),
            "amount_raw": first_token.get("value") if first_token else None,
        },
    }


def _trace_native_lineage(start_address: str, depth: int = 3, delay_s: float = 0.2) -> list[dict[str, Any]]:
    lineage: list[dict[str, Any]] = []
    current = _norm_addr(start_address)
    seen = set()

    for hop in range(depth):
        if not current or current in seen:
            break
        seen.add(current)
        txs = get_native_transactions(current, limit=120)
        if not txs:
            lineage.append({"hop": hop + 1, "address": current, "funder": None, "reason": "no_native_history"})
            break
        origin = _origin_funders(current, txs, [])
        funder = (origin.get("first_native_funder") or {}).get("address")
        row = {
            "hop": hop + 1,
            "address": current,
            "funder": funder,
            "tx_hash": (origin.get("first_native_funder") or {}).get("tx_hash"),
            "timestamp": (origin.get("first_native_funder") or {}).get("timestamp"),
            "value_eth": (origin.get("first_native_funder") or {}).get("value_eth"),
        }
        lineage.append(row)
        if not funder:
            break
        current = funder
        time.sleep(delay_s)
    return lineage


def _pass_through_pairs(edges: list[FlowEdge], max_time_delta_s: int = 3600, amount_tolerance: float = 0.01) -> list[dict[str, Any]]:
    inbound = [e for e in edges if e.direction == "inbound"]
    outbound = [e for e in edges if e.direction == "outbound"]
    pairs: list[dict[str, Any]] = []

    for inn in inbound:
        if inn.amount_decimals is None:
            continue
        best = None
        for out in outbound:
            if out.timestamp < inn.timestamp:
                continue
            if out.token_symbol != inn.token_symbol:
                continue
            if out.amount_decimals is None or inn.amount_decimals <= 0:
                continue
            delta_t = out.timestamp - inn.timestamp
            if delta_t > max_time_delta_s:
                continue
            pct_diff = abs(out.amount_decimals - inn.amount_decimals) / inn.amount_decimals
            if pct_diff > amount_tolerance:
                continue
            candidate = {
                "inbound_tx": inn.tx_hash,
                "outbound_tx": out.tx_hash,
                "token": inn.token_symbol,
                "in_amount": inn.amount_decimals,
                "out_amount": out.amount_decimals,
                "amount_pct_diff": round(pct_diff, 6),
                "time_delta_s": delta_t,
                "in_from": inn.counterparty,
                "out_to": out.counterparty,
            }
            if best is None or candidate["time_delta_s"] < best["time_delta_s"]:
                best = candidate
        if best:
            pairs.append(best)
    return pairs


def _major_counterparties(edges: list[FlowEdge], top_n: int = 8) -> list[dict[str, Any]]:
    scores: Counter = Counter()
    amounts: defaultdict[str, float] = defaultdict(float)
    for e in edges:
        scores[e.counterparty] += 1
        if e.amount_decimals:
            amounts[e.counterparty] += abs(e.amount_decimals)
    ranked = sorted(scores.items(), key=lambda kv: (kv[1], amounts.get(kv[0], 0.0)), reverse=True)[:top_n]
    out = []
    for addr, cnt in ranked:
        out.append({"address": addr, "interaction_count": cnt, "approx_amount_sum": round(amounts.get(addr, 0.0), 4)})
    return out


def _linked_wallets_by_time(
    counterparties: list[str],
    pivot_timestamps: list[int],
    *,
    allowed_token_contracts: set[str] | None = None,
    window_s: int = 1800,
) -> dict[str, Any]:
    linked_counter = Counter()
    evidence = []
    ts_set = [t for t in pivot_timestamps if t]
    if not ts_set:
        return {"linked_wallets": [], "evidence": []}

    for cp in counterparties[:3]:
        ops = get_token_history(cp, limit=60)
        for o in ops:
            ts = int(o.get("timestamp") or 0)
            if ts == 0:
                continue
            if not any(abs(ts - p) <= window_s for p in ts_set):
                continue
            token_info = o.get("tokenInfo") or {}
            token_contract = _norm_addr(token_info.get("address"))
            if allowed_token_contracts and token_contract not in allowed_token_contracts:
                continue
            from_addr = _norm_addr(o.get("from"))
            to_addr = _norm_addr(o.get("to"))
            if from_addr:
                linked_counter[from_addr] += 1
            if to_addr:
                linked_counter[to_addr] += 1
            evidence.append(
                {
                    "counterparty": cp,
                    "timestamp": ts,
                    "tx_hash": o.get("transactionHash"),
                    "from": from_addr,
                    "to": to_addr,
                    "token": (token_info.get("symbol") or "UNKNOWN"),
                    "token_contract": token_contract,
                    "amount_raw": o.get("value"),
                }
            )
        time.sleep(0.12)

    ranked = [{"address": a, "co_occurrence": c} for a, c in linked_counter.most_common(20)]
    return {"linked_wallets": ranked, "evidence": evidence[:120]}


def _cex_wash_assessment(address: str, edges: list[FlowEdge], pass_pairs: list[dict[str, Any]], counterparties: list[dict[str, Any]]) -> dict[str, Any]:
    # Public/no-key heuristic scoring. This is not legal attribution.
    stable_pass = [p for p in pass_pairs if p.get("token") in STABLE_SYMBOLS and (p.get("in_amount") or 0) >= 10000]
    short_hops = [p for p in stable_pass if (p.get("time_delta_s") or 999999) <= 1800]
    concentration = len(counterparties[:2]) / max(1, len(counterparties))

    score = 0
    if len(stable_pass) >= 1:
        score += 30
    if len(stable_pass) >= 2:
        score += 20
    if len(short_hops) >= 1:
        score += 15
    if concentration >= 0.3:
        score += 10
    # low residual posture signal
    outflow_count = len([e for e in edges if e.direction == "outbound"])
    inflow_count = len([e for e in edges if e.direction == "inbound"])
    if inflow_count and outflow_count and abs(inflow_count - outflow_count) <= max(1, int(0.5 * inflow_count)):
        score += 10
    score = min(100, score)

    level = "low"
    if score >= 65:
        level = "high"
    elif score >= 40:
        level = "medium"

    return {
        "score_0_to_100": score,
        "risk_level": level,
        "signals": {
            "stable_pass_through_count": len(stable_pass),
            "short_window_pass_through_count": len(short_hops),
            "major_counterparty_count": len(counterparties),
            "counterparty_concentration_ratio": round(concentration, 4),
        },
        "note": "Heuristic behavior score only. Does not prove legal identity or criminal intent.",
        "candidate_paths": stable_pass[:20],
    }


def investigate_evm_wallet(address: str, *, lineage_depth: int = 4, out_path: Path | None = None, verbose: bool = True) -> dict[str, Any]:
    addr = _norm_addr(address)
    if verbose:
        print(f"[EVM] Fetching wallet info for {addr}")
    info = get_address_info(addr)
    native_txs = get_native_transactions(addr, limit=120)
    token_ops = get_token_history(addr, limit=120)
    edges = _extract_token_edges(addr, token_ops)
    origin = _origin_funders(addr, native_txs, token_ops)
    lineage = _trace_native_lineage(addr, depth=lineage_depth)
    pass_pairs = _pass_through_pairs(edges)
    counterparties = _major_counterparties(edges)
    pivot_timestamps = [e.timestamp for e in edges[-30:]]
    legit_contracts = {
        _norm_addr(e.token_contract)
        for e in edges
        if _norm_addr(e.token_contract) and e.token_symbol in STABLE_SYMBOLS
    }
    linked = _linked_wallets_by_time(
        [c["address"] for c in counterparties],
        pivot_timestamps,
        allowed_token_contracts=legit_contracts or None,
    )
    wash = _cex_wash_assessment(addr, edges, pass_pairs, counterparties)

    result = {
        "wallet": addr,
        "chain": "ethereum",
        "generated_at_unix": int(time.time()),
        "data_sources": {
            "ethplorer": True,
            "etherscan_v2": bool(os.environ.get("ETHERSCAN_API_KEY")),
        },
        "address_info": {
            "eth_balance": ((info.get("ETH") or {}).get("balance") if isinstance(info, dict) else None),
            "tokens_preview": [
                {
                    "symbol": (t.get("tokenInfo") or {}).get("symbol"),
                    "balance_raw": t.get("balance"),
                }
                for t in (info.get("tokens") or [])[:20]
            ] if isinstance(info, dict) else [],
        },
        "origin_funders": origin,
        "native_lineage": lineage,
        "token_flow_edges": [e.as_dict() for e in edges],
        "major_counterparties": counterparties,
        "pass_through_pairs": pass_pairs,
        "linked_wallets_by_time": linked,
        "cex_wash_assessment": wash,
    }

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        if verbose:
            print(f"[EVM] Wrote {out_path}")
    return result

