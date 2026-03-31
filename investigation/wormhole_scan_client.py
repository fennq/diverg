"""Wormhole Scan API client: bridge transfer history for Solana addresses.

Fetches cross-chain operations via the public Wormholescan API (no auth required).
Results are cached to disk per-address to avoid redundant network calls.

Env:
  SOLANA_BUNDLE_WORMHOLE_SCAN_MAX  — max wallet addresses to query (default 16, 0=off).
  DIVERG_WORMHOLE_TRANSFERS_CACHE_SEC — disk cache TTL in seconds (default 3600).

Output normalised per operation:
  {vaa_id, source_chain, source_address, dest_chain, dest_address,
   amount, token_symbol, timestamp_unix, source_tx_hash, explorer_url}

Disclaimer: Wormhole Scan shows emitter/counterparty addresses for Wormhole-protocol
transfers only. Results are investigative context; verify on official bridge explorers.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
_REPO_ROOT = ROOT.parent
DATA_DIR = _REPO_ROOT / "data"

WORMHOLE_SCAN_BASE = "https://api.wormholescan.io"
_TRANSFERS_CACHE_FILE = DATA_DIR / "wormhole_transfers_cache.json"

# Wormhole chain IDs → human-readable slug
WORMHOLE_CHAIN_IDS: dict[int, str] = {
    1: "solana",
    2: "ethereum",
    4: "bsc",
    5: "polygon",
    6: "avalanche",
    10: "fantom",
    13: "klaytn",
    14: "celo",
    16: "moonbeam",
    22: "aptos",
    23: "arbitrum",
    24: "optimism",
    28: "xpla",
    30: "base",
    32: "sei",
    34: "scroll",
    35: "mantle",
    36: "blast",
    40: "linea",
}

# Explorer address URL prefixes for known EVM chains
_EVM_EXPLORER_ADDR: dict[str, str] = {
    "ethereum": "https://etherscan.io/address/",
    "bsc": "https://bscscan.com/address/",
    "polygon": "https://polygonscan.com/address/",
    "avalanche": "https://snowtrace.io/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
    "base": "https://basescan.org/address/",
    "scroll": "https://scrollscan.com/address/",
    "mantle": "https://explorer.mantle.xyz/address/",
    "blast": "https://blastscan.io/address/",
    "linea": "https://lineascan.build/address/",
    "fantom": "https://ftmscan.com/address/",
}

_ADDR_RE_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ADDR_RE_SOL = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _cache_ttl() -> float:
    try:
        return float(os.environ.get("DIVERG_WORMHOLE_TRANSFERS_CACHE_SEC", "3600"))
    except ValueError:
        return 3600.0


def _load_cache() -> dict[str, Any]:
    if not _TRANSFERS_CACHE_FILE.exists():
        return {}
    try:
        j = json.loads(_TRANSFERS_CACHE_FILE.read_text(encoding="utf-8"))
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _save_cache(data: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _TRANSFERS_CACHE_FILE.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
    except Exception:
        pass


def _cache_get(address: str) -> Optional[list[dict[str, Any]]]:
    blob = _load_cache().get(address)
    if not isinstance(blob, dict):
        return None
    if time.time() - float(blob.get("fetched_at", 0)) > _cache_ttl():
        return None
    items = blob.get("items")
    return items if isinstance(items, list) else None


def _cache_set(address: str, items: list[dict[str, Any]]) -> None:
    data = _load_cache()
    data[address] = {"fetched_at": time.time(), "items": items}
    _save_cache(data)


def _chain_slug(chain_id: Any) -> str:
    try:
        cid = int(chain_id)
        return WORMHOLE_CHAIN_IDS.get(cid, f"chain_{cid}")
    except (TypeError, ValueError):
        return str(chain_id or "unknown")


def _evm_address_clean(raw: str) -> Optional[str]:
    """Normalise a 0x-padded 32-byte address to a standard 20-byte EVM address."""
    s = str(raw or "").strip()
    if not s:
        return None
    # 0x + 64 hex chars (32-byte) → trim leading zeros
    if len(s) == 66 and s.startswith("0x"):
        short = "0x" + s[-40:]
        if _ADDR_RE_EVM.match(short) and short != "0x0000000000000000000000000000000000000000":
            return short.lower()
    if _ADDR_RE_EVM.match(s):
        return s.lower()
    return None


def _explorer_url_for_address(chain_slug: str, address: str) -> Optional[str]:
    prefix = _EVM_EXPLORER_ADDR.get(chain_slug)
    if prefix and address:
        return prefix + address
    if chain_slug == "solana" and _ADDR_RE_SOL.match(address):
        return f"https://solscan.io/account/{address}"
    return None


def _normalise_operation(op: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Extract the useful cross-chain fields from one Wormhole Scan operation record."""
    if not isinstance(op, dict):
        return None
    vaa_id = op.get("id") or ""
    sp = {}
    content = op.get("content") or {}
    sp_raw = content.get("standarizedProperties")
    if isinstance(sp_raw, dict):
        sp = sp_raw

    from_chain = _chain_slug(sp.get("fromChain") or op.get("emitterChain"))
    to_chain = _chain_slug(sp.get("toChain") or (content.get("payload") or {}).get("toChain"))

    from_addr = str(sp.get("fromAddress") or "").strip()
    # toAddress may be 0x-padded 32-byte (EVM) or base58 (Solana)
    to_addr_raw = str(sp.get("toAddress") or "").strip()
    to_addr = _evm_address_clean(to_addr_raw) or None
    if to_addr is None and to_addr_raw:
        if _ADDR_RE_SOL.match(to_addr_raw):
            to_addr = to_addr_raw
        elif to_addr_raw:
            to_addr = to_addr_raw

    src_info = op.get("sourceChain") or {}
    src_tx = (src_info.get("transaction") or {}).get("txHash") or ""
    timestamp_str = src_info.get("timestamp") or ""
    timestamp_unix: Optional[int] = None
    if timestamp_str:
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            timestamp_unix = int(dt.timestamp())
        except Exception:
            pass

    data = op.get("data") or {}
    symbol = str(data.get("symbol") or sp.get("tokenSymbol") or "").strip() or None
    amount = str(data.get("tokenAmount") or sp.get("amount") or "").strip() or None
    usd_amount = str(data.get("usdAmount") or "").strip() or None

    # dest chain explorer URL for the counterparty address
    explorer_url = None
    if to_addr and to_chain:
        explorer_url = _explorer_url_for_address(to_chain, to_addr)

    if not from_addr and not to_addr:
        return None

    return {
        "vaa_id": vaa_id,
        "source_chain": from_chain,
        "source_address": from_addr or None,
        "dest_chain": to_chain,
        "dest_address": to_addr,
        "amount": amount,
        "usd_amount": usd_amount,
        "token_symbol": symbol,
        "timestamp_unix": timestamp_unix,
        "source_tx_hash": src_tx or None,
        "explorer_url": explorer_url,
    }


def fetch_bridge_operations(
    address: str,
    limit: int = 50,
    timeout: float = 14.0,
    use_cache: bool = True,
    max_pages: int = 4,
) -> list[dict[str, Any]]:
    """Return normalised Wormhole bridge operations involving `address`.

    Paginates up to `max_pages` pages (50 ops each, hard cap 200).
    Checks disk cache first (TTL controlled by DIVERG_WORMHOLE_TRANSFERS_CACHE_SEC).
    Returns empty list on network error or if address has no operations.
    """
    address = (address or "").strip()
    if not address:
        return []

    if use_cache:
        cached = _cache_get(address)
        if cached is not None:
            return cached

    page_size = min(limit, 50)
    hard_cap = min(limit, max_pages * 50, 200)
    results: list[dict[str, Any]] = []
    page = 0
    while len(results) < hard_cap and page < max_pages:
        params = urllib.parse.urlencode({
            "address": address,
            "pageSize": page_size,
            "page": page,
        })
        url = f"{WORMHOLE_SCAN_BASE}/api/v1/operations?{params}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Diverg-cross-chain/1.0",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
            j = json.loads(body)
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            break

        raw_ops = j if isinstance(j, list) else (j.get("operations") if isinstance(j, dict) else None)
        if not isinstance(raw_ops, list) or not raw_ops:
            break

        for op in raw_ops:
            norm = _normalise_operation(op)
            if norm:
                results.append(norm)

        if len(raw_ops) < page_size:
            break
        page += 1
        if page < max_pages:
            time.sleep(0.3)

    if use_cache and results:
        _cache_set(address, results)
    return results


def resolve_counterparties(
    addresses: list[str],
    limit_per: int = 20,
    rate_sleep: float = 0.35,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch Wormhole bridge transfer history for each address.

    Returns {address: [normalised_operations, ...]} for addresses that have activity.
    Respects SOLANA_BUNDLE_WORMHOLE_SCAN_MAX env (default 6); set to 0 to disable.
    """
    max_wallets = max(0, min(int(os.environ.get("SOLANA_BUNDLE_WORMHOLE_SCAN_MAX", "16")), 40))
    if max_wallets == 0 or not addresses:
        return {}

    out: dict[str, list[dict[str, Any]]] = {}
    sampled = [a for a in addresses if isinstance(a, str) and a.strip()][:max_wallets]

    for i, addr in enumerate(sampled):
        ops = fetch_bridge_operations(addr, limit=limit_per)
        if ops:
            out[addr] = ops
        if i < len(sampled) - 1:
            time.sleep(rate_sleep)

    return out


def extract_counterparty_evm_addresses(
    transfers_by_wallet: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Collect unique EVM destination addresses from Wormhole bridge transfers.

    These are the strongest cross-chain linkage signals — Solana wallets that
    sent funds to identifiable EVM addresses via the Wormhole protocol.
    """
    seen: dict[str, bool] = {}
    for ops in transfers_by_wallet.values():
        for op in ops:
            da = op.get("dest_address")
            if isinstance(da, str) and _ADDR_RE_EVM.match(da):
                seen[da.lower()] = True
    return sorted(seen.keys())


def extract_counterparty_solana_addresses(
    transfers_by_wallet: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Collect unique Solana destination addresses from Wormhole bridge transfers."""
    seen: set[str] = set()
    for ops in transfers_by_wallet.values():
        for op in ops:
            da = op.get("dest_address")
            if isinstance(da, str) and _ADDR_RE_SOL.match(da):
                seen.add(da)
            sa = op.get("source_address")
            if isinstance(sa, str) and _ADDR_RE_SOL.match(sa):
                seen.add(sa)
    return sorted(seen)
