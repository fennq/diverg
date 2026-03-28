"""
On-chain data clients for any blockchain investigation (Solana).
- Solana RPC (public): getAccountInfo, getSignaturesForAddress — no key.
- Helius: wallet history, transfers, identity, funded-by, balances; optional DAS and enhanced transactions.
  Requires HELIUS_API_KEY. Base: api.helius.xyz (Wallet API), mainnet.helius-rpc.com (RPC/DAS).
"""
import os
from typing import Any, Optional

import requests

# Public Solana RPC (rate limited but no key)
RPC_URL = os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")

# Helius: Wallet API (REST); JSON-RPC/DAS use mainnet.helius-rpc.com (see Helius docs)
HELIUS_WALLET_BASE = "https://api.helius.xyz"
HELIUS_RPC_BASE = "https://mainnet.helius-rpc.com"


def _rpc(method: str, params: list) -> dict:
    """JSON-RPC call to Solana."""
    r = requests.post(
        RPC_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")


def rpc_get_balance(address: str) -> Optional[int]:
    """Return SOL balance in lamports, or None if account missing."""
    try:
        out = _rpc("getBalance", [address])
        if isinstance(out, dict):
            return out.get("value")
        if isinstance(out, (int, float)):
            return int(out)
        return None
    except Exception:
        return None


def rpc_get_account_info(address: str) -> Optional[dict]:
    """Return account info (lamports, owner, data size)."""
    try:
        out = _rpc("getAccountInfo", [address, {"encoding": "jsonParsed"}])
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def rpc_get_signatures(address: str, limit: int = 25) -> list:
    """Return recent transaction signatures for address."""
    try:
        out = _rpc("getSignaturesForAddress", [address, {"limit": limit}])
        return out if isinstance(out, list) else []
    except Exception:
        return []


# --- Helius (optional) ---
HELIUS_KEY = os.environ.get("HELIUS_API_KEY", "").strip()


def _helius_get(path: str, params: Optional[dict] = None, base: str = HELIUS_WALLET_BASE) -> Optional[dict]:
    if not HELIUS_KEY:
        return None
    url = f"{base.rstrip('/')}{path}"
    params = params or {}
    if "api-key" not in url and "api_key" not in params:
        params["api-key"] = HELIUS_KEY
    try:
        r = requests.get(url, headers={"X-Api-Key": HELIUS_KEY}, params=params, timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _helius_post_json_rpc(method: str, params: dict) -> Optional[Any]:
    """POST JSON-RPC to Helius RPC (DAS, etc.). Returns result or None."""
    res, _err = helius_das_rpc_ex(method, params)
    return res


def helius_das_rpc_ex(method: str, params: dict) -> tuple[Optional[Any], Optional[str]]:
    """
    DAS / object-param JSON-RPC on Helius (e.g. getTokenAccounts, getAsset).
    Standard methods like getTokenLargestAccounts use array params via helius_json_rpc_ex.
    """
    if not HELIUS_KEY:
        return None, "HELIUS_API_KEY not set"
    url = f"{HELIUS_RPC_BASE}/?api-key={HELIUS_KEY}"
    try:
        r = requests.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            headers={"Content-Type": "application/json"},
            timeout=90,
        )
        r.raise_for_status()
        data = r.json()
        err = data.get("error")
        if err:
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return None, msg or "DAS RPC error"
        return data.get("result"), None
    except Exception as e:
        return None, str(e)


def helius_das_token_accounts_for_mint(
    mint: str,
    *,
    max_pages: int = 30,
    page_limit: int = 100,
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """
    Paginated DAS getTokenAccounts for a mint (holder token accounts).
    Each dict: {"owner": str, "amount": int} raw token amount (before decimals).
    """
    rows: list[dict[str, Any]] = []
    cursor: Optional[str] = None
    lim = max(1, min(int(page_limit), 100))
    pages = max(1, int(max_pages))
    last_err: Optional[str] = None
    for _ in range(pages):
        params: dict[str, Any] = {"mint": mint, "limit": lim}
        if cursor:
            params["cursor"] = cursor
        result, err = helius_das_rpc_ex("getTokenAccounts", params)
        if err:
            last_err = err
            if not rows:
                return [], err
            break
        if not result or not isinstance(result, dict):
            break
        accounts = result.get("token_accounts")
        if not isinstance(accounts, list):
            break
        for a in accounts:
            if not isinstance(a, dict):
                continue
            owner = a.get("owner")
            amt = a.get("amount")
            if isinstance(owner, str) and owner and amt is not None:
                try:
                    rows.append({"owner": owner, "amount": int(amt)})
                except (TypeError, ValueError):
                    pass
        cursor = result.get("cursor")
        if not cursor or not accounts:
            break
    return rows, last_err


def helius_json_rpc_ex(method: str, params: list) -> tuple[Optional[Any], Optional[str]]:
    """
    Standard Solana JSON-RPC via Helius (array params). Returns (result, error_message).
    """
    if not HELIUS_KEY:
        return None, "HELIUS_API_KEY not set"
    url = f"{HELIUS_RPC_BASE}/?api-key={HELIUS_KEY}"
    try:
        r = requests.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        err = data.get("error")
        if err:
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return None, msg or "RPC error"
        return data.get("result"), None
    except Exception as e:
        return None, str(e)


def helius_json_rpc(method: str, params: list) -> Optional[Any]:
    """Same as helius_json_rpc_ex but returns only result (or None)."""
    res, _ = helius_json_rpc_ex(method, params)
    return res


def helius_wallet_history(address: str, limit: int = 25) -> Optional[dict]:
    """Parsed transaction history with balance changes. Requires HELIUS_API_KEY."""
    return _helius_get(f"/v1/wallet/{address}/history", {"limit": limit, "tokenAccounts": "balanceChanged"})


def helius_transfers(address: str, limit: int = 50) -> Optional[dict]:
    """Token and SOL transfers. Requires HELIUS_API_KEY. Helius caps limit at 100."""
    lim = max(1, min(int(limit), 100))
    return _helius_get(f"/v1/wallet/{address}/transfers", {"limit": lim})


def helius_wallet_identity(address: str) -> Optional[dict]:
    """Known wallet label (exchange, protocol, KOL, scammer, etc.). 404 if unknown. Requires HELIUS_API_KEY."""
    return _helius_get(f"/v1/wallet/{address}/identity")


def helius_wallet_funded_by(address: str) -> Optional[dict]:
    """Who funded this wallet (first incoming SOL). 404 if none. Requires HELIUS_API_KEY."""
    return _helius_get(f"/v1/wallet/{address}/funded-by")


def helius_wallet_balances(
    address: str,
    limit: int = 100,
    page: int = 1,
    show_nfts: bool = False,
    show_zero_balance: bool = False,
) -> Optional[dict]:
    """Token/NFT balances with USD values (top 10k tokens). Requires HELIUS_API_KEY."""
    params = {
        "limit": limit,
        "page": page,
        "showNfts": str(show_nfts).lower(),
        "showZeroBalance": str(show_zero_balance).lower(),
    }
    return _helius_get(f"/v1/wallet/{address}/balances", params)


def helius_enhanced_transactions(
    address: str,
    limit: int = 25,
    token_accounts: str = "balanceChanged",
    type_filter: Optional[str] = None,
) -> Optional[list]:
    """Parsed, human-readable transaction history (type/source). Requires HELIUS_API_KEY."""
    params = {"limit": limit, "token-accounts": token_accounts}
    if type_filter:
        params["type"] = type_filter
    out = _helius_get(f"/v0/addresses/{address}/transactions", params, base=HELIUS_RPC_BASE)
    if out is None:
        out = _helius_get(f"/v0/addresses/{address}/transactions", params, base=HELIUS_WALLET_BASE)
    if isinstance(out, list):
        return out
    if isinstance(out, dict):
        txs = out.get("transactions")
        if isinstance(txs, list):
            return txs
    return None


def helius_batch_identity(addresses: list[str]) -> Optional[list]:
    """Batch identity for up to 100 addresses. Requires HELIUS_API_KEY."""
    if not HELIUS_KEY or len(addresses) > 100:
        return None
    try:
        r = requests.post(
            f"{HELIUS_WALLET_BASE}/v1/wallet/batch-identity",
            headers={"X-Api-Key": HELIUS_KEY, "Content-Type": "application/json"},
            params={"api-key": HELIUS_KEY},
            json={"addresses": addresses},
            timeout=30,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def helius_das_assets_by_owner(
    address: str,
    page: int = 1,
    limit: int = 100,
    show_fungible: bool = True,
    show_native_balance: bool = True,
    show_nfts: bool = False,
) -> Optional[dict]:
    """DAS API: assets (tokens/NFTs) owned by wallet. Requires HELIUS_API_KEY."""
    params = {
        "ownerAddress": address,
        "page": page,
        "limit": limit,
        "displayOptions": {
            "showFungible": show_fungible,
            "showNativeBalance": show_native_balance,
            "showNfts": show_nfts,
        },
    }
    return _helius_post_json_rpc("getAssetsByOwner", params)


def helius_das_asset(mint: str) -> Optional[dict]:
    """DAS API: single asset/token metadata. Requires HELIUS_API_KEY."""
    return _helius_post_json_rpc("getAsset", {"id": mint})
