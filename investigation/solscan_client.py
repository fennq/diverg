"""
Solscan public API client (api-v2.solscan.io).
Uses the same auth pattern as the Solscan web app; no API key required.
Not for production; may break if Solscan changes their API.
"""
import random
import time
from typing import Optional

try:
    import cloudscraper
    _session = cloudscraper.create_scraper()
except ImportError:
    import requests
    _session = requests.Session()

BASE_URL = "https://api-v2.solscan.io/v2"


def _solauth_token() -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==--"
    t = "".join(random.choice(chars) for _ in range(16))
    r = "".join(random.choice(chars) for _ in range(16))
    n = random.randint(0, 31)
    i = t + r
    return i[:n] + "B9dls0fK" + i[n:]


def _get(path: str, params: Optional[dict] = None) -> dict:
    params = {k: v for k, v in (params or {}).items() if v is not None}
    headers = {
        "Accept": "application/json, text/plain, */*",
        "sol-aut": _solauth_token(),
        "Referer": "https://solscan.io/",
        "Origin": "https://solscan.io",
    }
    r = _session.get(BASE_URL + path, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    if "data" in data:
        return data["data"]
    return data


def account_info(address: str) -> dict:
    """Get account summary (SOL balance, tx count, etc.)."""
    return _get("/account", {"address": address})


def account_transactions(address: str, page: int = 1, page_size: int = 20) -> dict:
    """Get transaction list for account."""
    return _get("/account/transaction", {"address": address, "page": page, "page_size": page_size})


def account_transfers(address: str, page: int = 1, page_size: int = 20, remove_spam: bool = True) -> dict:
    """Get transfer list for account."""
    return _get(
        "/account/transfer",
        {
            "address": address,
            "page": page,
            "page_size": page_size,
            "remove_spam": str(remove_spam).lower(),
            "exclude_amount_zero": "true",
        },
    )


def account_token_accounts(address: str, page: int = 1, page_size: int = 50, hide_zero: bool = True) -> dict:
    """Get token accounts (portfolio) for account."""
    return _get(
        "/account/tokenaccounts",
        {
            "address": address,
            "type": "token",
            "page": page,
            "page_size": page_size,
            "hide_zero": hide_zero,
        },
    )


def top_address_transfers(address: str, range_days: int = 7) -> dict:
    """Top counterparties by transfer volume."""
    return _get("/analytics/account/top-address-transfers", {"address": address, "range": range_days})


def token_holders(token_address: str, page: int = 1, page_size: int = 100) -> dict:
    """Get token holders (for a mint address)."""
    return _get("/token/holders", {"address": token_address, "page": page, "page_size": page_size})


def token_holders_total(token_address: str) -> dict:
    """Get total holder count for token."""
    return _get("/token/holder/total", {"address": token_address})


def token_metadata(token_address: str) -> dict:
    """Get token info (name, symbol, decimals, etc.) - common/sol-market style."""
    try:
        return _get("/common/sol-market", {"tokenAddress": token_address})
    except Exception:
        return {}


def throttle(seconds: float = 0.3):
    """Avoid hammering the API."""
    time.sleep(seconds)
