"""
FrontrunPro integration — no-cost (Address Finder) and optional paid API.

Without paying for the API you can still use FrontrunPro in investigations:
- address_finder_url(query): returns the public Address Finder URL. Pass a Twitter @handle
  (e.g. @ahmedattia) or a wallet fragment (e.g. 5ZkP…cikb). Open in browser to get the
  full Solana address. Use from any script or tool when you need "Twitter → wallet" or
  "partial address → full address" resolution.
- address_finder_url is the only no-API integration; no key required.

Paid API ($200+/month): linked wallets, mentioned wallets, renaming history, CA history,
KOL follow list. Contact https://t.me/frontrunintern for key and FRONTRUNPRO_BASE_URL.
Set FRONTRUNPRO_API_KEY + FRONTRUNPRO_BASE_URL to enable API calls; then wallet_enrichment()
and get_* functions return data. Paths in this module are placeholders until FrontrunPro
provides real API docs.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests

FRONTRUNPRO_KEY = os.environ.get("FRONTRUNPRO_API_KEY", "").strip()
# Base URL not published; set FRONTRUNPRO_BASE_URL once you receive it from FrontrunPro (t.me/frontrunintern)
FRONTRUNPRO_BASE_URL = os.environ.get("FRONTRUNPRO_BASE_URL", "").strip().rstrip("/")

# Placeholder paths — update when FrontrunPro provides real API docs
_PATH_LINKED_WALLETS = "/v1/wallet/{address}/linked"
_PATH_MENTIONED_WALLETS = "/v1/wallet/{address}/mentioned"
_PATH_RENAMING_HISTORY = "/v1/wallet/{address}/renaming-history"
_PATH_CA_HISTORY = "/v1/wallet/{address}/ca-history"
_PATH_KOL_FOLLOW_LIST = "/v1/wallet/{address}/kol-follow-list"
_PATH_KOL_FOLLOW_COUNT = "/v1/wallet/{address}/kol-follow-count"


def _get(
    path: str,
    address: str,
    *,
    timeout: int = 25,
) -> Optional[dict[str, Any]]:
    if not FRONTRUNPRO_KEY or not FRONTRUNPRO_BASE_URL:
        return None
    path = path.format(address=address)
    url = f"{FRONTRUNPRO_BASE_URL.rstrip('/')}{path}"
    try:
        r = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {FRONTRUNPRO_KEY}",
                "Accept": "application/json",
                "X-Api-Key": FRONTRUNPRO_KEY,
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def get_linked_wallets(address: str) -> Optional[dict]:
    """Linked wallets for a given address. Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_LINKED_WALLETS, address)


def get_mentioned_wallets(address: str) -> Optional[dict]:
    """Mentioned wallets (e.g. from CT/twitter). Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_MENTIONED_WALLETS, address)


def get_renaming_history(address: str) -> Optional[dict]:
    """Renaming / label history for the wallet. Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_RENAMING_HISTORY, address)


def get_ca_history(address: str) -> Optional[dict]:
    """Contract address (CA) history. Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_CA_HISTORY, address)


def get_kol_follow_list(address: str) -> Optional[dict]:
    """KOL follow list for the wallet. Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_KOL_FOLLOW_LIST, address)


def get_kol_follow_count(address: str) -> Optional[dict]:
    """Number of KOLs followed. Requires paid API + FRONTRUNPRO_API_KEY."""
    return _get(_PATH_KOL_FOLLOW_COUNT, address)


def wallet_enrichment(address: str) -> dict[str, Any]:
    """
    One-shot enrichment for a wallet: linked wallets, mentioned wallets,
    renaming history, CA history, KOL follow list and count.
    Returns a dict with keys present only when API returned data; all optional.
    """
    out: dict[str, Any] = {}
    if not FRONTRUNPRO_KEY or not FRONTRUNPRO_BASE_URL:
        return out
    out["linked_wallets"] = get_linked_wallets(address)
    out["mentioned_wallets"] = get_mentioned_wallets(address)
    out["renaming_history"] = get_renaming_history(address)
    out["ca_history"] = get_ca_history(address)
    out["kol_follow_list"] = get_kol_follow_list(address)
    out["kol_follow_count"] = get_kol_follow_count(address)
    return {k: v for k, v in out.items() if v is not None}


# --- No-API integration: public Address Finder ---

ADDRESS_FINDER_BASE = "https://www.frontrun.pro/address-finder"


def address_finder_url(query: str) -> str:
    """
    URL for FrontrunPro's public Address Finder (Twitter @handle or partial wallet → full Solana address).
    No API key needed. Use for manual lookup or link from tools.
    query: Twitter handle (e.g. @ahmedattia) or wallet fragment (e.g. 5ZkP…cikb).
    """
    from urllib.parse import quote
    return f"{ADDRESS_FINDER_BASE}?q={quote(query)}" if query.strip() else ADDRESS_FINDER_BASE


def is_configured() -> bool:
    """True if FRONTRUNPRO_API_KEY and FRONTRUNPRO_BASE_URL are set (API calls will be attempted)."""
    return bool(FRONTRUNPRO_KEY and FRONTRUNPRO_BASE_URL)
