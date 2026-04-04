"""
Shared Arkham Intelligence API helpers (Intel API + legacy label endpoint).

Base Intel: https://api.arkm.com — docs https://intel.arkm.com/llms.txt
Explorer links: https://intel.arkm.com/explorer/address/{address}
"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests

TIMEOUT = 12
ARKHAM_LEGACY_BASE = "https://api.arkhamintelligence.com"
ARKHAM_INTEL_BASE = "https://api.arkm.com"
ARKHAM_EXPLORER_PREFIX = "https://intel.arkm.com/explorer/address"


def explorer_url_for_address(address: str) -> str:
    return f"{ARKHAM_EXPLORER_PREFIX}/{address}"


def get_arkham_api_key() -> Optional[str]:
    k = (os.environ.get("ARKHAM_API_KEY") or "").strip()
    return k or None


def require_arkham_api_key() -> str:
    k = get_arkham_api_key()
    if not k:
        raise ValueError(
            "ARKHAM_API_KEY is required for blockchain investigation features. "
            "Set it in the server environment or .env."
        )
    return k


def summarize_for_report(data: Optional[dict]) -> dict[str, Any]:
    """Extract entity / label fields from /intelligence/address/{addr}/all JSON."""
    if not data or not isinstance(data, dict):
        return {}
    out: dict[str, Any] = {"chains": list(data.keys())}
    for _chain, obj in data.items():
        if not isinstance(obj, dict):
            continue
        entity = obj.get("arkhamEntity") or obj.get("predictedEntity")
        label = obj.get("arkhamLabel") or obj.get("userLabel")
        if entity and isinstance(entity, dict):
            out["entity_name"] = entity.get("name")
            out["entity_type"] = entity.get("type")
            out["entity_id"] = entity.get("id")
        if label and isinstance(label, dict):
            out["label_name"] = label.get("name")
            out["label_note"] = label.get("note")
        break
    return out


def address_intelligence_all(
    address: str,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> tuple[Optional[dict], Optional[str]]:
    """
    GET /intelligence/address/{address}/all
    Returns (payload, error_message). error_message set on HTTP/network failure.
    """
    key = (api_key or get_arkham_api_key() or "").strip()
    if not key:
        return None, "ARKHAM_API_KEY is not set"
    sess = session or requests
    try:
        r = sess.get(
            f"{ARKHAM_INTEL_BASE}/intelligence/address/{address}/all",
            headers={"API-Key": key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return None, f"Arkham HTTP {r.status_code}: {r.text[:200] if r.text else r.reason}"
        j = r.json()
        return (j if isinstance(j, dict) else None), None
    except requests.RequestException as e:
        return None, f"Arkham request failed: {e}"


def legacy_label(
    session: requests.Session,
    address: str,
    api_key: str,
) -> Optional[str]:
    """Single-address label (legacy Bearer endpoint on api.arkhamintelligence.com)."""
    try:
        r = session.get(
            f"{ARKHAM_LEGACY_BASE}/api/address/{address}",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.ok:
            j = r.json()
            return j.get("label") or j.get("entity") or j.get("name")
    except Exception:
        pass
    return None


def intel_batch(
    session: requests.Session,
    addresses: list[str],
    api_key: str,
    chain: str = "solana",
) -> dict[str, str]:
    """POST intelligence/address/batch — returns address -> display name."""
    out: dict[str, str] = {}
    if not addresses or len(addresses) > 100:
        return out
    try:
        r = session.post(
            f"{ARKHAM_INTEL_BASE}/intelligence/address/batch",
            params={"chain": chain} if chain else None,
            json={"addresses": addresses[:50]},
            headers={"Content-Type": "application/json", "API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return out
        j = r.json()
        for addr in addresses:
            info = j.get(addr) if isinstance(j, dict) else None
            if not info:
                continue
            name = None
            if isinstance(info, dict):
                entity = info.get("arkhamEntity") or info.get("entity")
                label = info.get("arkhamLabel") or info.get("label")
                if entity and isinstance(entity, dict):
                    name = entity.get("name")
                if not name and label and isinstance(label, dict):
                    name = label.get("name")
                if not name:
                    name = info.get("name")
            if name:
                out[addr] = str(name)
    except Exception:
        pass
    return out


def intel_counterparties(
    session: requests.Session,
    address: str,
    api_key: str,
    chain: str = "solana",
    limit: int = 10,
    time_last: str = "30d",
) -> list[dict]:
    try:
        r = session.get(
            f"{ARKHAM_INTEL_BASE}/counterparties/address/{address}",
            params={"chains": chain, "limit": limit, "timeLast": time_last, "sortKey": "usd", "sortDir": "desc"},
            headers={"API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return []
        j = r.json()
        if isinstance(j, dict) and address in j:
            cp = j[address]
            return cp if isinstance(cp, list) else []
        if isinstance(j, list):
            return j[:limit]
    except Exception:
        pass
    return []


def intel_flow(
    session: requests.Session,
    address: str,
    api_key: str,
    chain: str = "solana",
    time_last: str = "30d",
) -> list | None:
    try:
        r = session.get(
            f"{ARKHAM_INTEL_BASE}/flow/address/{address}",
            params={"chains": chain, "timeLast": time_last},
            headers={"API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return None
        j = r.json()
        return j if isinstance(j, list) else j.get("flow") or j.get("data")
    except Exception:
        return None


def evm_chain_slug_for_arkham(chain_slug: str) -> str:
    """Map Diverg EVM chain slug to Arkham `chains` query value (best-effort)."""
    s = (chain_slug or "ethereum").lower().strip()
    if s == "bsc":
        return "bsc"
    if s in ("polygon", "matic"):
        return "polygon"
    if s == "base":
        return "base"
    if s == "arbitrum":
        return "arbitrum"
    if s == "optimism":
        return "optimism"
    if s in ("avalanche", "avax"):
        return "avalanche"
    return "ethereum"
