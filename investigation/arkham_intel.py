"""
Shared Arkham Intelligence API helpers (Intel API + legacy label endpoint).

Base Intel: https://api.arkm.com — docs https://intel.arkm.com/llms.txt
Explorer links: https://intel.arkm.com/explorer/address/{address}
"""
from __future__ import annotations

import os
import random
import threading
import time
from typing import Any, Optional

import requests

TIMEOUT = 12
ARKHAM_LEGACY_BASE = "https://api.arkhamintelligence.com"
ARKHAM_INTEL_BASE = "https://api.arkm.com"
ARKHAM_EXPLORER_PREFIX = "https://intel.arkm.com/explorer/address"
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, Any]] = {}


def _cache_ttl_sec() -> float:
    try:
        return float(os.environ.get("DIVERG_ARKHAM_CACHE_SEC", "900"))
    except ValueError:
        return 900.0


def _retry_attempts() -> int:
    try:
        return max(1, min(int(os.environ.get("DIVERG_ARKHAM_RETRY_ATTEMPTS", "3")), 6))
    except ValueError:
        return 3


def _retry_backoff_base_sec() -> float:
    try:
        return max(0.05, min(float(os.environ.get("DIVERG_ARKHAM_RETRY_BACKOFF_SEC", "0.35")), 3.0))
    except ValueError:
        return 0.35


def _cache_get(key: str) -> Any | None:
    now = time.time()
    with _CACHE_LOCK:
        row = _CACHE.get(key)
        if not row:
            return None
        exp, val = row
        if exp < now:
            _CACHE.pop(key, None)
            return None
        return val


def _cache_set(key: str, value: Any, ttl: Optional[float] = None) -> None:
    t = _cache_ttl_sec() if ttl is None else max(1.0, float(ttl))
    with _CACHE_LOCK:
        _CACHE[key] = (time.time() + t, value)


def _request_with_retry(
    method: str,
    url: str,
    *,
    session: requests.Session | Any,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
    timeout_sec: Optional[float] = None,
    attempts_override: Optional[int] = None,
) -> tuple[Optional[requests.Response], Optional[str]]:
    attempts = attempts_override if attempts_override is not None else _retry_attempts()
    base = _retry_backoff_base_sec()
    timeout = TIMEOUT if timeout_sec is None else max(0.5, float(timeout_sec))
    last_err = None
    for idx in range(attempts):
        try:
            if method == "GET":
                r = session.get(url, headers=headers, params=params, timeout=timeout)
            else:
                r = session.post(url, headers=headers, params=params, json=json_body, timeout=timeout)
            if r.ok:
                return r, None
            # Retry only transient/provider-side failures.
            if r.status_code not in (408, 409, 425, 429, 500, 502, 503, 504):
                return r, f"Arkham HTTP {r.status_code}: {r.text[:200] if r.text else r.reason}"
            last_err = f"Arkham HTTP {r.status_code}: {r.text[:200] if r.text else r.reason}"
        except requests.RequestException as e:
            last_err = f"Arkham request failed: {e}"
        if idx < attempts - 1:
            sleep_s = base * (2**idx) + random.uniform(0.01, 0.12)
            time.sleep(min(sleep_s, 2.5))
    return None, last_err or "Arkham request failed"


def explorer_url_for_address(address: str) -> str:
    return f"{ARKHAM_EXPLORER_PREFIX}/{address}"


def get_arkham_api_key() -> Optional[str]:
    k = (os.environ.get("ARKHAM_API_KEY") or "").strip()
    return k or None


def arkham_runtime_status(session: Optional[requests.Session] = None) -> dict[str, Any]:
    """
    Runtime Arkham status suitable for health checks.
    Returns configured/reachable/latency/error and never exposes secrets.
    """
    key = get_arkham_api_key()
    if not key:
        return {"configured": False, "reachable": False, "error": "ARKHAM_API_KEY is not set"}
    sess = session or requests
    t0 = time.time()
    # Use a cheap, deterministic call to verify key + endpoint.
    probe_addr = "11111111111111111111111111111111"
    r, err = _request_with_retry(
        "GET",
        f"{ARKHAM_INTEL_BASE}/intelligence/address/{probe_addr}/all",
        session=sess,
        headers={"API-Key": key},
        timeout_sec=float(os.environ.get("DIVERG_ARKHAM_HEALTH_TIMEOUT_SEC", "2.0") or "2.0"),
        attempts_override=1,
    )
    latency_ms = int((time.time() - t0) * 1000)
    if r is not None and r.ok:
        return {"configured": True, "reachable": True, "latency_ms": latency_ms}
    return {"configured": True, "reachable": False, "latency_ms": latency_ms, "error": err or "probe failed"}


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
    cache_key = f"addr_all:{address}"
    cached = _cache_get(cache_key)
    sess = session or requests
    r, err = _request_with_retry(
        "GET",
        f"{ARKHAM_INTEL_BASE}/intelligence/address/{address}/all",
        session=sess,
        headers={"API-Key": key},
    )
    if r is not None and r.ok:
        try:
            j = r.json()
        except ValueError:
            j = None
        if isinstance(j, dict):
            _cache_set(cache_key, j)
            return j, None
    # Stale cache fallback to avoid user-facing hard failure on transient outages.
    if isinstance(cached, dict):
        return cached, None
    return None, err or "Arkham request failed"


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
    batch = addresses[:50]
    cache_key = f"batch:{chain}:{','.join(sorted(batch))}"
    cached = _cache_get(cache_key)
    r, _err = _request_with_retry(
        "POST",
        f"{ARKHAM_INTEL_BASE}/intelligence/address/batch",
        session=session,
        params={"chain": chain} if chain else None,
        json_body={"addresses": batch},
        headers={"Content-Type": "application/json", "API-Key": api_key},
    )
    if r is not None and r.ok:
        try:
            j = r.json()
        except ValueError:
            j = {}
        for addr in batch:
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
        _cache_set(cache_key, out)
        return out
    if isinstance(cached, dict):
        return cached
    return out


def intel_counterparties(
    session: requests.Session,
    address: str,
    api_key: str,
    chain: str = "solana",
    limit: int = 10,
    time_last: str = "30d",
) -> list[dict]:
    cache_key = f"counter:{chain}:{address}:{limit}:{time_last}"
    cached = _cache_get(cache_key)
    r, _err = _request_with_retry(
        "GET",
        f"{ARKHAM_INTEL_BASE}/counterparties/address/{address}",
        session=session,
        params={"chains": chain, "limit": limit, "timeLast": time_last, "sortKey": "usd", "sortDir": "desc"},
        headers={"API-Key": api_key},
    )
    if r is not None and r.ok:
        try:
            j = r.json()
        except ValueError:
            j = None
        if isinstance(j, dict) and address in j:
            cp = j[address]
            out = cp if isinstance(cp, list) else []
            _cache_set(cache_key, out)
            return out
        if isinstance(j, list):
            out = j[:limit]
            _cache_set(cache_key, out)
            return out
    if isinstance(cached, list):
        return cached
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
    if s == "linea":
        return "linea"
    if s == "scroll":
        return "scroll"
    if s == "blast":
        return "blast"
    if s == "celo":
        return "celo"
    if s in ("gnosis", "xdai"):
        return "gnosis"
    if s in ("fantom", "ftm"):
        return "fantom"
    return "ethereum"
