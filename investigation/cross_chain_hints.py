"""Free cross-chain hints: cached Wormhole token list + optional CoinGecko.

Env:
  DIVERG_WORMHOLE_CACHE_SEC — wormhole CSV/json TTL (default 86400).
  DIVERG_COINGECKO_CACHE_SEC — CoinGecko response disk cache TTL (default 21600).
  COINGECKO_API_KEY — optional Pro API.
"""
from __future__ import annotations

import csv
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
_REPO_ROOT = ROOT.parent
DATA_DIR = _REPO_ROOT / "data"
CACHE_FILE = DATA_DIR / "wormhole_tokenlist_cache.json"
COINGECKO_CACHE_FILE = DATA_DIR / "coingecko_cross_chain_cache.json"

# Canonical chain slug -> block explorer token (contract) URL prefix
EXPLORER_TOKEN_PREFIX: dict[str, str] = {
    "ethereum": "https://etherscan.io/token/",
    "bsc": "https://bscscan.com/token/",
    "polygon": "https://polygonscan.com/token/",
    "base": "https://basescan.org/token/",
    "arbitrum": "https://arbiscan.io/token/",
    "optimism": "https://optimistic.etherscan.io/token/",
    "avalanche": "https://snowtrace.io/token/",
}
SOLSCAN_TOKEN_URL = "https://solscan.io/token/"
# CoinGecko / API platform id -> slug keys in EXPLORER_TOKEN_PREFIX (or solana)
_COINGECKO_PLAT_TO_SLUG: dict[str, str] = {
    "ethereum": "ethereum",
    "binance-smart-chain": "bsc",
    "polygon-pos": "polygon",
    "base": "base",
    "arbitrum-one": "arbitrum",
    "optimistic-ethereum": "optimism",
    "avalanche": "avalanche",
    "solana": "solana",
}
_WORMHOLE_CSV_URL = (
    "https://raw.githubusercontent.com/wormhole-foundation/wormhole-token-list/main/content/by_source.csv"
)
_WORMHOLE_TOKENLIST_URLS = [
    "https://raw.githubusercontent.com/wormhole-foundation/wormhole-token-list/main/src/tokens/solana.tokenlist.json",
    "https://raw.githubusercontent.com/wormhole-foundation/wormhole-token-list/main/artifacts/latest/solana.json",
]
_registry_meta: Optional[dict[str, Any]] = None
_registry_ts: float = 0.0


def _ttl() -> float:
    try:
        return float(os.environ.get("DIVERG_WORMHOLE_CACHE_SEC", "86400"))
    except ValueError:
        return 86400.0


def _coingecko_cache_ttl() -> float:
    try:
        return float(os.environ.get("DIVERG_COINGECKO_CACHE_SEC", "21600"))
    except ValueError:
        return 21600.0


def _coingecko_disk_load() -> dict[str, Any]:
    if not COINGECKO_CACHE_FILE.exists():
        return {}
    try:
        j = json.loads(COINGECKO_CACHE_FILE.read_text(encoding="utf-8"))
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _coingecko_cache_get_list(key: str) -> Optional[list]:
    blob = _coingecko_disk_load().get(key)
    if not isinstance(blob, dict):
        return None
    if time.time() - float(blob.get("fetched_at", 0)) > _coingecko_cache_ttl():
        return None
    items = blob.get("items")
    return items if isinstance(items, list) else None


def _coingecko_cache_set_list(key: str, items: list) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = _coingecko_disk_load()
    data[key] = {"fetched_at": time.time(), "items": items}
    COINGECKO_CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=0), encoding="utf-8")


def _canonical_explorer_slug(foreign_chain: str) -> Optional[str]:
    fc = (foreign_chain or "").strip().lower().replace(" ", "-")
    if fc in EXPLORER_TOKEN_PREFIX or fc == "solana":
        return fc
    return _COINGECKO_PLAT_TO_SLUG.get(fc)


def _foreign_explorer_url(foreign_chain: str, foreign_address: str) -> Optional[str]:
    fa = (foreign_address or "").strip()
    if not fa:
        return None
    slug = _canonical_explorer_slug(foreign_chain)
    if slug == "solana":
        if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", fa):
            return SOLSCAN_TOKEN_URL + fa
        return None
    if slug and slug in EXPLORER_TOKEN_PREFIX and fa.startswith("0x") and len(fa) >= 10:
        return EXPLORER_TOKEN_PREFIX[slug] + fa.lower()
    return None


def _enrich_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    d = dict(candidate)
    url = _foreign_explorer_url(d.get("foreign_chain") or "", d.get("foreign_address") or "")
    if url:
        d["foreign_explorer_url"] = url
    return d


def _finalize_candidates(candidates: list) -> list[dict[str, Any]]:
    return [_enrich_candidate(c) for c in candidates if isinstance(c, dict)]


def _http_get(url: str, timeout: float = 18.0) -> tuple[Optional[bytes], Optional[str]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Sectester-cross-chain/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)


def _parse_list(raw: bytes) -> Optional[list[dict[str, Any]]]:
    try:
        j = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(j, list):
        return [x for x in j if isinstance(x, dict)]
    if isinstance(j, dict):
        for key in ("tokens", "items", "data"):
            v = j.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return None

def _wormhole_csv_to_rows(raw: bytes) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return []
    lines = text.splitlines()
    if len(lines) < 2:
        return []
    rdr = csv.DictReader(lines)
    out: list[dict[str, Any]] = []
    for row in rdr:
        if not isinstance(row, dict):
            continue
        src = (row.get("source") or "").strip().lower()
        sym = row.get("symbol") or ""
        name = row.get("name") or ""
        sol_mint = ""
        if src == "sol":
            sol_mint = (row.get("sourceAddress") or "").strip()
        else:
            sol_mint = (row.get("solAddress") or "").strip()
        platforms: dict[str, str] = {}
        if sol_mint and re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", sol_mint):
            platforms["solana"] = sol_mint
        pairs = [
            ("ethereum", "ethAddress"), ("bsc", "bscAddress"), ("polygon", "maticAddress"),
            ("base", "baseAddress"), ("arbitrum", "arbitrumAddress"), ("optimism", "optimismAddress"),
            ("avalanche", "avaxAddress"),
        ]
        for slug, col in pairs:
            v = (row.get(col) or "").strip()
            if v.startswith("0x") and len(v) >= 10:
                platforms[slug] = v.lower()
        if len(platforms) < 2:
            continue
        out.append({"symbol": sym, "name": name, "mint": sol_mint or None, "address": sol_mint or None, "platforms": platforms})
    return out


def fetch_wormhole_token_rows(force: bool = False) -> list[dict[str, Any]]:
    global _registry_meta, _registry_ts
    now = time.time()
    ttl = _ttl()
    if not force and _registry_meta is not None and (now - _registry_ts) < ttl:
        return list(_registry_meta.get("rows") or [])
    rows: list[dict[str, Any]] = []
    err_note = ""
    if CACHE_FILE.exists() and not force:
        try:
            prev = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(prev, dict) and isinstance(prev.get("rows"), list):
                rows = [x for x in prev["rows"] if isinstance(x, dict)]
                if rows and (now - float(prev.get("fetched_at", 0))) < ttl:
                    _registry_meta = {"rows": rows, "source_url": prev.get("source_url", ""), "fetched_at": prev.get("fetched_at", now)}
                    _registry_ts = float(prev.get("fetched_at", now))
                    return rows
        except Exception:
            pass
    data, err = _http_get(_WORMHOLE_CSV_URL)
    if data and not err:
        csv_rows = _wormhole_csv_to_rows(data)
        if csv_rows:
            rows = csv_rows
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps({"source_url": _WORMHOLE_CSV_URL, "fetched_at": now, "row_count": len(rows), "rows": rows[:3000]}),
                encoding="utf-8",
            )
            _registry_meta = {"rows": rows, "source_url": _WORMHOLE_CSV_URL, "fetched_at": now}
            _registry_ts = now
            return rows
    for url in _WORMHOLE_TOKENLIST_URLS:
        data, err = _http_get(url)
        if err:
            err_note = err
            continue
        if not data:
            continue
        parsed = _parse_list(data)
        if parsed:
            rows = parsed
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps({"source_url": url, "fetched_at": now, "row_count": len(rows), "rows": rows[:2500]}),
                encoding="utf-8",
            )
            _registry_meta = {"rows": rows, "source_url": url, "fetched_at": now}
            _registry_ts = now
            return rows
    _registry_meta = {"rows": [], "source_url": "", "error": err_note or "no_rows", "fetched_at": now}
    _registry_ts = now
    return []


def _row_solana_mint(row: dict[str, Any]) -> Optional[str]:
    m = row.get("mint")
    if isinstance(m, str) and re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", m):
        return m
    for k in ("address", "mint", "tokenMint", "baseMint"):
        v = row.get(k)
        if isinstance(v, str) and re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", v):
            return v
    pl = row.get("platforms") or row.get("chains")
    if isinstance(pl, dict) and isinstance(pl.get("solana"), str):
        v = pl["solana"]
        if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", v):
            return v
    return None


def _row_evm_addresses(row: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    exts = row.get("extensions") or {}
    if isinstance(exts, dict):
        for k, v in exts.items():
            if not isinstance(v, str) or not v.startswith("0x"):
                continue
            kl = k.lower()
            if "eth" in kl or kl == "ethereum":
                out.append(("ethereum", v.lower()))
            if "bsc" in kl or "bnb" in kl:
                out.append(("bsc", v.lower()))
            if "polygon" in kl or "matic" in kl:
                out.append(("polygon", v.lower()))
            if "base" in kl:
                out.append(("base", v.lower()))
            if "arbitrum" in kl or kl == "arb":
                out.append(("arbitrum", v.lower()))
    pl = row.get("platforms") or row.get("addresses")
    if isinstance(pl, dict):
        mapping = {
            "ethereum": "ethereum", "eth": "ethereum", "bsc": "bsc", "binance-smart-chain": "bsc",
            "polygon-pos": "polygon", "polygon": "polygon", "base": "base", "arbitrum-one": "arbitrum",
            "avalanche": "avalanche",
        }
        for pk, addr in pl.items():
            if not isinstance(pk, str) or not isinstance(addr, str):
                continue
            if not addr.startswith("0x") or len(addr) < 10:
                continue
            slug = mapping.get(pk.lower().replace(" ", "-"))
            if slug:
                out.append((slug, addr.lower()))
    return out


def lookup_from_wormhole_list(sol_mint: Optional[str], evm_chain: Optional[str], evm_address: Optional[str]) -> list[dict[str, Any]]:
    rows = fetch_wormhole_token_rows()
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    sol_mint = (sol_mint or "").strip()
    evm_chain = (evm_chain or "").strip().lower()
    evm_address = (evm_address or "").strip().lower()
    for row in rows:
        sym = row.get("symbol") or row.get("ticker") or ""
        name = row.get("name") or ""
        sm = _row_solana_mint(row)
        evms = _row_evm_addresses(row)
        if sol_mint and sm == sol_mint:
            for ch, addr in evms:
                key = f"{ch}:{addr}"
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "bridge_hint": "wormhole_token_list", "foreign_chain": ch, "foreign_address": addr,
                    "foreign_symbol": str(sym)[:32] if sym else None, "name": str(name)[:120] if name else None,
                    "confidence": "verified_mapping",
                    "evidence_url": f"https://solscan.io/token/{sol_mint}",
                })
        if evm_address and evm_chain and sm:
            for ch, addr in evms:
                if addr == evm_address and ch == evm_chain:
                    key = f"sol:{sm}"
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append({
                        "bridge_hint": "wormhole_token_list", "foreign_chain": "solana", "foreign_address": sm,
                        "foreign_symbol": str(sym)[:32] if sym else None, "confidence": "verified_mapping",
                        "evidence_url": f"https://solscan.io/token/{sm}",
                    })
    return _finalize_candidates(candidates)


def _coingecko_fetch_json(url: str, timeout: float) -> Optional[dict[str, Any]]:
    key = (os.environ.get("COINGECKO_API_KEY") or "").strip()
    headers = {"User-Agent": "Sectester-cross-chain/1.0"}
    if key:
        headers["x-cg-pro-api-key"] = key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8"))
        return j if isinstance(j, dict) else None
    except Exception:
        return None


def lookup_coingecko_solana_mint(mint: str, timeout: float = 8.0) -> list[dict[str, Any]]:
    mint = (mint or "").strip()
    if not mint:
        return []

    cache_key = f"sol:{mint}"
    cached = _coingecko_cache_get_list(cache_key)
    if cached is not None:
        base = [c for c in cached if isinstance(c, dict)]
        return _finalize_candidates(base)[:25]

    key = (os.environ.get("COINGECKO_API_KEY") or "").strip()
    base_url = "https://pro-api.coingecko.com/api/v3" if key else "https://api.coingecko.com/api/v3"
    url = f"{base_url}/coins/solana/contract/{mint}"
    j = _coingecko_fetch_json(url, timeout)
    if not j:
        return []
    platforms = j.get("platforms") or {}
    if not isinstance(platforms, dict):
        return []
    out: list[dict[str, Any]] = []
    sym = j.get("symbol") or ""
    for plat, addr in platforms.items():
        if plat == "solana" or not isinstance(addr, str) or not addr.startswith("0x"):
            continue
        out.append({
            "bridge_hint": "coingecko_platforms", "foreign_chain": str(plat)[:64], "foreign_address": addr.lower(),
            "foreign_symbol": sym, "confidence": "third_party_metadata", "evidence_url": "https://www.coingecko.com/",
        })
    out = out[:25]
    _coingecko_cache_set_list(cache_key, out)
    return _finalize_candidates(out)


def lookup_solana_mint(
    mint: str, *, token_symbol: Optional[str] = None, token_name: Optional[str] = None,
    include_coingecko: bool = True,
) -> dict[str, Any]:
    mint = (mint or "").strip()
    out: dict[str, Any] = {"mint": mint, "candidates": [], "sources": [], "fetched_at": time.time()}
    if not mint:
        return out
    worm = lookup_from_wormhole_list(sol_mint=mint, evm_chain=None, evm_address=None)
    if worm:
        out["candidates"].extend(worm)
        out["sources"].append("wormhole_token_list")
    if include_coingecko:
        cg = lookup_coingecko_solana_mint(mint)
        if cg:
            out["candidates"].extend(cg)
            out["sources"].append("coingecko")
    return out


def _lookup_coingecko_evm_other_platforms(platform: str, contract: str, timeout: float = 8.0) -> tuple[list[dict[str, Any]], bool]:
    """Returns (cross-chain candidate rows, coingecko_fetch_ok)."""
    contract = (contract or "").strip().lower()
    platform = (platform or "").strip()
    if not contract.startswith("0x") or len(contract) != 42 or not platform:
        return [], False

    cache_key = f"evm:{platform}:{contract}"
    cached = _coingecko_cache_get_list(cache_key)
    if cached is not None:
        base = [c for c in cached if isinstance(c, dict)]
        return _finalize_candidates(base)[:25], True

    base_api = (os.environ.get("COINGECKO_API_KEY") or "").strip()
    root = "https://pro-api.coingecko.com/api/v3" if base_api else "https://api.coingecko.com/api/v3"
    url = f"{root}/coins/{platform}/contract/{contract}"
    j = _coingecko_fetch_json(url, timeout)
    if not j or not isinstance(j.get("platforms"), dict):
        return [], False
    out: list[dict[str, Any]] = []
    sym = j.get("symbol") or ""
    for p2, a2 in j["platforms"].items():
        if p2 == platform or not isinstance(a2, str) or not a2.startswith("0x"):
            continue
        out.append({
            "bridge_hint": "coingecko_platforms", "foreign_chain": str(p2)[:64],
            "foreign_address": a2.lower(), "foreign_symbol": sym,
            "confidence": "third_party_metadata", "evidence_url": "https://www.coingecko.com/",
        })
    out = out[:25]
    _coingecko_cache_set_list(cache_key, out)
    return _finalize_candidates(out), True


def lookup_evm_token(chain_slug: str, contract: str, *, include_coingecko: bool = True) -> dict[str, Any]:
    chain_slug = (chain_slug or "").strip().lower()
    contract = (contract or "").strip()
    out: dict[str, Any] = {"chain": chain_slug, "contract": contract, "candidates": [], "sources": [], "fetched_at": time.time()}
    if not contract.startswith("0x") or len(contract) != 42:
        return out
    worm = lookup_from_wormhole_list(sol_mint=None, evm_chain=chain_slug, evm_address=contract)
    if worm:
        out["candidates"].extend(worm)
        out["sources"].append("wormhole_token_list")
    platform_map = {
        "ethereum": "ethereum", "eth": "ethereum", "bsc": "binance-smart-chain", "bnb": "binance-smart-chain",
        "polygon": "polygon-pos", "matic": "polygon-pos", "base": "base",
        "arbitrum": "arbitrum-one", "arb": "arbitrum-one", "avalanche": "avalanche", "avax": "avalanche",
        "optimism": "optimistic-ethereum", "op": "optimistic-ethereum",
    }
    plat = platform_map.get(chain_slug)
    if include_coingecko and plat:
        cg_items, cg_ok = _lookup_coingecko_evm_other_platforms(plat, contract)
        if cg_ok:
            out["sources"].append("coingecko")
            out["candidates"].extend(cg_items)
    return out
