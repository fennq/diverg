"""Free cross-chain hints: cached Wormhole token list + optional CoinGecko. Env: DIVERG_WORMHOLE_CACHE_SEC, COINGECKO_API_KEY."""
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
    return candidates


def lookup_coingecko_solana_mint(mint: str, timeout: float = 8.0) -> list[dict[str, Any]]:
    mint = (mint or "").strip()
    if not mint:
        return []
    key = (os.environ.get("COINGECKO_API_KEY") or "").strip()
    base = "https://pro-api.coingecko.com/api/v3" if key else "https://api.coingecko.com/api/v3"
    url = f"{base}/coins/solana/contract/{mint}"
    headers = {"User-Agent": "Sectester-cross-chain/1.0"}
    if key:
        headers["x-cg-pro-api-key"] = key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8"))
    except Exception:
        return []
    if not isinstance(j, dict):
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
    return out[:25]


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
    }
    plat = platform_map.get(chain_slug)
    if include_coingecko and plat:
        key = (os.environ.get("COINGECKO_API_KEY") or "").strip()
        base = "https://pro-api.coingecko.com/api/v3" if key else "https://api.coingecko.com/api/v3"
        url = f"{base}/coins/{plat}/contract/{contract.lower()}"
        headers = {"User-Agent": "Sectester-cross-chain/1.0"}
        if key:
            headers["x-cg-pro-api-key"] = key
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=8.0) as r:
                j = json.loads(r.read().decode("utf-8"))
            if isinstance(j, dict) and isinstance(j.get("platforms"), dict):
                out["sources"].append("coingecko")
                sym = j.get("symbol") or ""
                for p2, a2 in j["platforms"].items():
                    if p2 == plat or not isinstance(a2, str) or not a2.startswith("0x"):
                        continue
                    out["candidates"].append({
                        "bridge_hint": "coingecko_platforms", "foreign_chain": str(p2)[:64],
                        "foreign_address": a2.lower(), "foreign_symbol": sym,
                        "confidence": "third_party_metadata", "evidence_url": "https://www.coingecko.com/",
                    })
        except Exception:
            pass
    return out
