"""
Optional JSON overrides for Solana bundle CEX/mixer classification.

Set SOLANA_BUNDLE_INTEL_OVERRIDES_PATH to a JSON file, e.g.:

{
  "wallet_cex_allowlist": ["KnownCexHotWallet..."],
  "wallet_cex_denylist": [],
  "wallet_mixer_allowlist": [],
  "wallet_mixer_denylist": [],
  "cex_extra_label_markers": ["woo"],
  "mixer_extra_label_markers": []
}

Lists are optional; omitted keys behave as empty.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_TIER_RANK = {
    "unverified_candidate": 0,
    "verified_analytics": 1,
    "verified_primary": 2,
}

_cache_path: str | None = None
_cache_mtime: float | None = None
_cache_data: dict[str, Any] | None = None
_MIXER_INTEL_FILE = Path(__file__).resolve().parent / "mixer_service_intel.json"


def _norm_addr(s: str) -> str | None:
    t = (s or "").strip()
    return t if _ADDR_RE.match(t) else None


def _min_tier_rank() -> int:
    raw = (os.environ.get("DIVERG_MIXER_MIN_TIER") or "verified_analytics").strip().lower()
    return _TIER_RANK.get(raw, _TIER_RANK["verified_analytics"])


def load_bundle_intel_overrides() -> dict[str, Any]:
    """Return normalized override dict (sets + tuples). Reloads when file mtime changes."""
    global _cache_path, _cache_mtime, _cache_data
    path = (os.environ.get("SOLANA_BUNDLE_INTEL_OVERRIDES_PATH") or "").strip()
    if not path:
        _cache_path = None
        _cache_mtime = None
        _cache_data = None
        return _empty_overrides()

    p = Path(path).expanduser()
    if not p.is_file():
        return _empty_overrides()

    try:
        mtime = p.stat().st_mtime
    except OSError:
        return _empty_overrides()

    if _cache_data is not None and str(p) == _cache_path and mtime == _cache_mtime:
        return _cache_data

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}

    if not isinstance(raw, dict):
        raw = {}

    def _set(key: str) -> set[str]:
        v = raw.get(key)
        if not isinstance(v, list):
            return set()
        out: set[str] = set()
        for x in v:
            a = _norm_addr(str(x))
            if a:
                out.add(a)
        return out

    def _markers(key: str) -> tuple[str, ...]:
        v = raw.get(key)
        if not isinstance(v, list):
            return ()
        return tuple(str(x).lower().strip() for x in v if x is not None and str(x).strip())

    _cache_data = {
        "wallet_cex_allowlist": _set("wallet_cex_allowlist"),
        "wallet_cex_denylist": _set("wallet_cex_denylist"),
        "wallet_mixer_allowlist": set(_default_mixer_wallet_allowlist()) | _set("wallet_mixer_allowlist"),
        "wallet_mixer_denylist": _set("wallet_mixer_denylist"),
        "cex_extra_label_markers": _markers("cex_extra_label_markers"),
        "mixer_extra_label_markers": tuple(
            dict.fromkeys(
                list(_default_mixer_label_markers()) + list(_markers("mixer_extra_label_markers"))
            )
        ),
    }
    _cache_path = str(p.resolve())
    _cache_mtime = mtime
    return _cache_data


def _empty_overrides() -> dict[str, Any]:
    return {
        "wallet_cex_allowlist": set(),
        "wallet_cex_denylist": set(),
        "wallet_mixer_allowlist": set(_default_mixer_wallet_allowlist()),
        "wallet_mixer_denylist": set(),
        "cex_extra_label_markers": (),
        "mixer_extra_label_markers": _default_mixer_label_markers(),
    }


def _default_mixer_label_markers() -> tuple[str, ...]:
    """Default mixer/privacy service label markers from local intel JSON."""
    try:
        if _MIXER_INTEL_FILE.is_file():
            raw = json.loads(_MIXER_INTEL_FILE.read_text(encoding="utf-8"))
            markers = raw.get("label_markers") if isinstance(raw, dict) else None
            if isinstance(markers, list):
                out: list[str] = []
                for x in markers:
                    if isinstance(x, dict):
                        marker = str(x.get("marker") or "").lower().strip()
                        tier = str(x.get("tier") or "unverified_candidate").lower().strip()
                        if marker and _TIER_RANK.get(tier, 0) >= _min_tier_rank():
                            out.append(marker)
                    elif x is not None and str(x).strip():
                        out.append(str(x).lower().strip())
                return tuple(dict.fromkeys(out))
    except Exception:
        pass
    # conservative defaults if intel file unavailable
    return ("tornado cash", "sinbad", "blender")


def _default_mixer_wallet_allowlist() -> tuple[str, ...]:
    """Default Solana mixer/privacy wallet allowlist from local intel JSON."""
    try:
        if _MIXER_INTEL_FILE.is_file():
            raw = json.loads(_MIXER_INTEL_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                sw = raw.get("solana_wallets")
                out: list[str] = []
                if isinstance(sw, dict):
                    for _svc, addrs in sw.items():
                        if isinstance(addrs, list):
                            for a in addrs:
                                # supports either raw address strings or {"address","tier",...}
                                if isinstance(a, dict):
                                    aa = _norm_addr(str(a.get("address") or ""))
                                    tier = str(a.get("tier") or "unverified_candidate").strip().lower()
                                    if aa and _TIER_RANK.get(tier, 0) >= _min_tier_rank():
                                        out.append(aa)
                                else:
                                    aa = _norm_addr(str(a))
                                    if aa:
                                        out.append(aa)
                elif isinstance(sw, list):
                    for a in sw:
                        if isinstance(a, dict):
                            aa = _norm_addr(str(a.get("address") or ""))
                            tier = str(a.get("tier") or "unverified_candidate").strip().lower()
                            if aa and _TIER_RANK.get(tier, 0) >= _min_tier_rank():
                                out.append(aa)
                        else:
                            aa = _norm_addr(str(a))
                            if aa:
                                out.append(aa)
                return tuple(dict.fromkeys(out))
    except Exception:
        pass
    return ()
