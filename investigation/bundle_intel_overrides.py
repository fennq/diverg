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

_cache_path: str | None = None
_cache_mtime: float | None = None
_cache_data: dict[str, Any] | None = None


def _norm_addr(s: str) -> str | None:
    t = (s or "").strip()
    return t if _ADDR_RE.match(t) else None


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
        "wallet_mixer_allowlist": _set("wallet_mixer_allowlist"),
        "wallet_mixer_denylist": _set("wallet_mixer_denylist"),
        "cex_extra_label_markers": _markers("cex_extra_label_markers"),
        "mixer_extra_label_markers": _markers("mixer_extra_label_markers"),
    }
    _cache_path = str(p.resolve())
    _cache_mtime = mtime
    return _cache_data


def _empty_overrides() -> dict[str, Any]:
    return {
        "wallet_cex_allowlist": set(),
        "wallet_cex_denylist": set(),
        "wallet_mixer_allowlist": set(),
        "wallet_mixer_denylist": set(),
        "cex_extra_label_markers": (),
        "mixer_extra_label_markers": (),
    }
