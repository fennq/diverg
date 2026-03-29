"""
Optional X (Twitter) enrichment for Solana bundle snapshots.

Only attaches data when a search actually returns tweets mentioning the wallet.
Requires X_API_BEARER_TOKEN or NITTER_BASE_URL (see skills/x_search.py).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_HANDLE_RE = re.compile(r"@[A-Za-z0-9_]{1,15}")


def x_search_configured() -> bool:
    b = (os.environ.get("X_API_BEARER_TOKEN") or os.environ.get("TWITTER_BEARER_TOKEN") or "").strip()
    n = (os.environ.get("NITTER_BASE_URL") or "").strip()
    return bool(b or n)


def _import_x_search():
    root = Path(__file__).resolve().parents[1]
    skills = root / "skills"
    if not skills.is_dir():
        return None
    p = str(skills)
    if p not in sys.path:
        sys.path.insert(0, p)
    try:
        import x_search  # type: ignore

        return x_search
    except Exception:
        return None


def fetch_x_intel_for_wallet(address: str, *, max_results: int = 12) -> Optional[dict[str, Any]]:
    """
    Search recent X posts for the literal wallet address.
    Returns None if X is not configured, query invalid, or zero hits.
    """
    addr = (address or "").strip()
    if not _ADDR_RE.match(addr):
        return None
    mod = _import_x_search()
    if not mod:
        return None
    bearer = (getattr(mod, "X_BEARER", None) or "").strip()
    nitter = (getattr(mod, "NITTER_BASE", None) or "").strip()
    if not bearer and not nitter:
        return None

    raw = mod.run(addr, max_results=max(5, min(max_results, 50)))
    try:
        data = json.loads(raw) if isinstance(raw, str) else {}
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    results = data.get("results")
    if not isinstance(results, list) or not results:
        return None

    tweets_out: list[dict[str, Any]] = []
    handles_seen: set[str] = set()
    authors: set[str] = set()

    for row in results[:max_results]:
        if not isinstance(row, dict):
            continue
        text = str(row.get("text") or "")[:500]
        author = str(row.get("author_username") or "").strip()
        if author:
            authors.add(author.lower())
        for h in _HANDLE_RE.findall(text):
            handles_seen.add(h.lower())
        tweets_out.append(
            {
                "author_username": author or None,
                "text_snippet": text.strip(),
                "url": str(row.get("url") or "").strip() or None,
                "tweet_id": str(row.get("tweet_id") or "").strip() or None,
            }
        )

    if not tweets_out:
        return None

    source = str(data.get("source") or "unknown")
    return {
        "source": source,
        "query_wallet": addr,
        "tweet_count": len(tweets_out),
        "posting_authors": sorted(authors),
        "handles_in_tweets": sorted(handles_seen),
        "tweets": tweets_out[:max_results],
        "note": "Posts that match this address in search; authors are not verified on-chain owners.",
    }


def enrich_wallets_x_intel(
    wallets: list[str],
    *,
    max_wallets: int = 12,
    max_results_per_wallet: int = 10,
    delay_sec: float = 0.45,
) -> dict[str, dict[str, Any]]:
    """
    Sequential X lookups for a capped list of addresses.
    Returns only wallets with at least one hit (omit empty).
    """
    out: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    n = 0
    for w in wallets:
        if n >= max_wallets:
            break
        if not _ADDR_RE.match(w) or w in seen:
            continue
        seen.add(w)
        hit = fetch_x_intel_for_wallet(w, max_results=max_results_per_wallet)
        if hit:
            out[w] = hit
        n += 1
        if n < max_wallets and delay_sec > 0:
            time.sleep(delay_sec)
    return out
