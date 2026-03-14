"""
X (Twitter) search — find tweets that mention a wallet or query.
Used to link wallets to X accounts and collate with blockchain + web.

Supports:
- X API v2 (Bearer token): reliable, rate-limited. Set X_API_BEARER_TOKEN in .env.
- Nitter fallback (optional): set NITTER_BASE_URL to a Nitter instance (e.g. https://nitter.poast.org)
  for scraping when no API key. Many public Nitter instances are rate-limited or down.

Authorized use only. Compliant with X API ToS when using official API.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote_plus, urljoin

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 20
MAX_RESULTS_API = 50
MAX_RESULTS_NITTER = 25

# Env: X API v2 Bearer (from developer portal). Or Nitter base URL for scrape fallback.
X_BEARER = (os.environ.get("X_API_BEARER_TOKEN") or os.environ.get("TWITTER_BEARER_TOKEN") or "").strip()
NITTER_BASE = (os.environ.get("NITTER_BASE_URL") or "").strip().rstrip("/")


def _search_x_api(query: str, max_results: int) -> list[dict]:
    """Search using X API v2 recent search. Returns list of {tweet_id, text, author_username, created_at, url}. Retries on 429."""
    if not X_BEARER or not query.strip():
        return []
    n = min(max(10, max_results), 100)
    import time
    q = query.strip()[:500]
    params = {
        "query": q,
        "max_results": n,
        "tweet.fields": "created_at,author_id",
        "expansions": "author_id",
        "user.fields": "username",
    }
    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {X_BEARER}"}
    for attempt in range(3):
        try:
            r = SESSION.get(url, params=params, headers=headers, timeout=TIMEOUT)
            if r.status_code == 429:
                if attempt < 2:
                    time.sleep(2.0 + attempt * 3.0)
                    continue
                return []
            if not r.ok:
                return []
            data = r.json()
            tweets = data.get("data") or []
            users = {u["id"]: u for u in (data.get("includes") or {}).get("users") or []}
            out = []
            for t in tweets:
                author_id = t.get("author_id")
                username = (users.get(author_id) or {}).get("username") or "unknown"
                tid = t.get("id") or ""
                text = (t.get("text") or "")[:500]
                created = (t.get("created_at") or "")[:19]
                out.append({
                    "tweet_id": tid,
                    "text": text,
                    "author_username": username,
                    "created_at": created,
                    "url": f"https://x.com/{username}/status/{tid}" if tid else "",
                })
            return out
        except Exception:
            if attempt < 2:
                time.sleep(1.0 + attempt * 2.0)
                continue
            return []
    return []


def _search_nitter(query: str, max_results: int) -> list[dict]:
    """Scrape Nitter search page. Returns same shape as API. Works only if NITTER_BASE_URL is set and instance is up."""
    if not NITTER_BASE or not query.strip():
        return []
    n = min(max(5, max_results), MAX_RESULTS_NITTER)
    results = []
    try:
        q = quote_plus(query.strip()[:300])
        # Nitter search: /search?f=tweets&q=...
        search_url = f"{NITTER_BASE}/search?f=tweets&q={q}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        r = SESSION.get(search_url, headers=headers, timeout=TIMEOUT)
        if not r.ok:
            return []
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        # Nitter: .timeline-item or .tweet-body; author in .username or a.tweet-link; content in .tweet-content
        items = soup.select(".timeline-item") or soup.select(".tweet-body") or []
        for item in items[:n]:
            tweet_id = item.get("data-tweet-id") or ""
            # Find username: often in .username or first .tweet-link
            username = "unknown"
            uname_el = item.select_one(".username") or item.select_one(".tweet-link")
            if uname_el:
                uname_text = uname_el.get_text(strip=True) or ""
                if uname_text and not uname_text.startswith("http"):
                    username = uname_text.lstrip("@")[:100]
            link_el = item.select_one("a[href*='/status/']") or item.select_one(".tweet-link[href*='/status/']")
            if link_el and link_el.get("href"):
                href = link_el["href"]
                # Nitter links often /user/status/id
                match = re.search(r"/status/(\d+)", href)
                if match and not tweet_id:
                    tweet_id = match.group(1)
                if "/" in href and username == "unknown":
                    parts = href.split("/")
                    for i, p in enumerate(parts):
                        if p == "status" and i > 0 and parts[i - 1]:
                            username = parts[i - 1].lstrip("@")[:100]
                            break
            content_el = item.select_one(".tweet-content") or item.select_one(".tweet-body")
            text = (content_el.get_text(separator=" ", strip=True) if content_el else "")[:500]
            # Time: .tweet-date or .timestamp
            time_el = item.select_one(".tweet-date") or item.select_one(".timestamp")
            created_at = (time_el.get_text(strip=True) if time_el else "")[:30]
            url = f"https://x.com/{username}/status/{tweet_id}" if tweet_id else ""
            results.append({
                "tweet_id": tweet_id,
                "text": text,
                "author_username": username,
                "created_at": created_at,
                "url": url,
            })
        return results
    except Exception:
        return []


def run(query: str, max_results: int = 20) -> str:
    """
    Search X (Twitter) for tweets matching the query (e.g. wallet address, "wallet scam").
    Use to link wallets to X accounts and add context. Returns JSON: source (api|nitter), result_count, results.
    """
    if not (query or "").strip():
        out = {"source": "none", "error": "query required", "result_count": 0, "results": []}
        return json.dumps(out, indent=2)
    q = query.strip()[:500]
    n = min(max(10, max_results), MAX_RESULTS_API)

    # Prefer X API; fallback to Nitter
    if X_BEARER:
        results = _search_x_api(q, n)
        if results:
            return json.dumps({
                "source": "x_api",
                "query": q,
                "result_count": len(results),
                "results": results,
                "note": "Use author_username and url to link wallets to X accounts.",
            }, indent=2)

    if NITTER_BASE:
        results = _search_nitter(q, n)
        if results:
            return json.dumps({
                "source": "nitter",
                "query": q,
                "result_count": len(results),
                "results": results,
                "note": "Nitter scrape. Use author_username and url to link wallets to X accounts.",
            }, indent=2)

    out = {
        "source": "none",
        "query": q,
        "result_count": 0,
        "results": [],
        "error": "No X_API_BEARER_TOKEN or NITTER_BASE_URL set, or no results. Set X_API_BEARER_TOKEN in .env (X Developer Portal) or NITTER_BASE_URL to a Nitter instance for scrape fallback.",
    }
    return json.dumps(out, indent=2)
