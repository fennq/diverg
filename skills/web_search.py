"""
Web search skill — run a public search (DuckDuckGo) and return title/snippet/URL.
Used to collate web mentions with blockchain investigation (e.g. wallet + prompt).
No API key. Authorized use only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 15
MAX_RESULTS = 15


def _search_duckduckgo(query: str, max_results: int = 15) -> list[dict]:
    """Return list of {title, snippet, url} from DuckDuckGo HTML. No API key. Retries on 429/5xx."""
    import time
    results = []
    if not (query or "").strip():
        return results
    n = min(max(1, max_results), 30)
    url = "https://html.duckduckgo.com/html/"
    payload = {"q": query.strip()[:500]}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    for attempt in range(3):
        try:
            r = SESSION.post(url, data=payload, headers=headers, timeout=TIMEOUT)
            if r.status_code == 429:
                if attempt < 2:
                    time.sleep(2.0 + attempt * 2.0)
                    continue
                return results
            if r.status_code >= 500:
                if attempt < 2:
                    time.sleep(1.5 + attempt * 2.0)
                    continue
                return results
            if not r.ok:
                return results
            try:
                from bs4 import BeautifulSoup
            except ImportError:
                return results
            soup = BeautifulSoup(r.text, "html.parser")
            for block in soup.select(".result__body")[:n]:
                link = block.select_one(".result__url") or block.select_one("a.result__a")
                snippet_el = block.select_one(".result__snippet")
                title_el = block.select_one(".result__title") or block.select_one("a.result__a")
                title = (title_el.get_text(strip=True) if title_el else "")[:200]
                snippet = (snippet_el.get_text(strip=True) if snippet_el else "")[:400]
                href = ""
                if link and link.get("href"):
                    href = link["href"] if isinstance(link.get("href"), str) else ""
                if not href and title_el and title_el.get("href"):
                    href = title_el.get("href", "")
                if title or snippet or href:
                    results.append({"title": title, "snippet": snippet, "url": href})
            return results
        except Exception:
            if attempt < 2:
                time.sleep(1.0 + attempt * 2.0)
                continue
            return results
    return results


def run(query: str, max_results: int = 15) -> str:
    """Run a web search; return JSON with results (title, snippet, url) for collation with blockchain report."""
    n = 15
    if max_results and 1 <= max_results <= 30:
        n = max_results
    hits = _search_duckduckgo(query or "", max_results=n)
    out = {
        "query": (query or "").strip()[:500],
        "result_count": len(hits),
        "results": hits,
        "note": "Public web search only; use with run_blockchain_investigation to collate chain + web.",
    }
    return json.dumps(out, indent=2)
