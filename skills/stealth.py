"""
Stealth module — ghost-mode networking for all SecTester skills.

Features:
  - User-Agent rotation (25+ real browser strings)
  - Full header randomization per request (Accept, Lang, Referer, etc.)
  - Timing jitter with human-like patterns (not uniform random)
  - Adaptive rate limiting (auto-backoff on 429/403)
  - Proxy / SOCKS5 / Tor support
  - Referer spoofing (same-domain to look like internal navigation)
  - Cookie jar (accept + replay cookies like a real browser)
  - Request order randomization helper
  - DNS-over-HTTPS to avoid DNS-level logging
  - Auto-cleanup of connection fingerprints
  - No identifying strings anywhere in traffic
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import ssl
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("stealth")

# ---------------------------------------------------------------------------
# User-Agent pool — real browsers, updated regularly
# ---------------------------------------------------------------------------

USER_AGENTS = [
    # Chrome (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
]

ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en,en-US;q=0.9",
    "en-US,en;q=0.8",
]

ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]

SEC_FETCH_SITE = ["none", "same-origin", "same-site", "cross-site"]
SEC_FETCH_MODE = ["navigate", "cors", "no-cors"]
SEC_FETCH_DEST = ["document", "empty"]


# ---------------------------------------------------------------------------
# Header generation — every request looks like a different real browser
# ---------------------------------------------------------------------------

def random_headers(target_url: str = "") -> dict[str, str]:
    """Generate a complete set of realistic browser headers."""
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANG),
        "Accept-Encoding": random.choice(ACCEPT_ENCODING),
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Sec-Fetch-* headers (modern browsers send these)
    if random.random() > 0.3:
        headers["Sec-Fetch-Site"] = random.choice(SEC_FETCH_SITE)
        headers["Sec-Fetch-Mode"] = random.choice(SEC_FETCH_MODE)
        headers["Sec-Fetch-Dest"] = random.choice(SEC_FETCH_DEST)
        headers["Sec-Fetch-User"] = "?1"

    # Referer spoofing — look like internal navigation
    if target_url and random.random() > 0.4:
        parsed = urlparse(target_url)
        if parsed.scheme and parsed.netloc:
            headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"

    # Randomly include/exclude optional headers to vary fingerprint
    if random.random() > 0.5:
        headers["DNT"] = "1"
    if random.random() > 0.6:
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
    if random.random() > 0.7:
        headers["Pragma"] = "no-cache"

    return headers


# ---------------------------------------------------------------------------
# Timing — human-like patterns, not uniform random
# ---------------------------------------------------------------------------

def jitter(min_s: float = 0.1, max_s: float = 0.5):
    """Sleep with human-like timing variance (slightly weighted toward faster)."""
    # Beta distribution gives more natural timing than uniform
    delay = min_s + (max_s - min_s) * random.betavariate(2, 5)
    time.sleep(delay)


def heavy_jitter():
    """Longer delay for sensitive operations to avoid detection."""
    time.sleep(random.uniform(1.0, 3.0))


# ---------------------------------------------------------------------------
# Adaptive rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Tracks responses and backs off when the target pushes back."""

    def __init__(self):
        self._backoff = 0.0
        self._consecutive_blocks = 0

    def check_response(self, resp: requests.Response):
        if resp.status_code in (429, 503):
            self._consecutive_blocks += 1
            self._backoff = min(30.0, 2 ** self._consecutive_blocks)
            log.warning(f"Rate limited ({resp.status_code}), backing off {self._backoff:.1f}s")
            time.sleep(self._backoff)
        elif resp.status_code == 403:
            self._consecutive_blocks += 1
            self._backoff = min(3.0, 1.3 ** self._consecutive_blocks)
            log.warning(f"Blocked (403), backing off {self._backoff:.1f}s")
            time.sleep(self._backoff)
        else:
            if self._consecutive_blocks > 0:
                self._consecutive_blocks = max(0, self._consecutive_blocks - 1)
                self._backoff = max(0, self._backoff * 0.5)

    @property
    def is_blocked(self) -> bool:
        return self._consecutive_blocks >= 5


# ---------------------------------------------------------------------------
# Stealth session — the core of ghost mode
# ---------------------------------------------------------------------------

class StealthSession(requests.Session):
    """Session with full anti-fingerprinting and adaptive behavior."""

    def __init__(
        self,
        proxy: Optional[str] = None,
        min_delay: float = 0.1,
        max_delay: float = 0.5,
    ):
        super().__init__()
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rate_limiter = RateLimiter()
        self._request_count = 0

        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

        self.verify = True

        # Mount adapter with connection pooling + retries
        adapter = HTTPAdapter(
            pool_connections=5,
            pool_maxsize=10,
            max_retries=2,
        )
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        # Merge randomized headers
        custom_headers = kwargs.pop("headers", {}) or {}
        base = random_headers(target_url=url)
        base.update(custom_headers)
        kwargs["headers"] = base

        if "timeout" not in kwargs:
            kwargs["timeout"] = 6

        # Jitter before request
        jitter(self.min_delay, self.max_delay)

        # If rate-limited, add extra delay
        if self.rate_limiter._backoff > 0:
            time.sleep(self.rate_limiter._backoff)

        self._request_count += 1

        resp = super().request(method, url, **kwargs)
        self.rate_limiter.check_response(resp)

        return resp

    @property
    def request_count(self) -> int:
        return self._request_count


def get_session(proxy: Optional[str] = None) -> StealthSession:
    """Get a stealth session. Pass proxy URL for Tor/SOCKS5."""
    proxy = proxy or os.environ.get("SECTESTER_PROXY")
    return StealthSession(proxy=proxy)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_scan_seed: str | None = None


def set_scan_seed(target_url: str) -> None:
    """Set a deterministic seed derived from the target URL.

    Call once per skill ``run()`` before any ``randomize_order`` calls so
    that the same target always produces the same probe ordering.
    """
    global _scan_seed
    _scan_seed = hashlib.sha256(target_url.encode()).hexdigest()


def randomize_order(items: list, *, seed: str | None = None) -> list:
    """Return a shuffled copy.  Uses a deterministic seed when available
    so that repeated scans of the same target hit the same probe order."""
    effective_seed = seed or _scan_seed
    shuffled = items.copy()
    if effective_seed is not None:
        random.Random(effective_seed).shuffle(shuffled)
    else:
        random.shuffle(shuffled)
    return shuffled


def dns_over_https(domain: str, record_type: str = "A") -> list[str]:
    """Resolve DNS via HTTPS (Cloudflare) to avoid local DNS logging."""
    try:
        resp = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            return [a["data"] for a in data.get("Answer", [])]
    except Exception:
        pass
    return []


def clean_traces():
    """Remove any temp files or traces left behind."""
    import glob
    from pathlib import Path
    patterns = [
        "/tmp/sectester_*",
        "/tmp/_tmp_exec*",
    ]
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                Path(f).unlink(missing_ok=True)
            except Exception:
                pass
