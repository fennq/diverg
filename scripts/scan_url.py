#!/usr/bin/env python3
"""Run a one-off web scan and print JSON (for threads/docs). Usage: python scripts/scan_url.py https://okara.ai/chat"""
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orchestrator import run_web_scan


def _validate_url(url: str) -> str | None:
    """Return a normalised URL or None if invalid."""
    url = (url or "").strip()
    if not url:
        return None
    # Reject non-http(s) schemes before auto-prefix
    if "://" in url and not url.startswith("http://") and not url.startswith("https://"):
        return None
    # Reject scheme-like patterns without "://" (e.g. "javascript:alert(1)")
    # but allow "host:port" where port is digits
    if "://" not in url and not url.startswith("http"):
        colon_idx = url.find(":")
        if colon_idx != -1:
            after_colon = url[colon_idx + 1:].split("/")[0]
            if not after_colon.isdigit():
                return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return url


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/scan_url.py <url>", file=sys.stderr)
        sys.exit(1)

    raw = sys.argv[1].strip()
    url = _validate_url(raw)
    if url is None:
        print(json.dumps({"error": True, "message": f"Invalid URL: {raw}"}), file=sys.stderr)
        sys.exit(1)

    try:
        result = run_web_scan(url, scope="full", goal=None)
        print(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        print(json.dumps({"error": True, "message": f"Scan failed: {exc}"}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
