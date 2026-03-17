#!/usr/bin/env python3
"""Run a one-off web scan and print JSON (for threads/docs). Usage: python scripts/scan_url.py https://okara.ai/chat"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orchestrator import run_web_scan

def main():
    url = (sys.argv[1] or "").strip()
    if not url:
        print("Usage: python scripts/scan_url.py <url>", file=sys.stderr)
        sys.exit(1)
    if not url.startswith("http"):
        url = "https://" + url
    result = run_web_scan(url, scope="full", goal=None)
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()
