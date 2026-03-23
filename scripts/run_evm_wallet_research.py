#!/usr/bin/env python3
"""
Run EVM wallet investigation with funder tracing and wash heuristics.

Usage:
  python scripts/run_evm_wallet_research.py --wallet 0x... [--depth 4] [--out investigation/evm_wallet.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

BASE = Path(__file__).parent.parent
INV = BASE / "investigation"
sys.path.insert(0, str(INV))

from evm_investigation import investigate_evm_wallet


def main() -> int:
    ap = argparse.ArgumentParser(description="EVM wallet investigation (funder trace + pass-through heuristics)")
    ap.add_argument("--wallet", required=True, help="EVM wallet address (0x...)")
    ap.add_argument("--depth", type=int, default=4, help="Native lineage depth (default: 4)")
    ap.add_argument("--out", default=None, help="Output JSON path")
    ap.add_argument("--print-summary", action="store_true", help="Print compact summary to stdout")
    args = ap.parse_args()

    wallet = args.wallet.strip().lower()
    if not wallet.startswith("0x") or len(wallet) != 42:
        print("Invalid EVM wallet format. Expected 0x + 40 hex chars.", file=sys.stderr)
        return 1

    out_path = Path(args.out) if args.out else (INV / f"evm_wallet_{wallet[2:10]}.json")
    result = investigate_evm_wallet(wallet, lineage_depth=max(1, args.depth), out_path=out_path, verbose=True)

    if args.print_summary:
        summary = {
            "wallet": result.get("wallet"),
            "first_native_funder": ((result.get("origin_funders") or {}).get("first_native_funder") or {}).get("address"),
            "first_token_funder": ((result.get("origin_funders") or {}).get("first_token_funder") or {}).get("address"),
            "pass_through_pairs": len(result.get("pass_through_pairs") or []),
            "wash_score": ((result.get("cex_wash_assessment") or {}).get("score_0_to_100")),
            "wash_level": ((result.get("cex_wash_assessment") or {}).get("risk_level")),
            "major_counterparties": (result.get("major_counterparties") or [])[:3],
        }
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

