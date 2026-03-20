#!/usr/bin/env python3
"""
Generic blockchain on-chain fetch for any investigation (not Synq-specific).

Fetches: Solana RPC (balance, signatures), optional Helius, Arkham, FrontrunPro, Solscan token data.
Use for new investigations by passing wallet list and optional token mint.

Usage:
  # From CLI: space-separated wallets, optional token and output path
  python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 [ADDR3 ...] [--token MINT] [--out path.json]

  # From config file (e.g. for a new case)
  python scripts/run_blockchain_research.py --config investigation/cases/my_case.json

Config JSON format: { "wallets": ["addr1", "addr2"], "token": "optional_mint", "output": "optional/path.json" }
If output is omitted, writes to investigation/blockchain_data.json (or token-specific path when token given).

Environment: .env in project root. Optional keys: HELIUS_API_KEY, ARKHAM_API_KEY,
FRONTRUNPRO_API_KEY + FRONTRUNPRO_BASE_URL. No keys required for RPC + Solscan (public).
"""
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

from blockchain_fetch import run_blockchain_research


def main():
    ap = argparse.ArgumentParser(description="Generic on-chain fetch for any investigation (wallets + optional token)")
    ap.add_argument("--wallets", nargs="*", help="Solana wallet addresses")
    ap.add_argument("--token", default=None, help="Optional token mint address")
    ap.add_argument("--out", default=None, help="Output JSON path (default: investigation/blockchain_data.json)")
    ap.add_argument("--config", default=None, help="Path to JSON config: wallets, token?, output?")
    ap.add_argument("--quiet", action="store_true", help="Less output")
    args = ap.parse_args()

    wallets = []
    token_mint = None
    output_path = INV / "blockchain_data.json"

    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"Config not found: {cfg_path}", file=sys.stderr)
            return 1
        with open(cfg_path, encoding="utf-8") as f:
            cfg = json.load(f)
        wallets = cfg.get("wallets") or []
        token_mint = cfg.get("token")
        if cfg.get("output"):
            output_path = Path(cfg["output"])
    if args.wallets:
        wallets = args.wallets
    if args.token is not None:
        token_mint = args.token
    if args.out is not None:
        output_path = Path(args.out)

    if not wallets:
        print("No wallets given. Use --wallets ADDR1 ADDR2 ... or --config path.json", file=sys.stderr)
        return 1

    print("Fetching wallets (RPC + Helius + Arkham + FrontrunPro when keys set)...")
    run_blockchain_research(
        wallet_addresses=wallets,
        token_mint=token_mint,
        output_path=output_path,
        verbose=not args.quiet,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
