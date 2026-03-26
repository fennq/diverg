#!/usr/bin/env python3
"""
Fetch on-chain data for the Synq investigation (8 wallets + 1 token).

This is one use of the generic blockchain pipeline. Same data sources:
- Solana RPC (public), Helius (HELIUS_API_KEY), Arkham (ARKHAM_API_KEY),
  FrontrunPro (FRONTRUNPRO_API_KEY + FRONTRUNPRO_BASE_URL — optional paid API;
  without it, use address_finder_url() for Twitter → wallet), Solscan.

Writes investigation/synq_data.json. Merge that JSON into the markdown report with:
  python scripts/update_investigation_report_from_data.py
For other investigations use:
  python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 [--token MINT] [--out path.json]
"""
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

# Synq case: 8 wallets + 1 token
WALLETS = [
    "6fMGqiSN23mbbQ18DJaHXfLYz5xs3fdQtiGVzpeQPfWQ",
    "UteVevXPVWM6NtohF87ysipmqdfeCDuAQXf5rTNkzyR",
    "AABBP7za3DqZwxbHh8jx7cwdpQHeSSdtDq81Uz3g96b8",
    "ETvz4wgkp98ip8vabLHmyEypU1urvoCK558vPUFfipq7",
    "By946UgiAUnq4KcJh15Z2fRKVz2ScvUQRj4nqPXHTc2w",
    "9uHphoGiwR3kvwAMr7SfCQWH5Pe3nADW19rjeeMh9pYM",
    "4LciDVUKQ8n9DC4F8qEt5bAgpPPhovQfG7RCPxoNbRSX",
    "8LvxZoN1b6rNV9wkmXaitteRpm1pLHskyNduj35ekAHz",
]
TOKEN_MINT = "3So5XbQpL9uxfFXvDSJpzeGFLo8K4NGddv2cBhRPpump"


def main():
    INV.mkdir(exist_ok=True)
    run_blockchain_research(
        wallet_addresses=WALLETS,
        token_mint=TOKEN_MINT,
        output_path=INV / "synq_data.json",
        verbose=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
