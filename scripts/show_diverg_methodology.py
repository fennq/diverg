#!/usr/bin/env python3
"""
Print the path to Diverg's blockchain investigation methodology.
The methodology is loaded into the bot at runtime; this script is for reference.

Usage:
  python scripts/show_diverg_methodology.py
"""

from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
METHODOLOGY_FILE = BASE / "content" / "diverg_blockchain_methodology.txt"


def main() -> None:
    print("Diverg blockchain methodology:", METHODOLOGY_FILE)
    if METHODOLOGY_FILE.exists():
        print("(file exists; loaded into bot system prompt at runtime)")
    else:
        print("(file not found)")


if __name__ == "__main__":
    main()
