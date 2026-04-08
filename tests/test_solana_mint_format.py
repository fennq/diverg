"""Solana mint string validation (watchlist + bundle API)."""
from __future__ import annotations

import re
import unittest

_SOLANA_MINT_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _is_plausible_solana_mint(m: str) -> bool:
    s = (m or "").strip()
    return bool(s and _SOLANA_MINT_BASE58_RE.match(s))


class TestSolanaMintFormat(unittest.TestCase):
    def test_valid_length_and_charset(self):
        # 44-char style mint (illustrative pattern)
        self.assertTrue(_is_plausible_solana_mint("So11111111111111111111111111111111111111112"))
        self.assertTrue(_is_plausible_solana_mint("  So11111111111111111111111111111111111111112  "))

    def test_rejects_short_and_invalid_chars(self):
        self.assertFalse(_is_plausible_solana_mint(""))
        self.assertFalse(_is_plausible_solana_mint("short"))
        self.assertFalse(_is_plausible_solana_mint("0" + "1" * 43))  # 0 excluded from base58 set
        self.assertFalse(_is_plausible_solana_mint("I" + "1" * 43))  # I excluded
        self.assertFalse(_is_plausible_solana_mint("l" + "1" * 43))  # l excluded


if __name__ == "__main__":
    unittest.main()
