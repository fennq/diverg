"""Unit tests for cross_chain_hints (no live network when wormhole fetch skipped)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "investigation"))

FIX = Path(__file__).resolve().parent / "fixtures" / "wormhole_tokens_min.json"
FIX_CSV = Path(__file__).resolve().parent / "fixtures" / "wormhole_by_source_min.csv"

class TestCrossChainHints(unittest.TestCase):
    def test_wormhole_csv_golden_fixture(self):
        from cross_chain_hints import _wormhole_csv_to_rows

        raw = FIX_CSV.read_bytes()
        rows = _wormhole_csv_to_rows(raw)
        self.assertEqual(len(rows), 1)
        pl = rows[0]["platforms"]
        self.assertEqual(pl["solana"], "So11111111111111111111111111111111111111112")
        self.assertEqual(pl["ethereum"], "0xdac17f958d2ee523a2206206994597c13d831ec7")

    def test_foreign_explorer_url_solana_and_evm(self):
        from cross_chain_hints import _foreign_explorer_url

        u = _foreign_explorer_url("ethereum", "0xdac17f958d2ee523a2206206994597c13d831ec7")
        self.assertEqual(u, "https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7")
        u2 = _foreign_explorer_url("binance-smart-chain", "0xabc0000000000000000000000000000000000001")
        self.assertTrue(u2.startswith("https://bscscan.com/token/"))
        u3 = _foreign_explorer_url("solana", "So11111121111111111111111111111111111111112")
        self.assertEqual(u3, "https://solscan.io/token/So11111121111111111111111111111111111111112")

    def test_lookup_from_fixture_rows(self):
        from cross_chain_hints import lookup_from_wormhole_list

        rows = json.loads(FIX.read_text(encoding="utf-8"))
        with patch("cross_chain_hints.fetch_wormhole_token_rows", return_value=rows):
            sol = "So11111111111111111111111111111111111111112"
            hits = lookup_from_wormhole_list(sol_mint=sol, evm_chain=None, evm_address=None)
            self.assertTrue(any(h.get("foreign_chain") == "ethereum" for h in hits))
            eth = next(h for h in hits if h.get("foreign_chain") == "ethereum")
            self.assertIn("foreign_explorer_url", eth)
            self.assertIn("etherscan.io/token/", eth["foreign_explorer_url"])

    def test_bridge_allowlist_loads(self):
        from solana_bundle_signals import load_bridge_program_allowlist

        m = load_bridge_program_allowlist()
        self.assertIn("wormDTUJ6BPNq26feREzEhE3dxARYxkSG6AQUvU4C", m)

    def test_funding_cluster_bridge_mixer(self):
        from solana_bundle_signals import build_funding_cluster_bridge_mixer

        worm = "wormDTUJ6BPNq26feREzEhE3dxARYxkSG6AQUvU4C"
        program_sets = {
            "W1": {worm, "Other1111111111111111111111111111111111"},
            "W2": {worm},
        }
        out = build_funding_cluster_bridge_mixer(
            program_sets=program_sets,
            lookup_wallets=["W1", "W2"],
            privacy_mixer_funding_strict=[{"wallet_count": 3}],
            funder_mixer_flags={"X": True},
        )
        self.assertGreaterEqual(out["bridge_adjacent_wallet_count"], 1)
        self.assertTrue(out["shared_bridge_programs_multi_wallet"])


if __name__ == "__main__":
    unittest.main()
