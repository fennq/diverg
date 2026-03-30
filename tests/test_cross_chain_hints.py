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
            self.assertEqual(eth.get("confidence_tier"), "high")

    def test_summarize_cross_chain_payload(self):
        from cross_chain_hints import summarize_cross_chain_payload

        bundle = {
            "mint": "M1",
            "candidates": [
                {"foreign_chain": "ethereum", "foreign_address": "0xaa", "foreign_explorer_url": "https://etherscan.io/token/0xaa", "confidence_tier": "high"},
            ],
            "sources": ["wormhole_token_list"],
        }
        s1 = summarize_cross_chain_payload(bundle)
        self.assertEqual(s1["kind"], "solana_bundle")
        self.assertEqual(s1["candidate_count"], 1)
        self.assertTrue(s1["has_high_tier"])
        self.assertEqual(len(s1["explorer_links"]), 1)

        inv = {
            "lookups": [bundle],
            "note": "n",
        }
        s2 = summarize_cross_chain_payload(inv)
        self.assertEqual(s2["kind"], "investigation_report")
        self.assertEqual(s2["lookup_count"], 1)
        self.assertEqual(s2["candidate_count"], 1)

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
        self.assertEqual(out.get("bridge_signal_scope"), "all_sampled_wallets")
        self.assertIn(out.get("bridge_mixer_confidence_tier"), ("high", "medium", "low"))

    def test_funding_cluster_bridge_mixer_focus_scope(self):
        from solana_bundle_signals import build_funding_cluster_bridge_mixer

        worm = "wormDTUJ6BPNq26feREzEhE3dxARYxkSG6AQUvU4C"
        program_sets = {
            "W1": {worm},
            "W2": {worm},
        }
        out_all = build_funding_cluster_bridge_mixer(
            program_sets=program_sets,
            lookup_wallets=["W1", "W2"],
            privacy_mixer_funding_strict=[],
            funder_mixer_flags={},
        )
        out_focus = build_funding_cluster_bridge_mixer(
            program_sets=program_sets,
            lookup_wallets=["W1", "W2"],
            privacy_mixer_funding_strict=[],
            funder_mixer_flags={},
            bridge_count_eligible_wallets=["W1"],
        )
        self.assertGreaterEqual(out_all["bridge_adjacent_wallet_count"], out_focus["bridge_adjacent_wallet_count"])
        self.assertEqual(out_focus["bridge_adjacent_wallet_count"], 1)
        self.assertEqual(out_focus.get("bridge_signal_scope"), "focus_cluster")

    def test_funding_cluster_funder_bridge_path(self):
        from solana_bundle_signals import build_funding_cluster_bridge_mixer

        worm = "wormDTUJ6BPNq26feREzEhE3dxARYxkSG6AQUvU4C"
        funder = "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy"
        program_sets = {"W1": set(), "W2": set()}
        meta = {"W1": {"funder": funder}, "W2": {"funder": funder}}
        root_map: dict = {"W1": None, "W2": None}
        funder_program_sets = {funder: {worm}}
        out = build_funding_cluster_bridge_mixer(
            program_sets=program_sets,
            lookup_wallets=["W1", "W2"],
            privacy_mixer_funding_strict=[],
            funder_mixer_flags={},
            funder_program_sets=funder_program_sets,
            meta_by_wallet=meta,
            root_map=root_map,
        )
        self.assertGreaterEqual(out.get("wallets_with_bridge_touching_funder", 0), 2)
        self.assertGreaterEqual(out.get("bridge_program_funder_count", 0), 1)
        self.assertTrue(out.get("funder_bridge_hits"))

    def test_cross_chain_bundle_intel_merge(self):
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        cc = {
            "summary": {
                "candidate_count": 1,
                "explorer_links": [{"chain": "ethereum", "url": "https://etherscan.io/token/0xaa", "tier": "high"}],
                "sources": ["wormhole_token_list"],
            }
        }
        fc = {
            "bridge_adjacent_wallet_count": 2,
            "bridge_mixer_confidence_tier": "high",
            "shared_bridge_programs_multi_wallet": [{"program_id": "x", "wallet_count": 2}],
            "strict_mixer_cluster_max_wallets": 0,
            "any_mixer_tagged_funder": False,
            "bridge_program_funder_count": 0,
            "wallets_with_bridge_touching_funder": 0,
            "funder_bridge_hits": [],
        }
        out = build_cross_chain_bundle_intel(
            mint="So11111111111111111111111111111111111111112",
            cross_chain=cc,
            funding_cluster_bridge_mixer=fc,
        )
        self.assertTrue(out["has_foreign_token_candidates"])
        self.assertGreater(len(out["investigator_notes"]), 0)
        self.assertIn("foreign_explorer_links", out)


if __name__ == "__main__":
    unittest.main()
