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

    def test_funding_cluster_cex_split_pattern(self):
        from solana_bundle_signals import build_funding_cluster_bridge_mixer

        wallets = ["W1", "W2", "W3"]
        meta = {
            "W1": {"funder": "F1"},
            "W2": {"funder": "F2"},
            "W3": {"funder": "F3"},
        }
        tier = {"F1": "strong", "F2": "strong", "F3": "strong"}
        shared_out = {
            "shared_receiver_to_wallets": {
                "R1": ["W1", "W2"],
                "R2": ["W2", "W3"],
            }
        }
        transfers = {
            "W1": [{"direction": "out", "to": "R1"}, {"direction": "out", "to": "R3"}, {"direction": "out", "to": "R4"}],
            "W2": [{"direction": "out", "to": "R1"}, {"direction": "out", "to": "R2"}, {"direction": "out", "to": "R5"}],
            "W3": [{"direction": "out", "to": "R2"}, {"direction": "out", "to": "R6"}, {"direction": "out", "to": "R7"}],
        }
        out = build_funding_cluster_bridge_mixer(
            program_sets={w: set() for w in wallets},
            lookup_wallets=wallets,
            privacy_mixer_funding_strict=[],
            funder_mixer_flags={},
            meta_by_wallet=meta,
            root_map={w: None for w in wallets},
            funder_cex_tier=tier,
            shared_outbound=shared_out,
            transfers_cache=transfers,
        )
        self.assertIn(out.get("cex_split_pattern_confidence"), ("medium", "high"))
        self.assertGreaterEqual(int(out.get("cex_split_wallet_count") or 0), 3)
        self.assertGreaterEqual(int(out.get("cex_split_shared_receiver_count") or 0), 1)

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

    def test_cross_chain_bundle_intel_with_bridge_transfers(self):
        """bridge_transfers param populates counterparty_evm_addresses and notes."""
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        bridge_transfers = {
            "FunderWallet1111111111111111111111111111111": [
                {
                    "vaa_id": "1/abc/1",
                    "source_chain": "solana",
                    "source_address": "FunderWallet1111111111111111111111111111111",
                    "dest_chain": "ethereum",
                    "dest_address": "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4",
                    "amount": "10.0",
                    "token_symbol": "WETH",
                    "timestamp_unix": 1700000000,
                    "source_tx_hash": "tx1",
                    "explorer_url": "https://etherscan.io/address/0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4",
                }
            ],
        }
        fc = {
            "bridge_adjacent_wallet_count": 1,
            "bridge_mixer_confidence_tier": "medium",
            "shared_bridge_programs_multi_wallet": [],
            "strict_mixer_cluster_max_wallets": 2,
            "any_mixer_tagged_funder": True,
            "wallets_with_mixer_touching_funder": 1,
            "mixer_service_funder_count": 1,
            "mixer_path_hits": [{"wallet": "W1", "via": "direct", "funder_address": "F1", "tier": "strong"}],
            "bridge_program_funder_count": 1,
            "wallets_with_bridge_touching_funder": 1,
            "funder_bridge_hits": [],
        }
        out = build_cross_chain_bundle_intel(
            mint="So11111111111111111111111111111111111111112",
            cross_chain=None,
            funding_cluster_bridge_mixer=fc,
            bridge_transfers=bridge_transfers,
        )
        self.assertIn("counterparty_evm_addresses", out)
        self.assertEqual(len(out["counterparty_evm_addresses"]), 1)
        self.assertEqual(out["counterparty_evm_addresses"][0], "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4")
        # Should have bridge-transfer note
        notes_joined = " ".join(out["investigator_notes"])
        self.assertIn("Bridge transfers found", notes_joined)
        # combined_escalation should be True (bridge transfer + bridge/mixer signals)
        self.assertTrue(out["combined_escalation"])
        # bridge_transfers_by_wallet should be trimmed
        self.assertIn("FunderWallet1111111111111111111111111111111", out["bridge_transfers_by_wallet"])
        # mixer path fields should be present and numeric
        self.assertIn("wallets_with_mixer_touching_funder", out)
        self.assertIsInstance(out["wallets_with_mixer_touching_funder"], int)

    def test_cross_chain_bundle_intel_mixer_path_fields(self):
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        fc = {
            "bridge_adjacent_wallet_count": 0,
            "bridge_mixer_confidence_tier": "medium",
            "shared_bridge_programs_multi_wallet": [],
            "strict_mixer_cluster_max_wallets": 1,
            "any_mixer_tagged_funder": False,
            "bridge_program_funder_count": 0,
            "wallets_with_bridge_touching_funder": 0,
            "wallets_with_mixer_touching_funder": 2,
            "mixer_service_funder_count": 1,
            "mixer_path_hits": [
                {"wallet": "W1", "via": "direct", "funder_address": "F1", "tier": "strong"},
                {"wallet": "W2", "via": "root", "funder_address": "F1", "tier": "strong"},
            ],
            "funder_bridge_hits": [],
        }
        out = build_cross_chain_bundle_intel(
            mint="So11111111111111111111111111111111111111112",
            cross_chain=None,
            funding_cluster_bridge_mixer=fc,
        )
        self.assertEqual(out["wallets_with_mixer_touching_funder"], 2)
        self.assertEqual(out["mixer_service_funder_count"], 1)
        self.assertEqual(len(out["mixer_path_hits"]), 2)
        # Notes should mention mixer/privacy path context when path-level count is present
        notes_joined = " ".join(out["investigator_notes"]).lower()
        self.assertTrue("mixer" in notes_joined or "privacy" in notes_joined)

    def test_cross_chain_bundle_intel_cex_split_fields_basic(self):
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        fc = {
            "bridge_adjacent_wallet_count": 2,
            "bridge_mixer_confidence_tier": "medium",
            "shared_bridge_programs_multi_wallet": [],
            "strict_mixer_cluster_max_wallets": 0,
            "any_mixer_tagged_funder": False,
            "bridge_program_funder_count": 1,
            "wallets_with_bridge_touching_funder": 1,
            "cex_split_pattern_confidence": "high",
            "cex_split_wallet_count": 3,
            "cex_split_shared_receiver_count": 1,
            "cex_split_fanout_avg": 3.0,
            "funder_bridge_hits": [],
        }
        out = build_cross_chain_bundle_intel(
            mint="So11111111111111111111111111111111111111112",
            cross_chain={"summary": {"candidate_count": 1, "explorer_links": [], "sources": []}},
            funding_cluster_bridge_mixer=fc,
            bridge_transfers=None,
        )
        self.assertEqual(out.get("cex_split_pattern_confidence"), "high")
        self.assertEqual(out.get("cex_split_wallet_count"), 3)
        self.assertTrue(out.get("combined_escalation"))
        notes = " ".join(out.get("investigator_notes") or []).lower()
        self.assertIn("cex-routed split pattern", notes)

    def test_cross_chain_bundle_intel_cex_split_fields_with_hits(self):
        from cross_chain_bundle_intel import build_cross_chain_bundle_intel

        fc = {
            "bridge_adjacent_wallet_count": 2,
            "bridge_mixer_confidence_tier": "medium",
            "shared_bridge_programs_multi_wallet": [{"program_id": "x", "wallet_count": 2}],
            "strict_mixer_cluster_max_wallets": 0,
            "any_mixer_tagged_funder": False,
            "bridge_program_funder_count": 1,
            "wallets_with_bridge_touching_funder": 2,
            "wallets_with_mixer_touching_funder": 0,
            "mixer_service_funder_count": 0,
            "mixer_path_hits": [],
            "funder_bridge_hits": [],
            "cex_split_pattern_confidence": "high",
            "cex_split_wallet_count": 3,
            "cex_split_shared_receiver_count": 2,
            "cex_split_fanout_avg": 3.1,
            "cex_split_path_hits": [{"wallet": "W1", "tier": "strong"}],
            "cex_split_shared_receiver_hits": [{"receiver": "R1", "wallet_count": 2}],
        }
        out = build_cross_chain_bundle_intel(
            mint="So11111111111111111111111111111111111111112",
            cross_chain={"summary": {"candidate_count": 1, "explorer_links": []}},
            funding_cluster_bridge_mixer=fc,
            bridge_transfers={},
        )
        self.assertEqual(out.get("cex_split_pattern_confidence"), "high")
        self.assertEqual(out.get("cex_split_wallet_count"), 3)
        notes_joined = " ".join(out.get("investigator_notes") or []).lower()
        self.assertIn("cex-routed split pattern", notes_joined)
        self.assertTrue(out.get("combined_escalation"))


class TestWormholeScanClient(unittest.TestCase):
    """Unit tests for wormhole_scan_client using mocked HTTP."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "investigation"))

    def test_normalise_operation_extracts_fields(self):
        from wormhole_scan_client import _normalise_operation

        raw = {
            "id": "1/emitter/42",
            "emitterChain": 1,
            "content": {
                "payload": {"toChain": 2},
                "standarizedProperties": {
                    "fromChain": 1,
                    "fromAddress": "7dm9am6Qx7cH64RB99Mzf7ZsLbEfmXM7ihXXCvMiT2X1",
                    "toChain": 2,
                    "toAddress": "0x000000000000000000000000bf5f3f65102ae745a48bd521d10bab5bf02a9ef4",
                },
            },
            "sourceChain": {
                "timestamp": "2025-01-01T00:00:00Z",
                "transaction": {"txHash": "abc123"},
                "from": "7dm9am6Qx7cH64RB99Mzf7ZsLbEfmXM7ihXXCvMiT2X1",
            },
            "data": {"symbol": "WETH", "tokenAmount": "1.0", "usdAmount": "2500.0"},
        }
        out = _normalise_operation(raw)
        self.assertIsNotNone(out)
        self.assertEqual(out["vaa_id"], "1/emitter/42")
        self.assertEqual(out["source_chain"], "solana")
        self.assertEqual(out["dest_chain"], "ethereum")
        self.assertEqual(out["dest_address"], "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4")
        self.assertEqual(out["token_symbol"], "WETH")
        self.assertIsNotNone(out["timestamp_unix"])

    def test_normalise_drops_empty(self):
        from wormhole_scan_client import _normalise_operation

        self.assertIsNone(_normalise_operation({}))
        self.assertIsNone(_normalise_operation({"content": {}}))

    def test_extract_counterparty_evm_addresses(self):
        from wormhole_scan_client import extract_counterparty_evm_addresses

        transfers = {
            "wallet1": [
                {"dest_address": "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4", "dest_chain": "ethereum"},
                {"dest_address": "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4", "dest_chain": "ethereum"},
            ],
            "wallet2": [
                {"dest_address": "0x6b175474e89094c44da98b954eedeac495271d0f", "dest_chain": "ethereum"},
                {"dest_address": "not-an-evm-addr", "dest_chain": "solana"},
            ],
        }
        result = extract_counterparty_evm_addresses(transfers)
        self.assertEqual(len(result), 2)
        self.assertIn("0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4", result)
        self.assertIn("0x6b175474e89094c44da98b954eedeac495271d0f", result)

    def test_extract_counterparty_solana_addresses(self):
        from wormhole_scan_client import extract_counterparty_solana_addresses

        transfers = {
            "wallet1": [
                {
                    "source_address": "7dm9am6Qx7cH64RB99Mzf7ZsLbEfmXM7ihXXCvMiT2X1",
                    "dest_address": "8LwX9t5C5a4bE4Pr4W9w5gw24R3f7F1C4nWYkQwP6V7N",
                }
            ],
            "wallet2": [{"dest_address": "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4"}],
        }
        out = extract_counterparty_solana_addresses(transfers)
        self.assertIn("7dm9am6Qx7cH64RB99Mzf7ZsLbEfmXM7ihXXCvMiT2X1", out)
        self.assertIn("8LwX9t5C5a4bE4Pr4W9w5gw24R3f7F1C4nWYkQwP6V7N", out)

    def test_fetch_bridge_operations_mocked(self):
        from unittest.mock import MagicMock, patch

        sample_response = json.dumps({
            "operations": [
                {
                    "id": "1/emitter/1",
                    "emitterChain": 1,
                    "content": {
                        "standarizedProperties": {
                            "fromChain": 1,
                            "fromAddress": "SolanaWallet111111111111111111111111111111",
                            "toChain": 2,
                            "toAddress": "0x000000000000000000000000bf5f3f65102ae745a48bd521d10bab5bf02a9ef4",
                        }
                    },
                    "sourceChain": {
                        "timestamp": "2025-06-01T12:00:00Z",
                        "transaction": {"txHash": "abc"},
                    },
                    "data": {"symbol": "SOL", "tokenAmount": "5.0"},
                }
            ]
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = sample_response
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            from wormhole_scan_client import fetch_bridge_operations
            ops = fetch_bridge_operations("SolanaWallet111111111111111111111111111111", use_cache=False)

        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["dest_chain"], "ethereum")
        self.assertEqual(ops[0]["dest_address"], "0xbf5f3f65102ae745a48bd521d10bab5bf02a9ef4")

    def test_resolve_counterparties_respects_max(self):
        """When SOLANA_BUNDLE_WORMHOLE_SCAN_MAX=0, returns empty dict without network call."""
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"SOLANA_BUNDLE_WORMHOLE_SCAN_MAX": "0"}):
            from wormhole_scan_client import resolve_counterparties
            result = resolve_counterparties(["addr1", "addr2"])
        self.assertEqual(result, {})

    def test_bridge_allowlist_expanded(self):
        """bridge_programs_solana.json now includes Mayan Swift and LayerZero v2."""
        from solana_bundle_signals import load_bridge_program_allowlist

        m = load_bridge_program_allowlist()
        self.assertIn("BLZRi6frs4X4DNLw56V4EXai1b6QVESN1BhHBTYM9VcY", m, "Mayan Swift should be in allowlist")
        self.assertIn("76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6", m, "LayerZero v2 endpoint should be in allowlist")


class TestMixerIntel(unittest.TestCase):
    def test_default_mixer_markers_loaded(self):
        from bundle_intel_overrides import load_bundle_intel_overrides

        ov = load_bundle_intel_overrides()
        markers = tuple(ov.get("mixer_extra_label_markers") or ())
        # strict policy excludes unverified candidates by default
        self.assertNotIn("splitnow", markers)
        self.assertTrue(any("tornado" in m for m in markers))
        self.assertIsInstance(ov.get("wallet_mixer_allowlist"), set)

    def test_bundle_overrides_tier_filtering(self):
        import tempfile
        import bundle_intel_overrides as bio

        payload = {
            "label_markers": [
                {"marker": "candidate-mixer", "tier": "unverified_candidate"},
                {"marker": "verified-mixer", "tier": "verified_analytics"},
            ],
            "solana_wallets": {
                "Svc": [
                    {"address": "So11111111111111111111111111111111111111112", "tier": "verified_analytics"},
                    {"address": "9fN9x5f4dnm3DU4D7jY2R2wYjvATNQv4VxQbATqj8v9n", "tier": "unverified_candidate"},
                ]
            },
        }
        old_file = bio._MIXER_INTEL_FILE
        with tempfile.TemporaryDirectory() as td:
            fp = Path(td) / "mixer_intel_test.json"
            fp.write_text(json.dumps(payload), encoding="utf-8")
            try:
                bio._MIXER_INTEL_FILE = fp
                with patch.dict("os.environ", {"DIVERG_MIXER_MIN_TIER": "verified_analytics"}, clear=False):
                    ov = bio.load_bundle_intel_overrides()
                self.assertIn("verified-mixer", tuple(ov.get("mixer_extra_label_markers") or ()))
                self.assertNotIn("candidate-mixer", tuple(ov.get("mixer_extra_label_markers") or ()))
                allow = ov.get("wallet_mixer_allowlist") or set()
                self.assertIn("So11111111111111111111111111111111111111112", allow)
                self.assertNotIn("9fN9x5f4dnm3DU4D7jY2R2wYjvATNQv4VxQbATqj8v9n", allow)
            finally:
                bio._MIXER_INTEL_FILE = old_file

    def test_evm_detect_mixer_hits(self):
        # Import from skills module path
        sys.path.insert(0, str(_ROOT))
        from skills.blockchain_investigation import _evm_detect_mixer_hits, _summarize_service_hits

        txs = [
            {"hash": "0xabc", "to": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", "timeStamp": "1710000000", "value": "1"},
            {"hash": "0xghi", "from": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", "timeStamp": "1710000002", "value": "2"},
            {"hash": "0xdef", "to": "0x000000000000000000000000000000000000dead", "timeStamp": "1710000001", "value": "0"},
        ]
        hits = _evm_detect_mixer_hits(txs, "ethereum")
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["tx_hash"], "0xabc")
        self.assertIn("Tornado", hits[0]["service"])
        self.assertIn(hits[0]["direction"], ("incoming", "outgoing"))
        self.assertEqual(hits[1]["tx_hash"], "0xghi")
        self.assertEqual(hits[1]["direction"], "incoming")

        summary = _summarize_service_hits(hits)
        self.assertTrue(summary)
        self.assertGreaterEqual(summary[0]["count"], 2)

    def test_evm_detect_mixer_wallet_hits(self):
        sys.path.insert(0, str(_ROOT))
        import skills.blockchain_investigation as bi

        backup = dict(bi.KNOWN_MIXER_EVM_WALLETS)
        try:
            bi.KNOWN_MIXER_EVM_WALLETS["0x000000000000000000000000000000000000beef"] = "SplitNOW Wallet"
            txs = [
                {"hash": "0x111", "to": "0x000000000000000000000000000000000000beef", "timeStamp": "1710000010", "value": "1"},
                {"hash": "0x222", "from": "0x000000000000000000000000000000000000beef", "timeStamp": "1710000011", "value": "2"},
            ]
            hits = bi._evm_detect_mixer_hits(txs, "ethereum")
            self.assertEqual(len(hits), 2)
            self.assertEqual(hits[0]["service"], "SplitNOW Wallet")
            dirs = sorted([h["direction"] for h in hits])
            self.assertEqual(dirs, ["incoming", "outgoing"])
        finally:
            bi.KNOWN_MIXER_EVM_WALLETS.clear()
            bi.KNOWN_MIXER_EVM_WALLETS.update(backup)

    def test_blockchain_loader_tier_filtering(self):
        import tempfile
        import skills.blockchain_investigation as bi

        payload = {
            "evm_contracts": {
                "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
                    "service": "Verified Contract",
                    "tier": "verified_primary",
                },
                "0x000000000000000000000000000000000000dEaD": {
                    "service": "Candidate Contract",
                    "tier": "unverified_candidate",
                },
            },
            "evm_wallets": {
                "Svc": [
                    {"address": "0x1111111111111111111111111111111111111111", "tier": "verified_analytics"},
                    {"address": "0x2222222222222222222222222222222222222222", "tier": "unverified_candidate"},
                ]
            },
            "label_markers": [
                {"marker": "verified-marker", "tier": "verified_analytics"},
                {"marker": "candidate-marker", "tier": "unverified_candidate"},
            ],
        }
        old_file = bi._MIXER_INTEL_FILE
        with tempfile.TemporaryDirectory() as td:
            fp = Path(td) / "mixer_intel_test.json"
            fp.write_text(json.dumps(payload), encoding="utf-8")
            try:
                bi._MIXER_INTEL_FILE = fp
                with patch.dict("os.environ", {"DIVERG_MIXER_MIN_TIER": "verified_analytics"}, clear=False):
                    contracts, wallets, markers = bi._load_mixer_intel()
                self.assertIn("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", contracts)
                self.assertNotIn("0x000000000000000000000000000000000000dead", contracts)
                self.assertIn("0x1111111111111111111111111111111111111111", wallets)
                self.assertNotIn("0x2222222222222222222222222222222222222222", wallets)
                self.assertIn("verified-marker", markers)
                self.assertNotIn("candidate-marker", markers)
            finally:
                bi._MIXER_INTEL_FILE = old_file

    def test_build_cex_split_pattern_high(self):
        from solana_bundle_signals import build_cex_split_pattern

        out = build_cex_split_pattern(
            lookup_wallets=["W1", "W2", "W3"],
            meta_by_wallet={
                "W1": {"funder": "F1", "first_fund_lamports": 1000, "first_fund_timestamp_unix": 1700000000},
                "W2": {"funder": "F1", "first_fund_lamports": 1000, "first_fund_timestamp_unix": 1700000001},
                "W3": {"funder": "F1", "first_fund_lamports": 900, "first_fund_timestamp_unix": 1700000002},
            },
            root_map={"W1": None, "W2": None, "W3": None},
            funder_cex_tier={"F1": "strong"},
            shared_outbound={"shared_receiver_to_wallets": {"R1": ["W1", "W2"]}},
            eligible_wallets=["W1", "W2", "W3"],
            bucket_sec=5.0,
        )
        self.assertEqual(out.get("confidence_tier"), "high")
        self.assertEqual(out.get("cex_path_wallet_count"), 3)
        self.assertTrue(out.get("shared_cex_funder_groups"))


if __name__ == "__main__":
    unittest.main()
