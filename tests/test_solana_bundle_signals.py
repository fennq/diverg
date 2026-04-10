"""Table-driven tests for CEX/mixer tier classifiers (no Helius network calls)."""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "investigation"))

import solana_bundle_signals as sbs  # noqa: E402
from bundle_intel_overrides import _empty_overrides  # noqa: E402


class TestClassifyCexTier(unittest.TestCase):
    def test_strong_structural_category(self) -> None:
        tier, reasons = sbs.classify_cex_tier({"category": "Centralized Exchange", "name": "Foo"})
        self.assertEqual(tier, "strong")
        self.assertTrue(any(r.startswith("struct:") for r in reasons))

    def test_strong_venue_in_label(self) -> None:
        tier, _ = sbs.classify_cex_tier(
            {"primary_label": "Binance Hot Wallet 7", "category": "Unknown", "tags": []}
        )
        self.assertEqual(tier, "strong")

    def test_weak_hot_wallet_only(self) -> None:
        tier, reasons = sbs.classify_cex_tier(
            {"primary_label": "Random LP", "tags": ["hot wallet"], "category": "Protocol"}
        )
        self.assertEqual(tier, "weak")
        self.assertIn("weak_custodial_language", reasons)

    def test_none_random_protocol(self) -> None:
        tier, _ = sbs.classify_cex_tier(
            {"primary_label": "Raydium Pool", "category": "DEX", "tags": ["amm"]}
        )
        self.assertEqual(tier, "none")

    def test_decentralized_exchange_not_strong_cex(self) -> None:
        tier, _ = sbs.classify_cex_tier(
            {"category": "Decentralized Exchange", "name": "Some DEX", "tags": []}
        )
        self.assertEqual(tier, "none")

    def test_type_dex_not_structural(self) -> None:
        tier, _ = sbs.classify_cex_tier({"type": "DEX", "name": "Router", "tags": []})
        self.assertEqual(tier, "none")

    def test_extra_venue_marker(self) -> None:
        tier, reasons = sbs.classify_cex_tier(
            {"primary_label": "Woo deposit node", "category": "Other", "tags": []},
            extra_venue_markers=("woo",),
        )
        self.assertEqual(tier, "strong")
        self.assertTrue(any(r.startswith("venue:") for r in reasons))

    def test_funder_override_denylist(self) -> None:
        ov = _empty_overrides()
        addr = "11111111111111111111111111111111"
        ov["wallet_cex_denylist"] = {addr}
        tier, r = sbs.classify_cex_tier_for_funder(addr, {"name": "Binance", "category": "CEX"}, ov)
        self.assertEqual(tier, "none")
        self.assertIn("override:wallet_cex_denylist", r)

    def test_funder_override_allowlist(self) -> None:
        ov = _empty_overrides()
        addr = "22222222222222222222222222222222"
        ov["wallet_cex_allowlist"] = {addr}
        tier, r = sbs.classify_cex_tier_for_funder(addr, None, ov)
        self.assertEqual(tier, "strong")
        self.assertIn("override:wallet_cex_allowlist", r)

    def test_withdrawn_not_weak_cex(self) -> None:
        """'withdraw' substring inside 'withdrawn' must not trigger weak tier."""
        tier, _ = sbs.classify_cex_tier(
            {"primary_label": "User withdrawn funds log", "category": "Other", "tags": []}
        )
        self.assertEqual(tier, "none")

    def test_is_cex_strict_env(self) -> None:
        weak_ident = {"tags": ["withdraw"], "category": "Other"}
        try:
            os.environ["SOLANA_BUNDLE_CEX_STRICT"] = "1"
            self.assertFalse(sbs.is_cex_identity(weak_ident))
            os.environ.pop("SOLANA_BUNDLE_CEX_STRICT", None)
            self.assertTrue(sbs.is_cex_identity(weak_ident))
        finally:
            os.environ.pop("SOLANA_BUNDLE_CEX_STRICT", None)


class TestClassifyMixerTier(unittest.TestCase):
    def test_strong_mixer_keyword(self) -> None:
        tier, _ = sbs.classify_mixer_tier({"name": "Tornado Cash Router", "category": "Mixer"})
        self.assertEqual(tier, "strong")

    def test_weak_privacy_pool_phrase(self) -> None:
        tier, _ = sbs.classify_mixer_tier({"name": "Acme privacy pool beta", "tags": []})
        self.assertEqual(tier, "strong")

    def test_dex_blocklist_privacy_cash(self) -> None:
        tier, _ = sbs.classify_mixer_tier(
            {"primary_label": "jupiter privacy cash vault", "tags": ["defi"]}
        )
        self.assertEqual(tier, "none")

    def test_weak_privacy_cash_no_dex(self) -> None:
        tier, reasons = sbs.classify_mixer_tier(
            {"name": "Offshore privacy cash router", "category": "Privacy"}
        )
        self.assertEqual(tier, "weak")
        self.assertIn("privacy_companion_weak", reasons)


class TestCorroborationModes(unittest.TestCase):
    def test_dual_requires_bucket_and_lamports(self) -> None:
        meta = {
            "a": {"first_fund_timestamp_unix": 10, "first_fund_lamports": 100},
            "b": {"first_fund_timestamp_unix": 12, "first_fund_lamports": 999},
        }
        corr = sbs.wallets_funding_corroborated(
            ["a", "b"], meta, bucket_sec=5.0, rel_tol=0.01, mode="dual", max_spread_sec=0.0
        )
        self.assertEqual(corr, set())

    def test_dual_match(self) -> None:
        meta = {
            "a": {"first_fund_timestamp_unix": 10, "first_fund_lamports": 1_000_000_000},
            "b": {"first_fund_timestamp_unix": 11, "first_fund_lamports": 1_000_000_000},
        }
        corr = sbs.wallets_funding_corroborated(
            ["a", "b"], meta, bucket_sec=5.0, rel_tol=0.002, mode="dual", max_spread_sec=0.0
        )
        self.assertEqual(corr, {"a", "b"})

    def test_spread_filters_bucket_pair(self) -> None:
        meta = {
            "a": {"first_fund_timestamp_unix": 100, "first_fund_lamports": 1},
            "b": {"first_fund_timestamp_unix": 500, "first_fund_lamports": 2},
        }
        corr = sbs.wallets_funding_corroborated(
            ["a", "b"], meta, bucket_sec=1000.0, rel_tol=0.5, mode="either", max_spread_sec=60.0
        )
        self.assertEqual(corr, set())


class TestStrictFromLoose(unittest.TestCase):
    def test_keeps_only_corroborated_wallets(self) -> None:
        loose = [
            {"funder": "F11111111111111111111111111111111111111111", "wallets": ["a", "b", "c"], "funder_tier": "strong"}
        ]
        meta = {
            "a": {"first_fund_timestamp_unix": 10, "first_fund_lamports": 100},
            "b": {"first_fund_timestamp_unix": 12, "first_fund_lamports": 100},
            "c": {"first_fund_timestamp_unix": 99999, "first_fund_lamports": 999},
        }
        strict = sbs._strict_from_loose(loose, meta, bucket_sec=5.0, rel_tol=0.002)
        self.assertEqual(len(strict), 1)
        self.assertEqual(set(strict[0]["wallets"]), {"a", "b"})
        self.assertEqual(strict[0]["confidence"], "high")


class TestFundingCorroboration(unittest.TestCase):
    def test_time_bucket_pair(self) -> None:
        meta = {
            "a": {"first_fund_timestamp_unix": 100, "first_fund_lamports": 1},
            "b": {"first_fund_timestamp_unix": 102, "first_fund_lamports": 9},
        }
        corr = sbs.wallets_funding_corroborated(["a", "b"], meta, bucket_sec=10.0, rel_tol=0.01)
        self.assertEqual(corr, {"a", "b"})

    def test_lamports_close_pair(self) -> None:
        meta = {
            "a": {"first_fund_timestamp_unix": None, "first_fund_lamports": 1_000_000_000},
            "b": {"first_fund_timestamp_unix": None, "first_fund_lamports": 1_000_000_001},
        }
        corr = sbs.wallets_funding_corroborated(["a", "b"], meta, bucket_sec=5.0, rel_tol=0.002)
        self.assertEqual(corr, {"a", "b"})


class TestRecallAndMeaningOutputs(unittest.TestCase):
    def test_detect_wash_flow_patterns_split_merge(self) -> None:
        flows = {
            "SRC": [
                {"from": "SRC", "to": "A1", "lamports": 100, "signature": "s1"},
                {"from": "SRC", "to": "A2", "lamports": 100, "signature": "s2"},
                {"from": "SRC", "to": "A3", "lamports": 100, "signature": "s3"},
            ],
            "A1": [{"from": "A1", "to": "DST", "lamports": 90, "signature": "s4"}],
            "A2": [{"from": "A2", "to": "DST", "lamports": 90, "signature": "s5"}],
            "A3": [{"from": "A3", "to": "DST", "lamports": 90, "signature": "s6"}],
        }
        chains = {"W1": ["W1", "SRC", "A1", "DST"], "W2": ["W2", "SRC", "A2", "DST"]}
        out = sbs.detect_wash_flow_patterns(flows, chains, bridge_programs={}, mixer_programs={})
        self.assertIn(out.get("confidence"), ("medium", "high"))
        self.assertTrue(out.get("split_merge_flows"))
        self.assertGreaterEqual(int(out.get("pattern_count") or 0), 1)

    def test_compute_coordination_bundle_emits_candidate_and_confidence(self) -> None:
        addr1 = "11111111111111111111111111111111"
        addr2 = "21111111111111111111111111111111"
        fund1 = "31111111111111111111111111111111"
        fund2 = "41111111111111111111111111111111"
        root1 = "51111111111111111111111111111111"
        root2 = "61111111111111111111111111111111"

        funded_by = {
            addr1: {"funder": fund1, "lamports": 1_000_000_000, "timestamp": 1700000000},
            addr2: {"funder": fund2, "lamports": 1_000_000_000, "timestamp": 1700000001},
        }

        transfer_payload = {"data": []}
        identity_none = {}

        def _enhanced(addr: str, limit: int = 25, token_accounts: str = "balanceChanged", type_filter=None):
            return [{"slot": 1, "tokenTransfers": [], "nativeTransfers": []}]

        with patch("solana_bundle_signals.helius_transfers", return_value=transfer_payload), \
            patch("solana_bundle_signals.helius_wallet_identity", return_value=identity_none), \
            patch("solana_bundle_signals.helius_enhanced_transactions", side_effect=_enhanced):
            out = sbs.compute_coordination_bundle(
                lookup_wallets=[addr1, addr2],
                funded_by=funded_by,
                owner_amount={addr1: 10.0, addr2: 12.0},
                mint="So11111111111111111111111111111111111111112",
                focus_wallets=[addr1, addr2],
                transfers_cache_preload={addr1: transfer_payload, addr2: transfer_payload},
                funder_root_by_wallet={addr1: root1, addr2: root2},
                funder_chain_by_wallet={addr1: [addr1, fund1, root1], addr2: [addr2, fund2, root2]},
            )

        self.assertIn("candidate_evidence", out)
        self.assertTrue(isinstance(out.get("candidate_evidence"), list))
        self.assertGreaterEqual(len(out.get("candidate_evidence") or []), 2)
        self.assertIn("confidence_model", out)
        cm = out.get("confidence_model") or {}
        self.assertIn(cm.get("tier"), ("low", "medium", "high"))
        self.assertIn("observed_signals", cm)
        self.assertIn("corroborated_signals", cm)
        self.assertIn("high_confidence_signals", cm)

    def test_authority_misuse_token2022_detects_core_controls(self) -> None:
        out = sbs.evaluate_authority_misuse(
            token_program_analysis={
                "token_standard": "token-2022",
                "authority_signals": [
                    "mint_authority_set",
                    "freeze_authority_set",
                    "permanent_delegate_set",
                ],
                "extensions": ["TransferFeeConfig", "PermanentDelegate", "DefaultAccountState"],
                "risk_flags": ["authority:mint_authority_set"],
            },
            token_supply_ui=1_000_000.0,
            top_holders=[
                {"wallet": "A", "pct_supply": 66.0},
                {"wallet": "B", "pct_supply": 10.0},
            ],
        )
        self.assertEqual(out.get("token_standard"), "token-2022")
        self.assertIn("mint_authority_set_with_circulating_supply", out.get("matched_signals") or [])
        self.assertIn(out.get("severity"), ("medium", "high"))
        self.assertTrue(out.get("findings"))


if __name__ == "__main__":
    unittest.main()
