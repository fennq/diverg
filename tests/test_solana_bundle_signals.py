"""Table-driven tests for CEX/mixer tier classifiers (no Helius network calls)."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "investigation"))

import solana_bundle_signals as sbs  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
