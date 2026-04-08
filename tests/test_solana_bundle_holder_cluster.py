"""Unit tests for holder cluster keys (direct funder) in solana_bundle."""
from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "investigation"))

from solana_bundle import holder_supply_cluster_key  # noqa: E402


H1 = "7DhqsvN4t9wP1uU7v7e7V5xv1qVv9v7v7v7v7v7v7v7"  # 43-char placeholder
H2 = "8EhrswO5uXwQ2uV8wU8wU8v8wU8v8wU8v8wU8v8wU8v8"  # 43-char placeholder
F_DIRECT = "DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy"
F_OTHER = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  # SPL token program id shape
ROOT_CEX = "Binance1HotWalletxxxxxxxxxxxxxxxxxxxxxxxxx"  # invalid base58 - for negative test


class TestHolderSupplyClusterKey(unittest.TestCase):
    def test_same_direct_not_same_terminal(self) -> None:
        """Holders A,B share a CEX root but different direct funders → separate clusters."""
        chain_a = [H1, F_DIRECT, "SomeCexHotWallet7zzzzzzzzzzzzzzzzzzzzzzzz"]
        chain_b = [H2, F_OTHER, "SomeCexHotWallet7zzzzzzzzzzzzzzzzzzzzzzzz"]
        self.assertNotEqual(holder_supply_cluster_key(H1, chain_a), holder_supply_cluster_key(H2, chain_b))
        self.assertEqual(holder_supply_cluster_key(H1, chain_a), f"funder:{F_DIRECT}")
        self.assertEqual(holder_supply_cluster_key(H2, chain_b), f"funder:{F_OTHER}")

    def test_shared_direct_clusters_together(self) -> None:
        chain1 = [H1, F_DIRECT, "UnusedRootzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]
        chain2 = [H2, F_DIRECT, "AnotherRootzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]
        self.assertEqual(holder_supply_cluster_key(H1, chain1), holder_supply_cluster_key(H2, chain2))

    def test_single_hop_singleton(self) -> None:
        self.assertEqual(holder_supply_cluster_key(H1, [H1]), f"singleton:{H1}")

    def test_invalid_direct_address_falls_back_singleton(self) -> None:
        chain = [H1, ROOT_CEX, "X"]
        self.assertEqual(holder_supply_cluster_key(H1, chain), f"singleton:{H1}")


if __name__ == "__main__":
    unittest.main()
