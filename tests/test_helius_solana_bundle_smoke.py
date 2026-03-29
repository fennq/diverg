"""
Optional live Helius smoke test. Skipped in CI unless HELIUS_API_KEY is set.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless((os.environ.get("HELIUS_API_KEY") or "").strip(), "HELIUS_API_KEY not set")
class TestHeliusSolanaBundleSmoke(unittest.TestCase):
    def test_run_bundle_snapshot_wsol_small_sample(self):
        sys.path.insert(0, str(_ROOT))
        sys.path.insert(0, str(_ROOT / "investigation"))
        from solana_bundle import run_bundle_snapshot

        out = run_bundle_snapshot(
            "So11111111111111111111111111111111111111112",
            max_holders=8,
            max_funded_by_lookups=8,
        )
        self.assertTrue(out.get("ok"), msg=out.get("error"))
        self.assertIn("bundle_signals", out)
        self.assertIn("cross_chain", out)
        cc = out.get("cross_chain") or {}
        self.assertIn("summary", cc)
        self.assertEqual(cc["summary"].get("kind"), "solana_bundle")


if __name__ == "__main__":
    unittest.main()
