from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "investigation"))

from benchmark_eval import Confusion, extract_confidence_features, passes_threshold, update_confusion


class TestBenchmarkEval(unittest.TestCase):
    def test_extract_confidence_features_defaults(self):
        out = extract_confidence_features({})
        self.assertEqual(out["tier"], "none")
        self.assertEqual(out["observed_count"], 0)
        self.assertEqual(out["corroborated_count"], 0)
        self.assertEqual(out["high_conf_count"], 0)

    def test_threshold_logic(self):
        f = {
            "tier": "medium",
            "observed_count": 2,
            "corroborated_count": 1,
            "high_conf_count": 0,
        }
        self.assertTrue(passes_threshold(f, "observed"))
        self.assertTrue(passes_threshold(f, "corroborated"))
        self.assertFalse(passes_threshold(f, "high_confidence"))

    def test_confusion_metrics(self):
        c = Confusion()
        update_confusion(c, expected_positive=True, predicted_positive=True)   # tp
        update_confusion(c, expected_positive=False, predicted_positive=True)  # fp
        update_confusion(c, expected_positive=True, predicted_positive=False)  # fn
        update_confusion(c, expected_positive=False, predicted_positive=False) # tn
        d = c.as_dict()
        self.assertEqual(d["tp"], 1)
        self.assertEqual(d["fp"], 1)
        self.assertEqual(d["fn"], 1)
        self.assertEqual(d["tn"], 1)
        self.assertAlmostEqual(d["precision"], 0.5, places=6)
        self.assertAlmostEqual(d["recall"], 0.5, places=6)


if __name__ == "__main__":
    unittest.main()

