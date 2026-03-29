"""Unit tests for scripts/scan_diff.py (console + file report diffing)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))


class TestScanDiff(unittest.TestCase):
    def test_diff_findings_new_fixed_changed(self):
        import scan_diff as sd

        old = [
            {"title": "A", "url": "https://x.com/a", "category": "c1", "severity": "High"},
            {"title": "B", "url": "https://x.com/b", "category": "c2", "severity": "Medium"},
        ]
        new = [
            {"title": "A", "url": "https://x.com/a", "category": "c1", "severity": "Critical"},
            {"title": "C", "url": "https://x.com/c", "category": "c3", "severity": "Low"},
        ]
        d = sd.diff_findings(old, new)
        self.assertEqual(len(d["new"]), 1)
        self.assertEqual(d["new"][0]["title"], "C")
        self.assertEqual(len(d["fixed"]), 1)
        self.assertEqual(d["fixed"][0]["title"], "B")
        self.assertEqual(len(d["changed"]), 1)
        self.assertEqual(d["changed"][0]["old_severity"], "High")
        self.assertEqual(d["changed"][0]["new_severity"], "Critical")

    def test_friendly_ts_portable(self):
        import scan_diff as sd

        s = sd._friendly_ts("2026-01-15T14:30:00+00:00")
        self.assertIn("Jan", s)
        self.assertIn("15", s)
        self.assertIn("2026", s)
        self.assertIn("14:30", s)

    def test_format_output_no_changes(self):
        import scan_diff as sd

        f = {"title": "Same", "url": "https://t.com/", "category": "x", "severity": "Info"}
        diff = sd.diff_findings([f], [f])
        out = sd.format_output(
            diff, "old", "new",
            {"timestamp": "2026-01-01T00:00:00Z", "target_url": "https://t.com", "findings": [f]},
            {"timestamp": "2026-01-02T00:00:00Z", "target_url": "https://t.com", "findings": [f]},
        )
        self.assertIn("No changes detected", out)

    def test_format_markdown_no_changes(self):
        import scan_diff as sd

        f = {"title": "Same", "url": "https://t.com/", "category": "x", "severity": "Info"}
        diff = sd.diff_findings([f], [f])
        md = sd.format_markdown(
            diff, "old", "new",
            {"timestamp": "2026-01-01T00:00:00Z", "target_url": "https://t.com", "findings": [f]},
            {"timestamp": "2026-01-02T00:00:00Z", "target_url": "https://t.com", "findings": [f]},
        )
        self.assertIn("No changes detected", md)
        self.assertIn("# Scan Diff:", md)

    def test_cli_two_json_files(self):
        import scan_diff as sd

        old = {"target_url": "https://example.com", "scanned_at": "2026-01-01T00:00:00Z", "findings": []}
        new = {
            "target_url": "https://example.com",
            "scanned_at": "2026-01-02T00:00:00Z",
            "findings": [
                {"title": "N1", "url": "https://example.com/x", "category": "Test", "severity": "High"},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            p_old = Path(td) / "old.json"
            p_new = Path(td) / "new.json"
            p_old.write_text(json.dumps(old), encoding="utf-8")
            p_new.write_text(json.dumps(new), encoding="utf-8")
            a = type("A", (), {})()
            a.target = None
            a.source = "all"
            a.db = None
            a.old = p_old
            a.new = p_new
            a.output = None
            o, n = sd._resolve_items(a)
            d = sd.diff_findings(o["findings"], n["findings"])
            self.assertEqual(len(d["new"]), 1)
            self.assertEqual(len(d["fixed"]), 0)


if __name__ == "__main__":
    unittest.main()
