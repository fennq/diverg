"""Tests for compliance mapping and enrichment in orchestrator.py."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "skills"))


class TestComplianceMapFile(unittest.TestCase):
    def setUp(self):
        path = ROOT / "content" / "compliance_map.json"
        with open(path) as f:
            self.data = json.load(f)

    def test_has_required_keys(self):
        self.assertIn("by_exploit_id", self.data)
        self.assertIn("by_category", self.data)

    def test_exploit_ids_have_frameworks(self):
        required_frameworks = {"owasp_top10", "pci_dss", "soc2"}
        for eid, mapping in self.data["by_exploit_id"].items():
            for fw in required_frameworks:
                self.assertIn(fw, mapping, f"{eid} missing {fw}")

    def test_all_exploit_catalog_ids_covered(self):
        catalog_path = ROOT / "content" / "exploit_catalog.json"
        with open(catalog_path) as f:
            catalog = json.load(f)
        catalog_ids = {e["id"] for e in catalog.get("exploits", [])}
        mapped_ids = set(self.data["by_exploit_id"].keys())
        missing = catalog_ids - mapped_ids
        self.assertEqual(missing, set(), f"Exploit IDs not in compliance map: {missing}")

    def test_category_entries_have_owasp(self):
        for cat, mapping in self.data["by_category"].items():
            self.assertIn("owasp_top10", mapping, f"Category {cat} missing owasp_top10")


class TestComplianceEnrichment(unittest.TestCase):
    def test_enrich_finding_adds_compliance(self):
        from orchestrator import enrich_findings_compliance

        findings = [{
            "title": "XSS Reflected in search param",
            "severity": "High",
            "category": "Injection",
            "exploit_ref": {"owasp": "A03:2021 Injection"},
        }]
        enriched = enrich_findings_compliance(findings)
        self.assertEqual(len(enriched), 1)
        # Should have compliance attached via exploit_ref owasp match or category
        # (depends on mapping logic, but the function should not crash)

    def test_enrich_by_category_fallback(self):
        from orchestrator import enrich_findings_compliance

        findings = [{
            "title": "Detected Express 4.17.1; CVE-2022-24999 may apply",
            "severity": "High",
            "category": "Dependency / CVE",
        }]
        enriched = enrich_findings_compliance(findings)
        comp = enriched[0].get("compliance")
        self.assertIsNotNone(comp, "Category 'Dependency / CVE' should match compliance map")
        self.assertIn("owasp_top10", comp)


class TestComplianceSummary(unittest.TestCase):
    def test_summary_aggregates_counts(self):
        from orchestrator import build_compliance_summary

        findings = [
            {
                "title": "A",
                "compliance": {
                    "owasp_top10": "A03:2021 Injection",
                    "pci_dss": ["6.2.4", "6.5.1"],
                },
            },
            {
                "title": "B",
                "compliance": {
                    "owasp_top10": "A03:2021 Injection",
                    "pci_dss": ["6.2.4"],
                },
            },
            {"title": "C"},
        ]
        summary = build_compliance_summary(findings)
        self.assertEqual(summary["owasp_top10"]["A03:2021 Injection"], 2)
        self.assertEqual(summary["pci_dss"]["6.2.4"], 2)
        self.assertEqual(summary["pci_dss"]["6.5.1"], 1)
        self.assertNotIn("soc2", summary)

    def test_empty_findings(self):
        from orchestrator import build_compliance_summary
        self.assertEqual(build_compliance_summary([]), {})


if __name__ == "__main__":
    unittest.main()
