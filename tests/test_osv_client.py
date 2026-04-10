"""Tests for skills/osv_client.py — ecosystem mapping, parsing, cache."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills"))
import osv_client


class TestEcosystemMap(unittest.TestCase):
    def test_known_products_resolve(self):
        self.assertEqual(osv_client.resolve_ecosystem("Next.js"), "npm")
        self.assertEqual(osv_client.resolve_ecosystem("Django"), "PyPI")
        self.assertEqual(osv_client.resolve_ecosystem("WordPress"), "WordPress")
        self.assertEqual(osv_client.resolve_ecosystem("Tomcat"), "Maven")
        self.assertEqual(osv_client.resolve_ecosystem("Node.js"), "node")

    def test_unknown_product_returns_none(self):
        self.assertIsNone(osv_client.resolve_ecosystem("UnknownFramework9000"))

    def test_case_insensitive_lowercase(self):
        self.assertEqual(osv_client.resolve_ecosystem("django"), "PyPI")
        self.assertEqual(osv_client.resolve_ecosystem("express"), "npm")


class TestPackageName(unittest.TestCase):
    def test_npm_display_name_mapped(self):
        self.assertEqual(osv_client._osv_package_name("Next.js", "npm"), "next")
        self.assertEqual(osv_client._osv_package_name("Express", "npm"), "express")

    def test_non_npm_passthrough(self):
        self.assertEqual(osv_client._osv_package_name("Django", "PyPI"), "Django")


class TestParseSeverity(unittest.TestCase):
    def test_critical_from_score(self):
        vuln = {"severity": [{"score": "9.8"}]}
        label, score = osv_client._parse_severity(vuln)
        self.assertEqual(label, "Critical")
        self.assertAlmostEqual(score, 9.8)

    def test_medium_from_score(self):
        vuln = {"severity": [{"score": "5.3"}]}
        label, score = osv_client._parse_severity(vuln)
        self.assertEqual(label, "Medium")

    def test_fallback_to_database_specific(self):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        label, score = osv_client._parse_severity(vuln)
        self.assertEqual(label, "Medium")
        self.assertIsNone(score)

    def test_default_high_when_no_data(self):
        label, score = osv_client._parse_severity({})
        self.assertEqual(label, "High")
        self.assertIsNone(score)


class TestCache(unittest.TestCase):
    def test_put_and_get(self):
        cache = osv_client._Cache(ttl_seconds=3600)
        cache.put("k1", [{"cve_id": "CVE-1"}])
        result = cache.get("k1")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-1")

    def test_miss_returns_none(self):
        cache = osv_client._Cache(ttl_seconds=3600)
        self.assertIsNone(cache.get("nonexistent"))

    def test_clear(self):
        cache = osv_client._Cache(ttl_seconds=3600)
        cache.put("k1", [])
        cache.clear()
        self.assertIsNone(cache.get("k1"))


class TestParseFixedVersions(unittest.TestCase):
    def test_extracts_fixed_version(self):
        vuln = {
            "affected": [{
                "package": {"name": "next", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "14.0.5"}]}],
            }]
        }
        fixed = osv_client._parse_fixed_versions(vuln, "npm", "next")
        self.assertIn("14.0.5", fixed)

    def test_no_match_different_ecosystem(self):
        vuln = {
            "affected": [{
                "package": {"name": "next", "ecosystem": "npm"},
                "ranges": [{"events": [{"fixed": "14.0.5"}]}],
            }]
        }
        fixed = osv_client._parse_fixed_versions(vuln, "PyPI", "next")
        self.assertEqual(fixed, [])


class TestParseCveId(unittest.TestCase):
    def test_prefers_cve_alias(self):
        vuln = {"id": "GHSA-xxxx", "aliases": ["CVE-2024-1234"]}
        self.assertEqual(osv_client._parse_cve_id(vuln), "CVE-2024-1234")

    def test_falls_back_to_id(self):
        vuln = {"id": "GHSA-xxxx", "aliases": []}
        self.assertEqual(osv_client._parse_cve_id(vuln), "GHSA-xxxx")


if __name__ == "__main__":
    unittest.main()
