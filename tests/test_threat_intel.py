"""Tests for skills/threat_intel.py — IP/domain extraction and finding generation."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills"))
import threat_intel


class TestIPValidation(unittest.TestCase):
    def test_public_ip(self):
        self.assertTrue(threat_intel._is_public_ip("8.8.8.8"))
        self.assertTrue(threat_intel._is_public_ip("1.2.3.4"))

    def test_private_ip_rejected(self):
        self.assertFalse(threat_intel._is_public_ip("10.0.0.1"))
        self.assertFalse(threat_intel._is_public_ip("192.168.1.1"))
        self.assertFalse(threat_intel._is_public_ip("127.0.0.1"))

    def test_invalid_ip_rejected(self):
        self.assertFalse(threat_intel._is_public_ip("not.an.ip"))
        self.assertFalse(threat_intel._is_public_ip("999.999.999.999"))
        self.assertFalse(threat_intel._is_public_ip(""))


class TestExtractIPs(unittest.TestCase):
    def test_extracts_from_resolved_ips(self):
        recon = json.dumps({"resolved_ips": ["93.184.216.34", "10.0.0.1"]})
        ips = threat_intel._extract_ips_from_recon(recon)
        self.assertIn("93.184.216.34", ips)
        self.assertNotIn("10.0.0.1", ips)

    def test_extracts_from_dns_a_records(self):
        recon = json.dumps({"dns_records": {"A": ["1.2.3.4"]}})
        ips = threat_intel._extract_ips_from_recon(recon)
        self.assertIn("1.2.3.4", ips)

    def test_extracts_from_subdomains(self):
        recon = json.dumps({"subdomains": [{"name": "api.example.com", "ip": "5.6.7.8"}]})
        ips = threat_intel._extract_ips_from_recon(recon)
        self.assertIn("5.6.7.8", ips)

    def test_handles_bad_json(self):
        self.assertEqual(threat_intel._extract_ips_from_recon("not json"), [])

    def test_deduplicates(self):
        recon = json.dumps({"resolved_ips": ["1.1.1.1", "1.1.1.1", "1.1.1.1"]})
        ips = threat_intel._extract_ips_from_recon(recon)
        self.assertEqual(len(ips), 1)

    def test_limits_to_50(self):
        recon = json.dumps({"resolved_ips": [f"1.2.3.{i}" for i in range(100)]})
        ips = threat_intel._extract_ips_from_recon(recon)
        self.assertLessEqual(len(ips), 50)


class TestExtractDomains(unittest.TestCase):
    def test_extracts_associated_domains(self):
        osint = json.dumps({"associated_domains": ["example.com", "test.org"]})
        domains = threat_intel._extract_domains_from_osint(osint)
        self.assertIn("example.com", domains)
        self.assertIn("test.org", domains)

    def test_handles_dict_format(self):
        osint = json.dumps({"domains": [{"domain": "foo.com"}, {"name": "bar.org"}]})
        domains = threat_intel._extract_domains_from_osint(osint)
        self.assertIn("foo.com", domains)
        self.assertIn("bar.org", domains)

    def test_deduplicates_and_lowercases(self):
        osint = json.dumps({"domains": ["Example.COM", "example.com"]})
        domains = threat_intel._extract_domains_from_osint(osint)
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0], "example.com")


class TestReportStructure(unittest.TestCase):
    def test_run_returns_valid_json(self):
        result = threat_intel.run("https://example.com", scan_type="full")
        data = json.loads(result)
        self.assertIn("findings", data)
        self.assertIn("target_url", data)
        self.assertIn("feeds_queried", data)
        self.assertIsInstance(data["findings"], list)
        self.assertTrue(len(data["findings"]) >= 1)

    def test_info_finding_when_no_hits(self):
        result = threat_intel.run("https://example.com", scan_type="full")
        data = json.loads(result)
        info_findings = [f for f in data["findings"] if f["severity"] == "Info"]
        self.assertTrue(len(info_findings) >= 1)


class TestDependencyAuditEOL(unittest.TestCase):
    def test_eol_detected(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills"))
        from dependency_audit import _check_eol
        f = _check_eol("Node.js", "16.20.1", "https://example.com")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "High")
        self.assertIn("end-of-life", f.title)

    def test_eol_not_triggered_for_current(self):
        from dependency_audit import _check_eol
        f = _check_eol("Node.js", "22.1.0", "https://example.com")
        self.assertIsNone(f)

    def test_eol_unknown_product(self):
        from dependency_audit import _check_eol
        f = _check_eol("SomethingNew", "1.0.0", "https://example.com")
        self.assertIsNone(f)


class TestCDNVersionExtraction(unittest.TestCase):
    def test_extracts_from_cdn_url(self):
        from dependency_audit import _extract_cdn_versions
        cs_json = json.dumps({
            "scripts": [
                {"src": "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"},
                {"src": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"},
            ]
        })
        versions = _extract_cdn_versions(cs_json)
        products = {v["product"].lower() for v in versions}
        self.assertTrue(
            "lodash" in products or "jquery" in products,
            f"Expected CDN packages but got: {products}"
        )


if __name__ == "__main__":
    unittest.main()
