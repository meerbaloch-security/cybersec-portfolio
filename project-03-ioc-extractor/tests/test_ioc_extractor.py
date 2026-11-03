import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ioc_extractor as ie  # noqa: E402

SAMPLE = (ROOT / "samples" / "sandfox_report.md").read_text(encoding="utf-8")


def values(iocs, kind):
    return [i.value for i in iocs[kind]]


class TestRefang(unittest.TestCase):
    def test_common_styles(self):
        self.assertEqual(ie.refang("hxxps://evil[.]com/a"), "https://evil.com/a")
        self.assertEqual(ie.refang("evil(.)com"), "evil.com")
        self.assertEqual(ie.refang("evil[dot]com"), "evil.com")
        self.assertEqual(ie.refang("bad[at]evil[.]com"), "bad@evil.com")
        self.assertEqual(ie.refang("bad (at) evil.com"), "bad@evil.com")
        self.assertEqual(ie.refang("hxxp[://]1.2.3[.]4"), "http://1.2.3.4")

    def test_defang_roundtrip(self):
        for kind, v in [("url", "https://evil.com/x"), ("domain", "evil.com"), ("ipv4", "1.2.3.4"), ("email", "a@evil.com")]:
            self.assertEqual(ie.refang(ie.defang(v, kind)), v)


class TestSampleReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.iocs = ie.extract(SAMPLE)

    def test_network_indicators(self):
        self.assertEqual(values(self.iocs, "ipv4"), ["203.0.113.45", "198.51.100.23", "192.0.2.77"])
        self.assertIn("2001:db8:4f2a::17", values(self.iocs, "ipv6"))
        for d in ["quick-freight-billing.top", "docs-share-portal.xyz", "cdn-update-sync.com",
                  "logistics-tracking.online", "invoice-portal.zip"]:
            self.assertIn(d, values(self.iocs, "domain"))
        self.assertIn("https://bit.ly/sandfox-inv", values(self.iocs, "url"))
        self.assertEqual(values(self.iocs, "email"), ["billing@quick-freight-billing.top"])

    def test_hashes_not_double_counted(self):
        self.assertEqual(len(values(self.iocs, "sha256")), 3)
        self.assertEqual(len(values(self.iocs, "sha1")), 1)
        self.assertEqual(len(values(self.iocs, "md5")), 1)

    def test_cve_and_attack(self):
        self.assertEqual(values(self.iocs, "cve"), ["CVE-2023-23397", "CVE-2024-21413"])
        self.assertEqual(values(self.iocs, "attack_technique"), ["T1566.001", "T1059.001", "T1071.001", "T1041"])

    def test_noise_filtered(self):
        all_values = {i.value for v in self.iocs.values() for i in v}
        for noise in ["10.20.30.40", "192.168.1.15", "2.4.1.9", "loader.ps1", "backup.zip", "payload.zip",
                      "learn.microsoft.com", "attack.mitre.org", "soc-team@example.com", "0" * 64]:
            self.assertNotIn(noise, all_values)

    def test_keep_flags(self):
        iocs = ie.extract(SAMPLE, keep_private=True, keep_benign=True)
        self.assertIn("10.20.30.40", values(iocs, "ipv4"))
        self.assertIn("learn.microsoft.com", values(iocs, "domain"))


class TestFormats(unittest.TestCase):
    def setUp(self):
        self.iocs = ie.extract(SAMPLE)

    def test_stix_bundle(self):
        b = ie.to_stix(self.iocs, "sandfox_report.md")
        self.assertEqual(b["type"], "bundle")
        kinds = {o["type"] for o in b["objects"]}
        self.assertTrue({"identity", "indicator", "vulnerability", "attack-pattern"} <= kinds)
        for o in b["objects"]:
            self.assertEqual(o["spec_version"], "2.1")
            if o["type"] == "indicator":
                self.assertRegex(o["pattern"], r"^\[[a-z0-9-]+:[\w.'-]+ = '.+'\]$")
        json.dumps(b)  # serialisable

    def test_stix_ids_are_deterministic(self):
        a = {o["id"] for o in ie.to_stix(self.iocs, "x")["objects"]}
        b = {o["id"] for o in ie.to_stix(self.iocs, "x")["objects"]}
        self.assertEqual(a, b)

    def test_csv_and_defanged(self):
        self.assertTrue(ie.to_csv(self.iocs).startswith("type,value,defanged,context"))
        md = ie.to_defanged(self.iocs, "x")
        self.assertIn("docs-share-portal[.]xyz", md)
        self.assertNotIn("https://docs-share-portal.xyz", md)

    def test_html_input(self):
        html = '<p>C2 at <b>203.0.113[.]9</b></p><a href="hxxps://evil-site[.]top/x">report</a><script>var a="10.0.0.1"</script>'
        iocs = ie.extract(ie.html_to_text(html))
        self.assertEqual(values(iocs, "ipv4"), ["203.0.113.9"])
        self.assertIn("https://evil-site.top/x", values(iocs, "url"))

    def test_cli(self):
        self.assertEqual(ie.main([str(ROOT / "samples" / "sandfox_report.md"), "--format", "json"]), 0)


if __name__ == "__main__":
    unittest.main()
