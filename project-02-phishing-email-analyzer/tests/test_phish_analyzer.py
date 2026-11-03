import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "samples"))

import make_samples  # noqa: E402
import phish_analyzer as pa  # noqa: E402

make_samples.save("credential_phish.eml", make_samples.credential_phish())
make_samples.save("malware_invoice.eml", make_samples.malware_phish())
make_samples.save("bec_giftcard.eml", make_samples.bec_phish())
make_samples.save("legit_newsletter.eml", make_samples.legit_newsletter())
S = ROOT / "samples"


def cats(report):
    return {f.category for f in report.findings}


class TestHelpers(unittest.TestCase):
    def test_lookalike(self):
        self.assertEqual(pa.lookalike_of("paypa1-secure.xyz"), "paypal.com")
        self.assertEqual(pa.lookalike_of("rnicrosoft.com"), "microsoft.com")
        self.assertEqual(pa.lookalike_of("microsoft.account-verify.top"), "microsoft.com")
        self.assertIsNone(pa.lookalike_of("www.paypal.com"))
        self.assertIsNone(pa.lookalike_of("example.org"))

    def test_registrable(self):
        self.assertEqual(pa.registrable("login.commbank.com.au"), "commbank.com.au")
        self.assertEqual(pa.registrable("a.b.example.com"), "example.com")

    def test_defang(self):
        self.assertEqual(pa.defang("http://evil.com/a"), "hxxp://evil[.]com/a")


class TestSamples(unittest.TestCase):
    def test_credential_phish(self):
        r = pa.analyze(S / "credential_phish.eml")
        self.assertEqual(r.verdict, "malicious")
        self.assertEqual(r.auth["dmarc"], "fail")
        self.assertEqual(r.sender_ip, "203.0.113.45")
        self.assertTrue({"spoofing", "lookalike", "url", "social-engineering"} <= cats(r))
        self.assertTrue(any("text/href mismatch" in u["flags"] for u in r.urls))
        self.assertTrue(any("raw IP address" in u["flags"] for u in r.urls))

    def test_malware_invoice(self):
        r = pa.analyze(S / "malware_invoice.eml")
        self.assertEqual(r.verdict, "malicious")
        flags = {f for a in r.attachments for f in a["flags"]}
        self.assertIn("double extension", flags)
        self.assertIn("macro-enabled Office file", flags)

    def test_bec(self):
        r = pa.analyze(S / "bec_giftcard.eml")
        self.assertIn(r.verdict, {"suspicious", "malicious"})
        self.assertIn("spoofing", cats(r))  # display name hides a different address
        self.assertIn("bec", cats(r))

    def test_legit(self):
        r = pa.analyze(S / "legit_newsletter.eml")
        self.assertEqual(r.verdict, "likely safe")
        self.assertLess(r.score, 30)

    def test_markdown_and_json(self):
        r = pa.analyze(S / "credential_phish.eml")
        md = pa.to_markdown(r)
        self.assertIn("Verdict", md)
        self.assertIn("hxxp", md)
        self.assertEqual(pa.main([str(S / "legit_newsletter.eml"), "--format", "json"]), 0)


if __name__ == "__main__":
    unittest.main()
