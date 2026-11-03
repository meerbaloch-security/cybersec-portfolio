"""Offline tests. All vulnerability data below is FAKE fixture data (package
'demo-lib', CVE-0000-xxxx IDs) shaped like the real OSV, EPSS and KEV APIs."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vuln_prioritizer as vp  # noqa: E402

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"   # 7.8
MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"    # 6.1


def vuln(vid, cve, vector=None, fixed="2.0.0", label=None, pkg="demo-lib", eco="PyPI"):
    v = {"id": vid, "summary": f"Fake issue {vid}", "aliases": [cve] if cve else [],
         "affected": [{"package": {"name": pkg, "ecosystem": eco},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    if vector:
        v["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if label:
        v["database_specific"] = {"severity": label}
    return v


VULNS = {
    "TEST-KEV": vuln("TEST-KEV", "CVE-0000-0001", MED, "1.5.0"),         # medium CVSS, but exploited
    "TEST-EPSS": vuln("TEST-EPSS", "CVE-0000-0002", HIGH, "1.8.0"),      # high CVSS + high EPSS
    "TEST-CRIT": vuln("TEST-CRIT", "CVE-0000-0003", CRIT, "2.0.0"),      # critical, nobody exploiting
    "TEST-LOW": vuln("TEST-LOW", "CVE-0000-0004", None, "2.0.0", "LOW"),  # only an advisory label
    "TEST-DUP": vuln("TEST-DUP", "CVE-0000-0003", CRIT, "2.0.0"),        # same CVE from another database
}
EPSS = {"CVE-0000-0001": ("0.02", "0.80"), "CVE-0000-0002": ("0.45", "0.98"),
        "CVE-0000-0003": ("0.0004", "0.10"), "CVE-0000-0004": ("0.0001", "0.01")}
KEV = {"vulnerabilities": [{"cveID": "CVE-0000-0001", "knownRansomwareCampaignUse": "Known", "dueDate": "2026-12-01"}]}


class FakeAPI:
    def __init__(self):
        self.calls = []

    def __call__(self, url, body=None):
        self.calls.append(url)
        if url == vp.OSV_BATCH:
            out = []
            for q in body["queries"]:
                ids = list(VULNS) if q["package"]["name"] == "demo-lib" else []
                out.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]})
            return {"results": out}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return VULNS[url.rsplit("/", 1)[1]]
        if url.startswith("https://api.first.org/"):
            cves = url.split("cve=", 1)[1].split(",")
            return {"status": "OK", "data": [{"cve": c, "epss": EPSS[c][0], "percentile": EPSS[c][1],
                                              "date": "2026-11-01"} for c in cves if c in EPSS]}
        if url == vp.KEV_FEED:
            return KEV
        raise AssertionError(f"unexpected URL {url}")


class TestScoring(unittest.TestCase):
    def test_cvss_reference_vectors(self):
        self.assertEqual(vp.cvss3_base(CRIT), 9.8)
        self.assertEqual(vp.cvss3_base(HIGH), 7.8)
        self.assertEqual(vp.cvss3_base(MED), 6.1)
        self.assertEqual(vp.cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(vp.cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(vp.cvss3_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))

    def test_tiers(self):
        self.assertEqual(vp.prioritise(4.0, 0.001, True)[0], "P1")
        self.assertEqual(vp.prioritise(7.5, 0.20, False)[0], "P1")
        self.assertEqual(vp.prioritise(5.0, 0.20, False)[0], "P2")
        self.assertEqual(vp.prioritise(9.8, 0.0004, False)[0], "P2")
        self.assertEqual(vp.prioritise(7.5, 0.001, False)[0], "P3")
        self.assertEqual(vp.prioritise(4.0, 0.001, False)[0], "P4")


class TestParsing(unittest.TestCase):
    def test_requirements(self):
        pkgs, skipped = vp.parse_requirements("Django==3.2\nPyYAML[extra]==5.3 ; python_version>'3'\n"
                                              "flask>=2\n# comment\n-r other.txt\nzope.interface==5.0\n")
        self.assertEqual([(p.name, p.version) for p in pkgs], [("django", "3.2"), ("pyyaml", "5.3"),
                                                               ("zope-interface", "5.0")])
        self.assertEqual(skipped, ["flask>=2"])

    def test_package_lock_v1_and_v3(self):
        v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0",
                         "dependencies": {"b": {"version": "2.0.0"}}}}})
        self.assertEqual({p.name for p in vp.parse_package_lock(v1)[0]}, {"a", "b"})
        pkgs, _ = vp.load_dependencies(ROOT / "samples" / "package-lock.json")
        self.assertIn(("qs", "6.7.0"), {(p.name, p.version) for p in pkgs})  # nested dependency
        self.assertNotIn("demo-web-app", {p.name for p in pkgs})            # root project excluded

    def test_version_sort(self):
        self.assertEqual(sorted(["2.0.0", "2.0.0rc1", "1.10.0", "1.9.2"], key=vp._version_key),
                         ["1.9.2", "1.10.0", "2.0.0rc1", "2.0.0"])


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.findings = vp.analyse([vp.Package("demo-lib", "1.0.0", "PyPI"), vp.Package("safe-lib", "1.0", "PyPI")],
                                   self.api)
        self.by_id = {f.vuln_id: f for f in self.findings}

    def test_duplicate_cve_reported_once(self):
        self.assertEqual(len(self.findings), 4)
        self.assertNotIn("TEST-DUP", self.by_id)

    def test_exploitation_beats_severity(self):
        kev = self.by_id["TEST-KEV"]
        self.assertEqual((kev.tier, kev.in_kev, kev.ransomware), ("P1", True, True))
        self.assertEqual(self.by_id["TEST-EPSS"].tier, "P1")
        self.assertEqual(self.by_id["TEST-CRIT"].tier, "P2")    # 9.8 but EPSS 0.04%
        low = self.by_id["TEST-LOW"]
        self.assertEqual((low.cvss, low.cvss_source, low.tier), (2.5, "advisory label (low)", "P4"))
        self.assertEqual(self.findings[0].tier, "P1")            # sorted most urgent first

    def test_stats_and_plan(self):
        s = vp.stats(self.findings)
        self.assertEqual(s["by_tier"], {"P1": 2, "P2": 1, "P3": 0, "P4": 1})
        self.assertEqual(s["cvss_high_or_critical"], 2)
        plan = vp.upgrade_plan(self.findings)
        self.assertEqual(plan[0]["target"], "2.0.0")              # one upgrade fixes all four
        self.assertEqual(plan[0]["fixes"], 4)

    def test_reports_and_cli(self):
        md = vp.to_markdown(self.findings, [], [], "x")
        self.assertIn("Upgrade plan", md)
        self.assertIn("ransomware", md)
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text("demo-lib==1.0.0\n")
            self.assertEqual(vp.main([str(req), "--format", "json", "-o", str(Path(d) / "o.json"),
                                      "--fail-on", "P1"], fetch=FakeAPI()), 1)
            self.assertEqual(vp.main([str(req), "--cache", str(Path(d) / "c"), "-o", str(Path(d) / "o.txt")],
                                     fetch=FakeAPI()), 0)
            self.assertTrue(any((Path(d) / "c").iterdir()))       # cache written


if __name__ == "__main__":
    unittest.main()
