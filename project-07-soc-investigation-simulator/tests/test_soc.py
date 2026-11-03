import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from soc import sigma  # noqa: E402
from soc.detect import Correlation, detect, load_all, run_correlation, run_rules  # noqa: E402
from soc.events import load_jsonl, load_otrf_zip, normalise  # noqa: E402
from soc.incidents import decode_powershell, enrich, explain, investigate, load_threat_intel  # noqa: E402
from soc.validate import validate  # noqa: E402

import soc_sim  # noqa: E402

RULES = ROOT / "rules"
SCEN = ROOT / "datasets" / "scenarios"
T0 = datetime(2026, 10, 27, 9, 0, tzinfo=timezone.utc)


def ev(i, secs, **f):
    base = {"_id": f"t{i}", "@timestamp": (T0 + timedelta(seconds=secs)).isoformat(),
            "_logsource": {"product": "windows", "service": "security"}}
    return normalise(base | f, "test", i)


class TestSigmaEngine(unittest.TestCase):
    def rule(self, detection, logsource=None):
        cond = detection.pop("condition")
        return sigma.Rule("x", "x", "high", "test", "", logsource or {}, detection, cond, [], [], "")

    def test_modifiers(self):
        e = {"CommandLine": 'C:\\Windows\\System32\\rundll32.exe comsvcs.dll MiniDump 756 out.dmp full', "_logsource": {}}
        self.assertTrue(sigma.matches(self.rule({"s": {"CommandLine|contains|all": ["comsvcs", "minidump"]}, "condition": "s"}), e))
        self.assertFalse(sigma.matches(self.rule({"s": {"CommandLine|contains|all": ["comsvcs", "nothere"]}, "condition": "s"}), e))
        self.assertTrue(sigma.matches(self.rule({"s": {"CommandLine|re": r"MiniDump \d+"}, "condition": "s"}), e))
        self.assertTrue(sigma.matches(self.rule({"s": {"CommandLine": "*rundll32*"}, "condition": "s"}), e))

    def test_windash_cidr_numeric(self):
        e = {"CommandLine": "schtasks -create /tn x", "ip": "10.1.2.3", "bytes": 5, "_logsource": {}}
        self.assertTrue(sigma.matches(self.rule({"s": {"CommandLine|contains|windash": "/create"}, "condition": "s"}), e))
        self.assertTrue(sigma.matches(self.rule({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"}), e))
        self.assertTrue(sigma.matches(self.rule({"s": {"bytes|gte": 5}, "condition": "s"}), e))
        self.assertFalse(sigma.matches(self.rule({"s": {"bytes|gt": 5}, "condition": "s"}), e))

    def test_conditions(self):
        r = {"a": True, "b": False, "sel_x": True, "sel_y": False}
        self.assertTrue(sigma.evaluate_condition("a and not b", r))
        self.assertTrue(sigma.evaluate_condition("1 of sel_*", r))
        self.assertFalse(sigma.evaluate_condition("all of sel_*", r))
        self.assertTrue(sigma.evaluate_condition("(b or a) and sel_x", r))
        self.assertFalse(sigma.evaluate_condition("a and (b or sel_y)", r))

    def test_logsource(self):
        r = self.rule({"s": {"EventID": 4625}, "condition": "s"}, {"product": "windows", "service": "security"})
        self.assertTrue(sigma.matches(r, ev(1, 0, EventID=4625)))
        self.assertFalse(sigma.matches(r, {"EventID": 4625, "_logsource": {"product": "proxy"}}))

    def test_4688_field_mapping(self):
        e = normalise({"Channel": "Security", "EventID": 4688, "NewProcessName": "C:\\x\\net.exe",
                       "CommandLine": "net localgroup administrators", "TimeCreated": "2026-10-27 09:00:00"}, "t", 0)
        self.assertEqual(e["Image"], "C:\\x\\net.exe")
        self.assertEqual(e["_logsource"]["category"], "process_creation")


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.rules, self.corrs = load_all(RULES)

    def test_bruteforce_then_success(self):
        events = [ev(i, i * 5, EventID=4625, TargetUserName="bob", IpAddress="198.51.100.9") for i in range(12)]
        events.append(ev(99, 120, EventID=4624, TargetUserName="bob", IpAddress="198.51.100.9", LogonType=10))
        names = [a.rule_name for a in detect(self.rules, self.corrs, events)]
        self.assertIn("bruteforce_attempts", names)
        self.assertIn("bruteforce_success", names)

    def test_below_threshold_no_alert(self):
        events = [ev(i, i * 5, EventID=4625, TargetUserName="bob", IpAddress="198.51.100.9") for i in range(9)]
        self.assertEqual(detect(self.rules, self.corrs, events), [])

    def test_outside_timespan_no_alert(self):
        events = [ev(i, i * 120, EventID=4625, TargetUserName="bob", IpAddress="198.51.100.9") for i in range(12)]
        self.assertNotIn("bruteforce_attempts", [a.rule_name for a in detect(self.rules, self.corrs, events)])

    def test_value_count_spray(self):
        events = [ev(i, i * 5, EventID=4625, TargetUserName=f"user{i}", IpAddress="198.51.100.9") for i in range(6)]
        self.assertIn("password_spray", [a.rule_name for a in detect(self.rules, self.corrs, events)])

    def test_success_before_failures_does_not_correlate(self):
        events = [ev(0, 0, EventID=4624, TargetUserName="bob", IpAddress="198.51.100.9", LogonType=10)]
        events += [ev(i, 10 + i * 5, EventID=4625, TargetUserName="bob", IpAddress="198.51.100.9") for i in range(1, 12)]
        self.assertNotIn("bruteforce_success", [a.rule_name for a in detect(self.rules, self.corrs, events)])


class TestRealData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = validate(ROOT / "datasets" / "otrf", RULES)

    def test_every_dataset_detected_with_zero_false_positives(self):
        self.assertEqual(self.v["active"]["detected"], self.v["active"]["expected"])
        self.assertEqual(self.v["active"]["missed"], 0)
        self.assertEqual(self.v["active"]["false_positive_alerts"], 0)

    def test_naive_rule_documents_real_false_positives(self):
        self.assertEqual(self.v["naive_run_key"]["false_positive_alerts"], 4)
        self.assertEqual(self.v["tuned_run_key"]["false_positive_alerts"], 0)

    def test_sysmon_and_4688_deduplicated(self):
        rules, _ = load_all(RULES)
        res = run_rules(rules, load_otrf_zip(ROOT / "datasets" / "otrf" / "psh_lsass_memory_dump_comsvcs.zip"))
        alert = res["lsass_dump_comsvcs"]
        self.assertEqual(len(alert), 1)
        self.assertEqual(sorted(e["EventID"] for e in alert[0].events), [1, 4688])


class TestInvestigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_jsonl(SCEN / "harbor_pine_2026-10-27.jsonl")
        enrich(cls.events, load_threat_intel(SCEN / "threat_intel.csv"))
        cls.alerts = detect(*load_all(RULES), cls.events)
        cls.ctx = json.loads((SCEN / "context.json").read_text())
        cls.incidents = investigate(cls.alerts, cls.events, cls.ctx)
        cls.by_title = {i.title: i for i in cls.incidents}

    def find(self, text):
        return next(i for t, i in self.by_title.items() if text in t)

    def test_seven_incidents_from_eighteen_alerts(self):
        self.assertEqual(len(self.alerts), 18)
        self.assertEqual(len(self.incidents), 7)

    def test_brute_force_chain(self):
        inc = self.find("brute force")
        self.assertEqual((inc.verdict, inc.confidence, inc.severity), ("True positive", "High", "Critical"))
        self.assertEqual(inc.stage, "credential-access")
        self.assertTrue(any("Impossible concurrency" in x for x in inc.evidence_for))
        self.assertTrue(any("whoami /groups" in o for o in inc.observations))

    def test_phishing_scope(self):
        inc = self.find("Phishing")
        self.assertEqual(inc.verdict, "True positive")
        self.assertTrue(any("a.patel, r.haddad; clicked: a.patel" in o for o in inc.observations))

    def test_benign_traps_closed_with_reason(self):
        for text, reason in [("SRV-MGMT-01", "CHG-1042"), ("WS-MGARCIA-04", "CHG-2231"),
                             ("SRV-BACKUP-01", "backup"), ("10.0.9.50", "scanner")]:
            inc = self.find(text)
            self.assertEqual(inc.verdict, "Benign", text)
            self.assertIn(reason.lower(), " ".join(inc.explained.values()).lower())

    def test_unclear_case_stays_inconclusive(self):
        inc = self.find("WS-LCHEN-03")
        self.assertEqual(inc.verdict, "Inconclusive")
        self.assertTrue(inc.uncertainties)
        self.assertIn("Investigate", inc.recommendations)

    def test_ticket_outside_window_does_not_explain(self):
        a = next(a for a in self.alerts if a.rule_name == "powershell_encoded_command" and "MGMT" in a.first["Hostname"])
        late = json.loads(json.dumps(self.ctx))
        late["change_tickets"][0]["end"] = "2026-10-27T10:45:00Z"
        self.assertIsNotNone(explain(a, self.ctx))
        self.assertIsNone(explain(a, late))

    def test_decode_powershell(self):
        self.assertEqual(decode_powershell("powershell -enc dwBoAG8AYQBtAGkA"), "whoami")
        self.assertIsNone(decode_powershell("powershell -File x.ps1"))


class TestEndToEnd(unittest.TestCase):
    def test_cli_all(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(soc_sim.main(["all", "-o", d]), 0)
            html = (Path(d) / "soc_console.html").read_text()
            self.assertIn("SOC Investigation Console", html)
            self.assertNotIn("<script src", html)
            self.assertEqual(len(list((Path(d) / "reports").glob("INC-*.md"))), 7)


if __name__ == "__main__":
    unittest.main()
