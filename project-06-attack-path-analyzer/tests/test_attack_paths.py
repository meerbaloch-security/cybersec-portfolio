import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_paths as ap  # noqa: E402
import html_report  # noqa: E402

SAMPLE = json.loads((ROOT / "samples" / "acme_environment.json").read_text())
A = "111122223333"


def allow(a, r="*"):
    return {"Effect": "Allow", "Action": a, "Resource": r}


def env(compute=(), roles=(), users=(), data=()):
    return {"account": {"id": A, "name": "test"}, "compute": list(compute), "roles": list(roles),
            "users": list(users), "data": list(data)}


VULN = {"package": "lib", "version": "1.0", "cves": [{"id": "CVE-0000-0001", "cvss": 9.8, "epss": 0.5,
                                                        "kev": True, "fixed_in": "1.1"}]}
WEB = {"name": "web", "id": "i-1", "type": "ec2", "public": True, "role": "app",
       "exposure": [{"port": 443, "source": "0.0.0.0/0"}], "software": [VULN]}
SECRET = {"name": "db", "type": "secret", "arn": f"arn:aws:secretsmanager:us-east-1:{A}:secret:db-AbC",
          "sensitivity": "critical"}


class TestIam(unittest.TestCase):
    def test_resource_matching_and_deny(self):
        st = [allow("s3:GetObject", "arn:aws:s3:::acme-*/*"),
              {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-secret/*"}]
        self.assertTrue(ap.allowed(st, "s3:GetObject", "arn:aws:s3:::acme-data/x"))
        self.assertFalse(ap.allowed(st, "s3:GetObject", "arn:aws:s3:::acme-secret/x"))
        self.assertFalse(ap.allowed(st, "s3:GetObject", "arn:aws:s3:::other/x"))

    def test_allowed_on_any_requires_star(self):
        self.assertTrue(ap.allowed_on_any([allow("iam:PassRole")], "iam:PassRole"))
        self.assertFalse(ap.allowed_on_any([allow("iam:PassRole", f"arn:aws:iam::{A}:role/x")], "iam:PassRole"))


class TestGraph(unittest.TestCase):
    def test_simple_chain(self):
        inv = env([WEB], [{"name": "app", "trust": [], "statements": [allow("secretsmanager:GetSecretValue", SECRET["arn"])]}],
                  data=[SECRET])
        g, paths, plan = ap.analyse(inv)
        self.assertEqual(len(paths), 1)
        self.assertEqual(ap.describe(g, paths[0]), "Internet → web → app → db")
        self.assertEqual(paths[0].likelihood, "Very likely")
        self.assertEqual(len(plan), 1)
        self.assertIn("Upgrade lib to 1.1", plan[0]["fix"])

    def test_no_exploitable_vuln_no_entry(self):
        safe = copy.deepcopy(WEB)
        safe["software"] = [{"package": "lib", "version": "1.0", "cves": [{"id": "CVE-0000-0002", "cvss": 5.0, "epss": 0.001}]}]
        inv = env([safe], [{"name": "app", "trust": [], "statements": [allow("*")]}], data=[SECRET])
        self.assertEqual(ap.analyse(inv)[1], [])

    def test_escalation_and_role_chaining(self):
        inv = env([WEB], [
            {"name": "app", "trust": [], "statements": [allow("sts:AssumeRole", f"arn:aws:iam::{A}:role/deployer")]},
            {"name": "deployer", "trust": [{"principal": "role:app"}], "statements": [allow(["iam:PassRole", "ec2:RunInstances"])]},
        ], data=[SECRET])
        g, paths, _ = ap.analyse(inv)
        self.assertEqual(ap.describe(g, paths[0]), "Internet → web → app → deployer → Account administrator → db")

    def test_assume_role_needs_both_permission_and_trust(self):
        inv = env([WEB], [
            {"name": "app", "trust": [], "statements": [allow("sts:AssumeRole")]},
            {"name": "deployer", "trust": [{"principal": "role:someone-else"}], "statements": [allow("*")]},
        ], data=[SECRET])
        self.assertEqual(ap.analyse(inv)[1], [])

    def test_partial_bucket_access_counts(self):
        bucket = {"name": "cust", "type": "s3", "sensitivity": "critical"}
        inv = env([WEB], [{"name": "app", "trust": [], "statements": [allow("s3:GetObject", "arn:aws:s3:::cust/exports/*")]}],
                  data=[bucket])
        self.assertEqual(len(ap.analyse(inv)[1]), 1)

    def test_low_sensitivity_data_is_not_a_target(self):
        inv = env([WEB], [{"name": "app", "trust": [], "statements": [allow("s3:GetObject")]}],
                  data=[{"name": "public-images", "type": "s3", "sensitivity": "low"}])
        self.assertEqual(ap.analyse(inv)[1], [])


class TestSample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g, cls.paths, cls.plan = ap.analyse(SAMPLE)

    def test_headline_numbers(self):
        s = ap.summarise(self.g, self.paths, self.plan)
        self.assertEqual(s["attack_paths"], 17)
        self.assertEqual(len(s["crown_jewels_reachable"]), 3)
        self.assertEqual(s["fixes_to_break_all"], 5)
        self.assertEqual(s["easiest_path_steps"], 2)

    def test_top_path_is_three_steps_to_customer_data(self):
        top = self.paths[0]
        self.assertEqual(len(top.edges), 3)
        self.assertEqual(self.g.nodes[top.target].label, "acme-customer-data")

    def test_plan_breaks_everything(self):
        removed = {f["edge"] for f in self.plan}
        self.assertEqual(ap.find_paths(self.g, removed), [])
        self.assertEqual(self.plan[-1]["cumulative_pct"], 100)

    def test_admin_with_mfa_and_no_entry_is_not_a_path(self):
        self.assertFalse(any("user:alice" in e for p in self.paths for e in p.edges))

    def test_html_report(self):
        out = html_report.render(ap.to_json(self.g, self.paths, self.plan))
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertIn("Attack Path Report", out)
        self.assertNotIn("<script src", out)       # fully self-contained
        self.assertIn("acme-customer-data", out)

    def test_cli(self):
        self.assertEqual(ap.main([str(ROOT / "samples" / "acme_environment.json"), "--fail-on-paths",
                                  "--format", "json", "-o", "/dev/null"]), 1)


if __name__ == "__main__":
    unittest.main()
