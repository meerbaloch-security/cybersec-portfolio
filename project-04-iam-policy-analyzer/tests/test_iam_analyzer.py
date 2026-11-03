import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import iam_analyzer as ia  # noqa: E402

SAMPLES = ROOT / "samples"


def subject(*statements, trust=None):
    s = ia.Subject("policy", "test", "test.json", list(statements), trust_policy=trust)
    ia.check(s)
    s.findings = ia.dedupe(s.findings)
    return s


def rules(s):
    return {f.rule for f in s.findings}


def allow(action, resource="*", **kw):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **kw}


class TestEvaluation(unittest.TestCase):
    def test_wildcards_case_insensitive(self):
        st = [allow("IAM:Create*")]
        self.assertTrue(ia.grants(st, "iam:CreatePolicyVersion")[0])
        self.assertFalse(ia.grants(st, "iam:AttachUserPolicy")[0])

    def test_unconditional_deny_wins(self):
        st = [allow("iam:*"), {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]
        self.assertFalse(ia.grants(st, "iam:CreatePolicyVersion")[0])
        self.assertTrue(ia.grants(st, "iam:AttachUserPolicy")[0])

    def test_notaction(self):
        st = [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
        self.assertFalse(ia.grants(st, "iam:PassRole")[0])
        self.assertTrue(ia.grants(st, "lambda:UpdateFunctionCode")[0])

    def test_url_encoded_document(self):
        self.assertEqual(len(ia.statements_of("%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%7D%5D%7D")), 1)


class TestChecks(unittest.TestCase):
    def test_full_admin(self):
        self.assertIn("IAM-001", rules(subject(allow("*"))))

    def test_poweruser_is_not_admin_but_can_escalate(self):
        s = subject({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"})
        self.assertNotIn("IAM-001", rules(s))
        self.assertIn("IAM-002", rules(s))
        self.assertIn("PE-17", rules(s))   # Lambda code replacement still possible
        self.assertNotIn("PE-14", rules(s))  # no iam:PassRole

    def test_passrole_escalation_broad_vs_scoped(self):
        broad = subject(allow("iam:PassRole"), allow("ec2:RunInstances"))
        pe = next(f for f in broad.findings if f.rule == "PE-14")
        self.assertEqual(pe.severity, "critical")
        scoped = subject(allow("iam:PassRole", "arn:aws:iam::111122223333:role/web"), allow("ec2:RunInstances"))
        pe = next(f for f in scoped.findings if f.rule == "PE-14")
        self.assertEqual(pe.severity, "medium")

    def test_multi_action_path_needs_all_actions(self):
        self.assertNotIn("PE-15", rules(subject(allow(["iam:PassRole", "lambda:CreateFunction"]))))
        self.assertIn("PE-15", rules(subject(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))))

    def test_public_principal(self):
        s = subject({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
        self.assertIn("IAM-004", rules(s))
        s = subject({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
                     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}})
        self.assertNotIn("IAM-004", rules(s))

    def test_trust_policies(self):
        anyone = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
        self.assertIn("IAM-007", rules(subject(trust=anyone)))
        account = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                  "Action": "sts:AssumeRole"}]}
        self.assertIn("IAM-008", rules(subject(trust=account)))

    def test_least_privilege_is_clean(self):
        s = subject(allow(["dynamodb:GetItem", "dynamodb:PutItem"], "arn:aws:dynamodb:us-east-1:111122223333:table/orders"))
        self.assertEqual(s.findings, [])


class TestAccountExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.subjects = {s.name: s for s in ia.analyse(SAMPLES / "account_authorization_details.json")}

    def test_expected_results(self):
        s = self.subjects
        self.assertIn("IAM-001", rules(s["alice-admin"]))            # AWS managed AdministratorAccess
        self.assertIn("PE-14", rules(s["ci-deployer"]))              # URL-encoded inline policy
        self.assertIn("PE-01", rules(s["support-engineer"]))         # inherited through group managed policy
        self.assertIn("PE-17", rules(s["legacy-ops"]))
        self.assertNotIn("IAM-001", rules(s["legacy-ops"]))
        self.assertEqual(s["dev-intern"].findings, [])
        self.assertIn("IAM-008", rules(s["vendor-audit-role"]))
        self.assertIn("arn:aws:iam::aws:policy/ReadOnlyAccess", s["vendor-audit-role"].unresolved)

    def test_outputs(self):
        subjects = list(self.subjects.values())
        md = ia.to_markdown(subjects)
        self.assertIn("escalate to admin", md)
        sarif = ia.to_sarif(subjects)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        json.dumps(sarif)

    def test_fail_on_gate(self):
        self.assertEqual(ia.main([str(SAMPLES / "account_authorization_details.json"), "--fail-on", "high",
                                  "--format", "json", "-o", "/dev/null"]), 1)
        self.assertEqual(ia.main([str(SAMPLES / "policies" / "least_privilege_app.json"), "--fail-on", "low"]), 0)


if __name__ == "__main__":
    unittest.main()
