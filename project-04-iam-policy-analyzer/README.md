# Project 04 — AWS IAM Policy Risk Analyzer (iam-analyzer)

A tool that reads AWS IAM policies and answers the question cloud security
teams care about most: **who can become an administrator, even if they are
not one today?**

Most cloud breaches involve identity, not exotic exploits. A user without
admin rights can often grant themselves admin through a combination of
ordinary-looking permissions, such as `iam:PassRole` plus `ec2:RunInstances`.
iam-analyzer finds these **privilege-escalation paths**, along with wildcard
permissions, public resource policies and risky trust relationships.

It runs **fully offline** on JSON you export, so it needs no AWS credentials
while running and is safe to use in CI. Standard library only.

## What it checks

| Rule | Severity | What it finds |
|---|---|---|
| IAM-001 | Critical | Full administrator access (every action on every resource) |
| IAM-002 | High | `Allow` + `NotAction`, which silently grants new AWS services as they launch |
| IAM-003 | Critical/High | Service-wide wildcards such as `iam:*` or `s3:*` on all resources |
| IAM-004 | Critical | Resource policies open to `Principal: "*"` with no conditions |
| IAM-005 | High | `iam:PassRole` on all roles |
| IAM-006 | High/Medium | Risky actions on all resources: disabling CloudTrail or GuardDuty, reading secrets, changing bucket or key policies, destructive actions |
| IAM-007 | Critical | Role trust policy that anyone can assume |
| IAM-008 | Medium | Role that trusts an entire external account without an `ExternalId` or other condition |
| **PE-01 to PE-21** | **Critical** (or Medium if scoped) | **21 known privilege-escalation paths**, e.g. `CreatePolicyVersion`, `AttachUserPolicy`, `UpdateAssumeRolePolicy` + `AssumeRole`, `PassRole` + `RunInstances` / `CreateFunction` / `CreateStack`, `UpdateFunctionCode`, `ssm:SendCommand` |

How it evaluates permissions:
- Matches wildcards the way AWS does (`iam:Create*`, case-insensitive)
- Handles `NotAction` and `NotResource`
- Applies unconditional explicit `Deny` statements
- Downgrades an escalation path to Medium when the permissions are scoped to
  specific resources, because that is only dangerous if those resources are privileged

## Analyse a whole account

The most useful mode reads the read-only account export and evaluates each
user and role with **all** of its permissions combined: inline policies,
attached managed policies, and policies inherited through groups.

```bash
aws iam get-account-authorization-details > auth.json   # read-only; needs iam:GetAccountAuthorizationDetails
python3 iam_analyzer.py auth.json
python3 iam_analyzer.py auth.json --format markdown -o report.md
```

Combining policies matters: `support-engineer` in the sample has no policies
of its own, yet can escalate to admin through a policy attached to its group.

## Quick start with the samples

```bash
python3 iam_analyzer.py samples/account_authorization_details.json   # fictional account export
python3 iam_analyzer.py samples/policies/                            # folder of single policies
python3 -m unittest discover -s tests -v                             # 14 tests
```

## Results on the sample account

The sample is a **fictional** export (account `111122223333`, the AWS
documentation example ID) with nine users and roles.

| Principal | Result | Why |
|---|---|---|
| alice-admin | 🔴 Full admin | AWS managed `AdministratorAccess` |
| ci-deployer | 🔴 Can escalate | `iam:PassRole` on all roles + `ec2:RunInstances` |
| support-engineer | 🔴 Can escalate | `iam:CreatePolicyVersion`, inherited through its group |
| legacy-ops | 🔴 Can escalate | Blocked from `iam:*`, but can still replace Lambda code and run SSM commands |
| data-analyst | 🟠 High | Can read every secret and every S3 object |
| scoped-deployer | 🟡 Medium | Same escalation path as ci-deployer, but scoped to one role with a `PassedToService` condition |
| lambda-data-processor | 🟡 Medium | Can update one specific function's code |
| vendor-audit-role | 🟡 Medium | Trusts a whole external account with no `ExternalId` |
| dev-intern | 🟢 Clean | Least-privilege read access to one bucket |

**Key finding:** only 1 principal is an admin on paper, but **3 more** can
make themselves admin. `legacy-ops` shows why "deny all IAM" is not a fix:
without any IAM permissions it can still run code as more privileged roles.

Full reports: [account report](output/account_report.md),
[single-policy report](output/policies_report.md), [SARIF](output/account_report.sarif).

## Use it as a CI gate

If your infrastructure repo stores policy JSON, fail the build on risky
changes and show the findings in GitHub's Security tab:

```yaml
- run: python3 iam_analyzer.py policies/ --format sarif -o iam.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: iam.sarif
```

## Limitations and next steps

- Conditions are not evaluated (they depend on request context), so a
  conditional `Allow` is still reported. This errs on the side of flagging.
- Doesn't model SCPs, permission boundaries or session policies yet. Adding
  them would reduce false positives in AWS Organizations.
- Only five common AWS managed policies are built in. Others are listed as
  "could not read" unless the export includes their documents.
- Next: follow multi-hop paths (user → assume role A → role A can pass role B)
  as a graph, the way PMapper does.

## References

- Rhino Security Labs — AWS IAM privilege escalation methods
- AWS documentation — IAM policy evaluation logic
- CIS AWS Foundations Benchmark — IAM section
