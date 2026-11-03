#!/usr/bin/env python3
"""iam-analyzer: find risky permissions and privilege-escalation paths in AWS IAM.

Works fully offline on JSON you export yourself, so it needs no AWS access
while it runs:

  * a single IAM policy document           (policy.json)
  * a folder of policy documents           (policies/)
  * a full account export, analysed per user/role with every inline,
    attached and group policy combined:
        aws iam get-account-authorization-details > auth.json

Usage:
    python3 iam_analyzer.py samples/account_authorization_details.json
    python3 iam_analyzer.py samples/policies/ --format markdown -o report.md
    python3 iam_analyzer.py policy.json --format sarif -o results.sarif
    python3 iam_analyzer.py auth.json --fail-on high        # CI gate: exit 1 on high+
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote

SEVERITIES = ["critical", "high", "medium", "low"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
# Known privilege-escalation paths: if a principal holds ALL actions in one
# entry, it can grant itself more access than it was meant to have.
# Based on public research (Rhino Security Labs, PMapper, Cloudsplaining).
ESCALATION_PATHS = [
    {"id": "PE-01", "name": "Create a new version of a managed policy",
     "actions": ["iam:CreatePolicyVersion"],
     "how": "Can publish a new default version of a policy attached to itself containing \"Action\": \"*\"."},
    {"id": "PE-02", "name": "Switch a policy's default version",
     "actions": ["iam:SetDefaultPolicyVersion"],
     "how": "Can roll a policy back to an older, more permissive version."},
    {"id": "PE-03", "name": "Attach a managed policy to a user",
     "actions": ["iam:AttachUserPolicy"],
     "how": "Can attach AdministratorAccess to itself or another user."},
    {"id": "PE-04", "name": "Attach a managed policy to a group",
     "actions": ["iam:AttachGroupPolicy"],
     "how": "Can attach AdministratorAccess to a group it belongs to."},
    {"id": "PE-05", "name": "Attach a managed policy to a role and assume it",
     "actions": ["iam:AttachRolePolicy", "sts:AssumeRole"],
     "how": "Can attach AdministratorAccess to a role, then assume that role."},
    {"id": "PE-06", "name": "Write an inline policy on a user",
     "actions": ["iam:PutUserPolicy"],
     "how": "Can add an inline admin policy to itself."},
    {"id": "PE-07", "name": "Write an inline policy on a group",
     "actions": ["iam:PutGroupPolicy"],
     "how": "Can add an inline admin policy to a group it belongs to."},
    {"id": "PE-08", "name": "Write an inline policy on a role and assume it",
     "actions": ["iam:PutRolePolicy", "sts:AssumeRole"],
     "how": "Can add an inline admin policy to a role, then assume it."},
    {"id": "PE-09", "name": "Add self to a privileged group",
     "actions": ["iam:AddUserToGroup"],
     "how": "Can join an existing admin group."},
    {"id": "PE-10", "name": "Create access keys for other users",
     "actions": ["iam:CreateAccessKey"],
     "how": "Can create keys for a more privileged user and act as them."},
    {"id": "PE-11", "name": "Set or reset another user's console password",
     "actions": ["iam:CreateLoginProfile"],
     "how": "Can give a privileged user a console password it knows."},
    {"id": "PE-12", "name": "Reset another user's console password",
     "actions": ["iam:UpdateLoginProfile"],
     "how": "Can change a privileged user's console password."},
    {"id": "PE-13", "name": "Rewrite a role's trust policy and assume it",
     "actions": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
     "how": "Can make a privileged role trust itself, then assume it."},
    {"id": "PE-14", "name": "Pass a role to a new EC2 instance",
     "actions": ["iam:PassRole", "ec2:RunInstances"],
     "how": "Can launch an instance with a privileged role and use that role's credentials from the instance."},
    {"id": "PE-15", "name": "Pass a role to a new Lambda function",
     "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
     "how": "Can create and run a function that executes with a privileged role."},
    {"id": "PE-16", "name": "Pass a role to a Lambda triggered by an event source",
     "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
     "how": "Can create a function with a privileged role that runs on an event trigger."},
    {"id": "PE-17", "name": "Replace the code of an existing Lambda function",
     "actions": ["lambda:UpdateFunctionCode"],
     "how": "Can change the code of a function that already runs with a privileged role."},
    {"id": "PE-18", "name": "Pass a role to a CloudFormation stack",
     "actions": ["iam:PassRole", "cloudformation:CreateStack"],
     "how": "Can deploy a stack that creates resources using a privileged role."},
    {"id": "PE-19", "name": "Pass a role to a Glue development endpoint",
     "actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
     "how": "Can create a Glue endpoint that runs with a privileged role."},
    {"id": "PE-20", "name": "Pass a role to a SageMaker notebook",
     "actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
     "how": "Can create a notebook that runs with a privileged role."},
    {"id": "PE-21", "name": "Run commands on EC2 instances through SSM",
     "actions": ["ssm:SendCommand"],
     "how": "Can run commands on instances and use their instance-profile roles."},
]

# Single permissions that are risky when granted on Resource "*".
RISKY_ACTIONS = {
    "high": {
        "Defense evasion (disables security logging or detection)": [
            "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
            "guardduty:DeleteDetector", "guardduty:UpdateDetector", "config:StopConfigurationRecorder",
            "config:DeleteConfigurationRecorder", "securityhub:DisableSecurityHub", "logs:DeleteLogGroup",
        ],
        "Secret and key access (data exfiltration risk)": [
            "secretsmanager:GetSecretValue", "kms:Decrypt", "ssm:GetParameter", "ssm:GetParameters",
            "ssm:GetParametersByPath",
        ],
        "Resource policy changes (can expose data publicly)": [
            "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:DeleteBucketPolicy", "s3:PutBucketPublicAccessBlock",
            "kms:PutKeyPolicy", "lambda:AddPermission", "sns:SetTopicAttributes", "sqs:SetQueueAttributes",
        ],
    },
    "medium": {
        "Broad data read access": ["s3:GetObject", "dynamodb:Scan", "dynamodb:GetItem", "rds:DownloadDBLogFilePortion"],
        "Destructive actions": ["s3:DeleteBucket", "s3:DeleteObject", "rds:DeleteDBInstance", "ec2:TerminateInstances",
                                "dynamodb:DeleteTable", "kms:ScheduleKeyDeletion"],
        "Network exposure": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifyInstanceAttribute"],
    },
}
ADMIN_PROBES = ["iam:AttachUserPolicy", "iam:PassRole", "organizations:LeaveOrganization", "s3:GetObject",
                "ec2:RunInstances", "kms:Decrypt", "cloudtrail:StopLogging", "futureservice:AnyAction"]
SENSITIVE_SERVICES = {"iam", "sts", "kms", "secretsmanager", "organizations", "cloudtrail", "s3", "ec2", "lambda"}

# Well-known AWS managed policies, used when an account export does not include
# their documents. Only the parts that matter for risk are modelled.
AWS_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    "arn:aws:iam::aws:policy/IAMFullAccess": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    "arn:aws:iam::aws:policy/PowerUserAccess": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole",
                                       "iam:ListRoles", "organizations:DescribeOrganization"], "Resource": "*"},
    ],
    "arn:aws:iam::aws:policy/AmazonS3FullAccess": [{"Effect": "Allow", "Action": ["s3:*", "s3-object-lambda:*"], "Resource": "*"}],
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    remediation: str
    actions: list[str] = field(default_factory=list)


@dataclass
class Subject:
    """Something that holds permissions: a policy file, a user or a role."""
    kind: str  # policy | user | role | group
    name: str
    source: str
    statements: list[dict]
    policy_names: list[str] = field(default_factory=list)
    trust_policy: dict | None = None
    findings: list[Finding] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    @property
    def worst(self) -> str | None:
        return min((f.severity for f in self.findings), key=SEV_RANK.get, default=None)


# --------------------------------------------------------------------------- #
# Policy evaluation helpers
# --------------------------------------------------------------------------- #
def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def load_doc(doc) -> dict:
    """Policy documents in account exports can be URL-encoded strings."""
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    return doc


def statements_of(doc) -> list[dict]:
    doc = load_doc(doc)
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def stmt_covers(stmt: dict, action: str) -> bool:
    if "NotAction" in stmt:
        return not any(action_matches(p, action) for p in as_list(stmt["NotAction"]))
    return any(action_matches(p, action) for p in as_list(stmt.get("Action")))


def is_star_resource(stmt: dict) -> bool:
    return "NotResource" in stmt or "*" in as_list(stmt.get("Resource"))


def grants(statements: list[dict], action: str) -> tuple[bool, bool, bool]:
    """Return (allowed, on_any_resource, unconditional) for an action.

    An unconditional Deny on all resources removes the permission. Conditional
    or resource-scoped Denies are reported as still allowed (we can't evaluate
    request context offline), which errs on the side of flagging.
    """
    for s in statements:
        if s.get("Effect") == "Deny" and stmt_covers(s, action) and is_star_resource(s) and not s.get("Condition"):
            return False, False, False
    allow = [s for s in statements if s.get("Effect") == "Allow" and stmt_covers(s, action)]
    if not allow:
        return False, False, False
    return True, any(is_star_resource(s) for s in allow), any(not s.get("Condition") for s in allow)


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check(subject: Subject) -> None:
    st = subject.statements
    add = subject.findings.append

    # Full admin: every probe action (across IAM, data, compute, logging and an
    # invented future service) is allowed on all resources. A NotAction policy
    # that excludes iam:* is therefore not counted as admin, but is flagged below.
    probes = [grants(st, a) for a in ADMIN_PROBES]
    full_admin = (all(p[0] for p in probes), all(p[1] for p in probes))
    if full_admin[0] and full_admin[1]:
        add(Finding("IAM-001", "critical", "Full administrator access",
                    "Allows every action on every resource (\"Action\": \"*\" or equivalent NotAction).",
                    "Replace with least-privilege policies scoped to the services and resources actually used.",
                    ["*"]))

    for s in st:
        if s.get("Effect") != "Allow":
            continue
        if "NotAction" in s:
            add(Finding("IAM-002", "high", "Allow with NotAction",
                        f"Grants everything except {as_list(s['NotAction'])}; new AWS services are allowed automatically.",
                        "Use an explicit Action list instead of NotAction with Allow.", as_list(s["NotAction"])))
        for a in as_list(s.get("Action")):
            svc, _, op = a.partition(":")
            if op == "*" and svc.lower() in SENSITIVE_SERVICES and is_star_resource(s):
                add(Finding("IAM-003", "critical" if svc.lower() == "iam" else "high",
                            f"Service-wide wildcard: {a}",
                            f"Grants every {svc} action on all resources.",
                            f"List only the {svc} actions needed and scope Resource to specific ARNs.", [a]))
        for p in as_list(s.get("Principal", {}).get("AWS") if isinstance(s.get("Principal"), dict) else s.get("Principal")):
            if p == "*" and not s.get("Condition"):
                add(Finding("IAM-004", "critical", "Resource policy allows anyone (Principal \"*\")",
                            "Any AWS account, or anonymous users for S3, can use this resource.",
                            "Restrict Principal to specific account or role ARNs, or add aws:SourceAccount / aws:PrincipalOrgID conditions.",
                            as_list(s.get("Action"))))

    if full_admin[0] and full_admin[1]:
        return  # every other finding is implied by full admin

    # iam:PassRole on any role
    passrole = grants(st, "iam:PassRole")
    if passrole[0] and passrole[1]:
        add(Finding("IAM-005", "high", "iam:PassRole on all roles",
                    "Can hand any role, including admin roles, to AWS services.",
                    "Scope Resource to the specific role ARNs and add an iam:PassedToService condition.",
                    ["iam:PassRole"]))

    # Privilege escalation paths
    for path in ESCALATION_PATHS:
        results = [grants(st, a) for a in path["actions"]]
        if all(r[0] for r in results):
            broad = all(r[1] for r in results)
            add(Finding(path["id"], "critical" if broad else "medium",
                        f"Privilege escalation: {path['name']}",
                        path["how"] + ("" if broad else " Permissions are scoped to specific resources, so confirm "
                                                         "whether those resources are privileged."),
                        "Remove these permissions, or scope them to non-privileged resources with a permissions boundary.",
                        path["actions"]))

    # Risky single actions on any resource
    for sev, groups in RISKY_ACTIONS.items():
        for label, actions in groups.items():
            hit = [a for a in actions if (g := grants(st, a))[0] and g[1]]
            if hit:
                add(Finding("IAM-006", sev, label, f"Allowed on all resources: {', '.join(hit)}",
                            "Scope Resource to specific ARNs and require conditions such as aws:MultiFactorAuthPresent.",
                            hit))

    # Trust policy problems (roles)
    if subject.trust_policy:
        for s in statements_of(subject.trust_policy):
            if s.get("Effect") != "Allow":
                continue
            principal = s.get("Principal", {})
            aws = as_list(principal.get("AWS")) if isinstance(principal, dict) else as_list(principal)
            if "*" in aws and not s.get("Condition"):
                add(Finding("IAM-007", "critical", "Role can be assumed by anyone",
                            "Trust policy allows Principal \"*\" with no conditions.",
                            "Trust only specific accounts or roles, and add sts:ExternalId for third parties.", ["sts:AssumeRole"]))
            elif any(a.endswith(":root") and not s.get("Condition") for a in aws):
                ext = [a for a in aws if a.endswith(":root")]
                add(Finding("IAM-008", "medium", "Role trusts an entire account",
                            f"Any principal with sts:AssumeRole in {', '.join(ext)} can assume this role.",
                            "Trust a specific role ARN, or add conditions (sts:ExternalId, aws:PrincipalArn).",
                            ["sts:AssumeRole"]))


# --------------------------------------------------------------------------- #
# Loading inputs
# --------------------------------------------------------------------------- #
def subjects_from_auth_details(data: dict, source: str) -> list[Subject]:
    managed: dict[str, list[dict]] = {}
    for p in data.get("Policies", []):
        default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if default:
            managed[p["Arn"]] = statements_of(default["Document"])

    def resolve(attached: list[dict], subj: Subject) -> None:
        for a in attached:
            arn = a.get("PolicyArn", "")
            stmts = managed.get(arn) or AWS_MANAGED.get(arn)
            subj.policy_names.append(a.get("PolicyName", arn))
            if stmts is None:
                subj.unresolved.append(arn)
            else:
                subj.statements.extend(stmts)

    def inline(items: list[dict], subj: Subject) -> None:
        for p in items:
            subj.policy_names.append(f"{p.get('PolicyName')} (inline)")
            subj.statements.extend(statements_of(p["PolicyDocument"]))

    groups: dict[str, Subject] = {}
    for g in data.get("GroupDetailList", []):
        gs = Subject("group", g["GroupName"], source, [])
        inline(g.get("GroupPolicyList", []), gs)
        resolve(g.get("AttachedManagedPolicies", []), gs)
        groups[g["GroupName"]] = gs

    subjects: list[Subject] = []
    for u in data.get("UserDetailList", []):
        us = Subject("user", u["UserName"], source, [])
        inline(u.get("UserPolicyList", []), us)
        resolve(u.get("AttachedManagedPolicies", []), us)
        for gname in u.get("GroupList", []):
            if gname in groups:
                us.statements.extend(groups[gname].statements)
                us.policy_names += [f"{n} (via group {gname})" for n in groups[gname].policy_names]
                us.unresolved += groups[gname].unresolved
        subjects.append(us)

    for r in data.get("RoleDetailList", []):
        rs = Subject("role", r["RoleName"], source, [],
                     trust_policy=load_doc(r["AssumeRolePolicyDocument"]) if r.get("AssumeRolePolicyDocument") else None)
        inline(r.get("RolePolicyList", []), rs)
        resolve(r.get("AttachedManagedPolicies", []), rs)
        subjects.append(rs)
    return subjects


def load_subjects(path: Path) -> list[Subject]:
    files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    subjects: list[Subject] = []
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        if any(k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList")):
            subjects += subjects_from_auth_details(data, f.name)
        elif "Statement" in data:
            subjects.append(Subject("policy", f.stem, f.name, statements_of(data), [f.name]))
        else:
            print(f"skip {f}: not an IAM policy or account authorization export", file=sys.stderr)
    return subjects


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: SEV_RANK[f.severity]):
        key = (f.rule, f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def summary_counts(subjects: list[Subject]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for subj in subjects:
        for f in subj.findings:
            counts[f.severity] += 1
    return counts


ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def to_text(subjects: list[Subject]) -> str:
    out = []
    for s in sorted(subjects, key=lambda s: SEV_RANK.get(s.worst, 9)):
        label = (s.worst or "ok").upper()
        out.append(f"\n[{label:<8}] {s.kind} {s.name}  ({len(s.findings)} findings)")
        for f in s.findings:
            out.append(f"    {f.severity:<8} {f.rule:<8} {f.title}")
        if s.unresolved:
            out.append(f"    note: could not read {len(s.unresolved)} managed policy document(s): {', '.join(s.unresolved)}")
    c = summary_counts(subjects)
    esc = sum(1 for s in subjects if any(f.rule.startswith("PE-") and f.severity == "critical" for f in s.findings))
    admins = sum(1 for s in subjects if any(f.rule == "IAM-001" for f in s.findings))
    out.append(f"\nAnalysed {len(subjects)} principals/policies: {c['critical']} critical, {c['high']} high, "
               f"{c['medium']} medium findings")
    out.append(f"{admins} with full admin; {esc} more can escalate to admin through a privilege-escalation path")
    return "\n".join(out)


def to_markdown(subjects: list[Subject]) -> str:
    c = summary_counts(subjects)
    admins = [s for s in subjects if any(f.rule == "IAM-001" for f in s.findings)]
    escalators = [s for s in subjects if s not in admins and any(f.rule.startswith("PE-") and f.severity == "critical"
                                                                 for f in s.findings)]
    out = ["# IAM risk report", "",
           f"**{len(subjects)}** principals or policies analysed: **{c['critical']}** critical, "
           f"**{c['high']}** high, **{c['medium']}** medium findings.", "",
           f"- Full administrators: **{len(admins)}** ({', '.join(s.name for s in admins) or 'none'})",
           f"- Not admin, but can **escalate to admin**: **{len(escalators)}** "
           f"({', '.join(s.name for s in escalators) or 'none'})", "",
           "| Principal | Type | Worst | Findings | Policies |", "|---|---|---|---|---|"]
    for s in sorted(subjects, key=lambda s: SEV_RANK.get(s.worst, 9)):
        out.append(f"| {s.name} | {s.kind} | {ICON.get(s.worst, '🟢')} {s.worst or 'none'} | {len(s.findings)} | "
                   f"{'<br>'.join(s.policy_names) or '-'} |")
    for s in sorted(subjects, key=lambda s: SEV_RANK.get(s.worst, 9)):
        if not s.findings:
            continue
        out += ["", f"## {s.kind.title()}: {s.name}", ""]
        for f in s.findings:
            out += [f"### {ICON[f.severity]} {f.severity.upper()} · {f.rule} · {f.title}", "",
                    f"{f.detail}", "", f"**Permissions:** `{'`, `'.join(f.actions)}`  ", f"**Fix:** {f.remediation}", ""]
        if s.unresolved:
            out.append(f"> Note: could not read managed policy document(s): {', '.join(s.unresolved)}\n")
    return "\n".join(out)


def to_sarif(subjects: list[Subject]) -> dict:
    """SARIF 2.1.0 so findings show up in GitHub code scanning."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules, results = {}, []
    for s in subjects:
        for f in s.findings:
            rules.setdefault(f.rule, {"id": f.rule, "name": f.rule, "shortDescription": {"text": f.title},
                                      "help": {"text": f.remediation},
                                      "properties": {"security-severity": {"critical": "9.5", "high": "8.0",
                                                                           "medium": "5.5", "low": "3.0"}[f.severity]}})
            results.append({"ruleId": f.rule, "level": level[f.severity],
                            "message": {"text": f"{s.kind} {s.name}: {f.title}. {f.detail}"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": s.source}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "iam-analyzer", "informationUri":
                                          "https://github.com/meerbaloch-security/cybersec-portfolio",
                                          "rules": list(rules.values())}}, "results": results}]}


def analyse(path: Path) -> list[Subject]:
    subjects = load_subjects(path)
    for s in subjects:
        check(s)
        s.findings = dedupe(s.findings)
    return subjects


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find risky permissions and privilege-escalation paths in AWS IAM.")
    ap.add_argument("input", type=Path, help="Policy JSON, a folder of them, or get-account-authorization-details output")
    ap.add_argument("--format", choices=["text", "markdown", "json", "sarif"], default="text")
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--fail-on", choices=SEVERITIES, help="Exit 1 if any finding is at or above this severity")
    args = ap.parse_args(argv)

    subjects = analyse(args.input)
    if args.format == "markdown":
        rendered = to_markdown(subjects)
    elif args.format == "json":
        rendered = json.dumps([{"kind": s.kind, "name": s.name, "source": s.source, "policies": s.policy_names,
                                "unresolved": s.unresolved, "findings": [asdict(f) for f in s.findings]}
                               for s in subjects], indent=2)
    elif args.format == "sarif":
        rendered = json.dumps(to_sarif(subjects), indent=2)
    else:
        rendered = to_text(subjects)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(rendered)

    if args.fail_on:
        limit = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] <= limit for s in subjects for f in s.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
