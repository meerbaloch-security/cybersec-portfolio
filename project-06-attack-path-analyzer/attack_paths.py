#!/usr/bin/env python3
"""attack-paths: find how an attacker could chain small weaknesses in a cloud
environment into a breach, and which few fixes break the most chains.

Security tools usually report findings one at a time: a vulnerable package
here, an over-permissive role there, an open security group somewhere else.
Attackers don't see a list; they see a graph. This tool builds that graph
from an inventory of an AWS environment and finds every path from an entry
point (the internet, a trusted vendor account, a stale access key) to a crown
jewel (customer data, production secrets). Then it calculates the smallest
set of fixes that breaks those paths.

Pure Python standard library. Offline. Read-only.

Usage:
    python3 attack_paths.py samples/acme_environment.json
    python3 attack_paths.py samples/acme_environment.json --html report.html
    python3 attack_paths.py env.json --format json -o paths.json
    python3 attack_paths.py env.json --fail-on-paths       # CI gate: exit 1 if any path exists
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
COLUMNS = {"entry": 0, "compute": 1, "identity": 2, "privilege": 3, "data": 4}
IMPACT = {"critical": 10, "high": 7, "medium": 4, "low": 1}


@dataclass
class Node:
    id: str
    label: str
    kind: str            # entry | compute | identity | privilege | data
    detail: str = ""
    sensitivity: str | None = None   # data nodes only

    @property
    def crown_jewel(self) -> bool:
        return self.kind == "data" and self.sensitivity in {"critical", "high"}


@dataclass
class Edge:
    id: str
    src: str
    dst: str
    label: str           # short description of the step
    technique: str       # MITRE ATT&CK technique ID
    effort: int          # 1 = trivial ... 6 = hard; lower is more likely
    evidence: str        # why the tool believes this step is possible
    fix: str | None      # None = inherent step (cannot be "fixed" on its own)


@dataclass
class AttackPath:
    entry: str
    target: str
    edges: list[str]
    effort: int
    impact: int

    @property
    def likelihood(self) -> str:
        return ("Very likely" if self.effort <= 3 else "Likely" if self.effort <= 6
                else "Possible" if self.effort <= 9 else "Unlikely")

    @property
    def risk(self) -> int:
        """0-100: high impact and low effort = high risk."""
        return round(self.impact * 10 * max(0.15, 1 - (self.effort - 1) / 12))


@dataclass
class Graph:
    account_id: str
    account_name: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, src: str, dst: str, label: str, technique: str, effort: int, evidence: str,
                 fix: str | None) -> None:
        eid = f"{src}->{dst}"
        current = self.edges.get(eid)
        if current is None or effort < current.effort:  # keep the easiest way across
            self.edges[eid] = Edge(eid, src, dst, label, technique, effort, evidence, fix)

    def out(self, node_id: str, removed: set[str] = frozenset()) -> list[Edge]:
        return [e for e in self.edges.values() if e.src == node_id and e.id not in removed]


# --------------------------------------------------------------------------- #
# Minimal IAM evaluation (same semantics as Project 04: wildcards, NotAction,
# unconditional Deny). Resource ARNs are matched with AWS-style wildcards.
# --------------------------------------------------------------------------- #
def _list(v) -> list:
    return [] if v is None else v if isinstance(v, list) else [v]


def _match(patterns, value: str, case_insensitive: bool = False) -> bool:
    if case_insensitive:
        return any(fnmatch.fnmatchcase(value.lower(), p.lower()) for p in _list(patterns))
    return any(fnmatch.fnmatchcase(value, p) for p in _list(patterns))


def _covers(stmt: dict, action: str, resource: str) -> bool:
    if "NotAction" in stmt:
        act = not _match(stmt["NotAction"], action, True)
    else:
        act = _match(stmt.get("Action"), action, True)
    if not act:
        return False
    if "NotResource" in stmt:
        return not _match(stmt["NotResource"], resource)
    return _match(stmt.get("Resource", "*"), resource)


def allowed(statements: list[dict], action: str, resource: str = "*") -> bool:
    for s in statements:
        if s.get("Effect") == "Deny" and not s.get("Condition") and _covers(s, action, resource):
            return False
    return any(s.get("Effect") == "Allow" and _covers(s, action, resource) for s in statements)


def allowed_on_any(statements: list[dict], action: str) -> bool:
    """True if the action is allowed on every resource (Resource '*')."""
    return any(s.get("Effect") == "Allow" and _covers(s, action, "*") and
               ("NotResource" in s or "*" in _list(s.get("Resource", "*"))) for s in statements) \
        and allowed(statements, action, "*")


# Privilege escalation to account admin (subset of Project 04's 21 paths that
# lead directly to admin when granted on all resources).
ESCALATION = [
    (["iam:CreatePolicyVersion"], "Publish an admin version of its own policy"),
    (["iam:AttachRolePolicy"], "Attach AdministratorAccess to its own role"),
    (["iam:AttachUserPolicy"], "Attach AdministratorAccess to itself"),
    (["iam:PutRolePolicy"], "Write an admin inline policy on its own role"),
    (["iam:PutUserPolicy"], "Write an admin inline policy on itself"),
    (["iam:PassRole", "ec2:RunInstances"], "Launch an instance with an admin role"),
    (["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Run a Lambda function with an admin role"),
    (["iam:PassRole", "cloudformation:CreateStack"], "Deploy a stack with an admin role"),
]


# --------------------------------------------------------------------------- #
# Building the graph from an inventory
# --------------------------------------------------------------------------- #
def build_graph(inv: dict) -> Graph:
    acct = inv["account"]["id"]
    region = inv["account"].get("region", "us-east-1")
    g = Graph(acct, inv["account"].get("name", acct))

    role_arn = lambda n: f"arn:aws:iam::{acct}:role/{n}"          # noqa: E731
    user_arn = lambda n: f"arn:aws:iam::{acct}:user/{n}"          # noqa: E731

    def compute_arn(c: dict) -> str:
        if c["type"] == "lambda":
            return f"arn:aws:lambda:{region}:{acct}:function:{c['name']}"
        return f"arn:aws:ec2:{region}:{acct}:instance/{c['id']}"

    roles = {r["name"]: r for r in inv.get("roles", [])}
    users = {u["name"]: u for u in inv.get("users", [])}
    principals = {**{f"role:{n}": r["statements"] for n, r in roles.items()},
                  **{f"user:{n}": u["statements"] for n, u in users.items()}}

    g.add_node(Node("internet", "Internet", "entry", "Anyone on the internet"))
    g.add_node(Node("admin", "Account administrator", "privilege", "Full control of the AWS account"))

    for n in roles:
        g.add_node(Node(f"role:{n}", n, "identity", "IAM role"))
    for n in users:
        g.add_node(Node(f"user:{n}", n, "identity", "IAM user"))
    for d in inv.get("data", []):
        g.add_node(Node(f"data:{d['name']}", d["name"], "data", d.get("contains", d["type"]), d.get("sensitivity", "low")))

    # 1. Initial access: internet-exposed compute with an exploitable weakness
    for c in inv.get("compute", []):
        cid = f"compute:{c['name']}"
        g.add_node(Node(cid, c["name"], "compute", f"{c['type'].upper()}" + (" · public" if c.get("public") else "")))
        if c.get("public"):
            for exp in c.get("exposure", []):
                if exp.get("source") not in {"0.0.0.0/0", "::/0", "public"}:
                    continue
                best, exploitable = None, []
                for sw in c.get("software", []):
                    for cve in sw.get("cves", []):
                        if not cve.get("remote", True):
                            continue
                        effort = (1 if cve.get("kev") else 2 if cve.get("epss", 0) >= 0.10
                                  else 4 if cve.get("cvss", 0) >= 9.0 else None)
                        if effort:
                            exploitable.append(f"{sw['package']} to {cve.get('fixed_in', 'a fixed version')}")
                            if best is None or effort < best[0]:
                                best = (effort, sw, cve)
                if best:
                    effort, sw, cve = best
                    upgrades = " and ".join(dict.fromkeys(exploitable))
                    why = ("in CISA KEV (exploited in the wild)" if cve.get("kev")
                           else f"EPSS {cve.get('epss', 0):.0%}" if cve.get("epss", 0) >= 0.10
                           else f"CVSS {cve.get('cvss')}")
                    g.add_edge("internet", cid, f"Exploit {cve['id']} in {sw['package']} {sw['version']}", "T1190",
                               effort, f"{exp.get('service', 'service')} on port {exp['port']} open to the internet; "
                               f"{cve['id']} {why}",
                               f"Upgrade {upgrades} on {c['name']}"
                               + (f" ({len(exploitable)} exploitable CVEs)" if len(exploitable) > 1 else "")
                               + f", or remove internet access to port {exp['port']}")
                elif exp["port"] in {22, 3389} and c.get("password_auth"):
                    g.add_edge("internet", cid, f"Brute-force {'SSH' if exp['port'] == 22 else 'RDP'} password",
                               "T1110", 6, f"Port {exp['port']} open to the internet with password login enabled",
                               f"Close port {exp['port']} to the internet; use SSM Session Manager and key-only auth")

        # 2. Code on the instance or function can use its role's credentials
        if c.get("role"):
            how = ("instance metadata service (IMDSv1 also allows SSRF theft)" if c.get("imds_v1")
                   else "instance metadata service" if c["type"] == "ec2" else "function environment")
            g.add_edge(cid, f"role:{c['role']}", "Use the attached role's credentials", "T1552.005", 1,
                       f"{c['name']} runs as role {c['role']}; credentials available from the {how}", None)

    # 3. Other entry points
    for n, r in roles.items():
        for t in r.get("trust", []):
            p = t.get("principal", "")
            if p.startswith("account:") and p != f"account:{acct}" and not t.get("external_id"):
                ext = f"external:{p.split(':', 1)[1]}"
                g.add_node(Node(ext, "Vendor account", "entry", f"Third-party AWS account {p.split(':', 1)[1]}"))
                g.add_edge(ext, f"role:{n}", "Assume role trusted by a third party", "T1199", 4,
                           f"Role {n} trusts the whole account {p.split(':', 1)[1]} with no ExternalId condition; "
                           "a compromise of that vendor (or a confused deputy) reaches this account",
                           f"Add an sts:ExternalId condition to {n}'s trust policy and trust a specific role ARN")
    for n, u in users.items():
        stale = [k for k in u.get("access_keys", []) if k.get("age_days", 0) > 90]
        if stale and not u.get("mfa"):
            g.add_node(Node("leaked-key", "Leaked access key", "entry", "Key leaked in code or logs"))
            g.add_edge("leaked-key", f"user:{n}", "Use a leaked long-lived access key", "T1078.004", 5,
                       f"{n} has an access key {stale[0]['age_days']} days old and no MFA",
                       f"Rotate and remove {n}'s access key; use short-lived credentials (OIDC / IAM roles)")

    # 4. Identity-to-identity, lateral movement, escalation and data access
    computes = {c["name"]: c for c in inv.get("compute", [])}
    for pid, stmts in principals.items():
        # assume other roles
        for n, r in roles.items():
            if pid == f"role:{n}":
                continue
            trusted = any(t.get("principal") in {pid, f"account:{acct}"} for t in r.get("trust", []))
            if trusted and allowed(stmts, "sts:AssumeRole", role_arn(n)):
                g.add_edge(pid, f"role:{n}", f"Assume role {n}", "T1078.004", 1,
                           f"{pid.split(':', 1)[1]} may call sts:AssumeRole on {n}, and {n}'s trust policy allows it",
                           f"Remove {pid.split(':', 1)[1]} from {n}'s trust policy, or narrow its sts:AssumeRole permission")
        # lateral movement into compute that runs with other roles
        for cname, c in computes.items():
            arn = compute_arn(c)
            if c["type"] == "ec2" and allowed(stmts, "ssm:SendCommand", arn):
                g.add_edge(pid, f"compute:{cname}", f"Run commands on {cname} via SSM", "T1651", 1,
                           f"{pid.split(':', 1)[1]} may call ssm:SendCommand on {cname}",
                           f"Scope ssm:SendCommand for {pid.split(':', 1)[1]} to specific instances or tags")
            if c["type"] == "lambda" and allowed(stmts, "lambda:UpdateFunctionCode", arn):
                g.add_edge(pid, f"compute:{cname}", f"Replace the code of {cname}", "T1648", 1,
                           f"{pid.split(':', 1)[1]} may call lambda:UpdateFunctionCode on {cname}",
                           f"Remove lambda:UpdateFunctionCode from {pid.split(':', 1)[1]}; deploy through a pipeline")
        # escalation to admin
        if allowed_on_any(stmts, "*") and allowed_on_any(stmts, "iam:AttachRolePolicy"):
            g.add_edge(pid, "admin", "Already an administrator", "T1078.004", 0,
                       f"{pid.split(':', 1)[1]} has full administrator permissions",
                       f"Replace {pid.split(':', 1)[1]}'s admin access with least-privilege permissions")
        else:
            for actions, how in ESCALATION:
                if all(allowed_on_any(stmts, a) for a in actions):
                    g.add_edge(pid, "admin", f"Escalate: {how}", "T1098", 2,
                               f"{pid.split(':', 1)[1]} has {' + '.join(actions)} on all resources",
                               f"Remove or scope {' + '.join(actions)} for {pid.split(':', 1)[1]}")
                    break
        # data access
        for d in inv.get("data", []):
            action, res = data_action(d)
            if any(allowed(stmts, action, r) for r in data_probes(d, stmts, res)):
                g.add_edge(pid, f"data:{d['name']}", f"Read {d['name']}", "T1530", 1,
                           f"{pid.split(':', 1)[1]} may call {action} on {d['name']}",
                           f"Remove {action} on {d['name']} from {pid.split(':', 1)[1]} if it is not needed")

    # Admins can read everything
    for d in inv.get("data", []):
        g.add_edge("admin", f"data:{d['name']}", f"Read {d['name']}", "T1530", 1, "Administrators can access all data", None)

    # Drop nodes nothing connects to (keeps the picture readable)
    used = {e.src for e in g.edges.values()} | {e.dst for e in g.edges.values()}
    g.nodes = {k: v for k, v in g.nodes.items() if k in used}
    return g


def data_probes(d: dict, stmts: list[dict], default: str) -> list[str]:
    """Resources to test. For S3, access to any prefix of the bucket counts
    (reading exports/* of a customer bucket is still a breach)."""
    probes = [default]
    if d["type"] == "s3":
        bucket = f"arn:aws:s3:::{d['name']}/"
        for st in stmts:
            for r in _list(st.get("Resource")):
                if r.startswith(bucket):
                    probes.append(r.replace("*", "x"))
    return probes


def data_action(d: dict) -> tuple[str, str]:
    if d["type"] == "s3":
        return "s3:GetObject", f"arn:aws:s3:::{d['name']}/sample-object"
    if d["type"] == "secret":
        return "secretsmanager:GetSecretValue", d["arn"]
    if d["type"] == "dynamodb":
        return "dynamodb:Scan", d["arn"]
    return "unknown:Read", d.get("arn", "*")


# --------------------------------------------------------------------------- #
# Path search and fix planning
# --------------------------------------------------------------------------- #
MAX_DEPTH = 8


def find_paths(g: Graph, removed: set[str] = frozenset()) -> list[AttackPath]:
    """All simple paths from entry points to crown jewels."""
    paths: list[AttackPath] = []
    entries = [n for n in g.nodes.values() if n.kind == "entry"]

    def dfs(node: str, visited: set[str], trail: list[Edge], entry: str) -> None:
        if len(trail) > MAX_DEPTH:
            return
        n = g.nodes[node]
        if n.crown_jewel and trail:
            paths.append(AttackPath(entry, node, [e.id for e in trail], sum(e.effort for e in trail),
                                    IMPACT[n.sensitivity]))
            return
        for e in g.out(node, removed):
            if e.dst not in visited:
                dfs(e.dst, visited | {e.dst}, trail + [e], entry)

    for en in entries:
        dfs(en.id, {en.id}, [], en.id)
    paths.sort(key=lambda p: (-p.risk, p.effort, len(p.edges)))
    return paths


def plan_fixes(g: Graph, paths: list[AttackPath]) -> list[dict]:
    """Greedy choke-point analysis: repeatedly pick the fixable step that sits
    on the most remaining attack paths (weighted by risk), until none remain."""
    remaining = list(paths)
    plan: list[dict] = []
    total = len(paths)
    total_risk = sum(p.risk for p in paths) or 1
    while remaining:
        score: dict[str, float] = {}
        position: dict[str, int] = {}
        for p in remaining:
            for i, eid in enumerate(p.edges):
                if g.edges[eid].fix:
                    score[eid] = score.get(eid, 0) + p.risk
                    position[eid] = min(position.get(eid, 99), i)
        if not score:
            break
        # Most risk removed first; on a tie, cut closest to the entry point.
        best = max(score, key=lambda k: (score[k], -position[k]))
        broken = [p for p in remaining if best in p.edges]
        remaining = [p for p in remaining if best not in p.edges]
        plan.append({"edge": best, "fix": g.edges[best].fix, "paths_broken": len(broken),
                     "cumulative_pct": round(100 * (total - len(remaining)) / total),
                     "risk_removed_pct": round(100 * (total_risk - sum(p.risk for p in remaining)) / total_risk)})
    return plan


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def summarise(g: Graph, paths: list[AttackPath], plan: list[dict]) -> dict:
    jewels = sorted({p.target for p in paths})
    return {
        "account": f"{g.account_name} ({g.account_id})",
        "nodes": len(g.nodes), "edges": len(g.edges),
        "attack_paths": len(paths),
        "crown_jewels_reachable": [g.nodes[j].label for j in jewels],
        "entry_points": sorted({g.nodes[p.entry].label for p in paths}),
        "easiest_path_steps": min((len(p.edges) for p in paths), default=0),
        "fixes_to_break_all": len(plan),
        "fixes_for_80pct": next((i + 1 for i, f in enumerate(plan) if f["cumulative_pct"] >= 80), len(plan)),
        "risk_removed_by_top3": plan[min(2, len(plan) - 1)]["risk_removed_pct"] if plan else 0,
    }


def describe(g: Graph, p: AttackPath) -> str:
    chain = [g.nodes[p.entry].label] + [g.nodes[g.edges[e].dst].label for e in p.edges]
    return " → ".join(chain)


def to_text(g: Graph, paths: list[AttackPath], plan: list[dict]) -> str:
    s = summarise(g, paths, plan)
    out = [f"Environment: {s['account']}  ({s['nodes']} assets, {s['edges']} possible attacker moves)",
           f"Found {s['attack_paths']} attack paths to {len(s['crown_jewels_reachable'])} crown jewels "
           f"({', '.join(s['crown_jewels_reachable'])})",
           f"Entry points: {', '.join(s['entry_points'])}", ""]
    for i, p in enumerate(paths, 1):
        out.append(f"#{i:<3} risk {p.risk:>3}  {p.likelihood:<11}  {describe(g, p)}")
        for e in p.edges:
            ed = g.edges[e]
            out.append(f"        - [{ed.technique}] {ed.label}")
    out += ["", f"Fix plan: {s['fixes_to_break_all']} changes break every path "
                f"({s['fixes_for_80pct']} break at least 80%)"]
    for i, f in enumerate(plan, 1):
        out.append(f"  {i}. {f['fix']}  -> breaks {f['paths_broken']} path(s); "
                   f"{f['cumulative_pct']}% of paths and {f['risk_removed_pct']}% of risk removed so far")
    return "\n".join(out)


def to_markdown(g: Graph, paths: list[AttackPath], plan: list[dict]) -> str:
    s = summarise(g, paths, plan)
    out = [f"# Attack path report: {s['account']}", "",
           f"**{s['attack_paths']} attack paths** reach **{len(s['crown_jewels_reachable'])} crown jewels** "
           f"from {len(s['entry_points'])} entry points. The shortest takes **{s['easiest_path_steps']} steps**.", "",
           f"**{s['fixes_for_80pct']} fixes break at least 80% of paths; {s['fixes_to_break_all']} break all of them.**", "",
           "## Fix plan (highest impact first)", "",
           "| # | Fix | Paths broken | Paths removed so far | Risk removed so far |", "|---|---|---|---|---|"]
    out += [f"| {i} | {f['fix']} | {f['paths_broken']} | {f['cumulative_pct']}% | {f['risk_removed_pct']}% |"
            for i, f in enumerate(plan, 1)]
    out += ["", "## Attack paths", ""]
    for i, p in enumerate(paths, 1):
        out += [f"### #{i} · risk {p.risk} · {p.likelihood} · {g.nodes[p.target].label}", "",
                f"**{describe(g, p)}**", "", "| Step | ATT&CK | Evidence |", "|---|---|---|"]
        out += [f"| {g.edges[e].label} | {g.edges[e].technique} | {g.edges[e].evidence} |" for e in p.edges]
        out.append("")
    return "\n".join(out)


def to_json(g: Graph, paths: list[AttackPath], plan: list[dict]) -> dict:
    return {"summary": summarise(g, paths, plan),
            "nodes": [asdict(n) | {"crown_jewel": n.crown_jewel} for n in g.nodes.values()],
            "edges": [asdict(e) for e in g.edges.values()],
            "paths": [asdict(p) | {"risk": p.risk, "likelihood": p.likelihood, "description": describe(g, p)}
                      for p in paths],
            "fix_plan": plan}


def analyse(inv: dict) -> tuple[Graph, list[AttackPath], list[dict]]:
    g = build_graph(inv)
    paths = find_paths(g)
    return g, paths, plan_fixes(g, paths)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find attack paths to crown jewels in a cloud inventory.")
    ap.add_argument("inventory", type=Path)
    ap.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--html", type=Path, help="Also write the interactive HTML report")
    ap.add_argument("--fail-on-paths", action="store_true", help="Exit 1 if any attack path exists")
    args = ap.parse_args(argv)

    inv = json.loads(args.inventory.read_text(encoding="utf-8"))
    g, paths, plan = analyse(inv)

    if args.format == "json":
        rendered = json.dumps(to_json(g, paths, plan), indent=2)
    elif args.format == "markdown":
        rendered = to_markdown(g, paths, plan)
    else:
        rendered = to_text(g, paths, plan)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(rendered)

    if args.html:
        from html_report import render  # local module
        args.html.write_text(render(to_json(g, paths, plan)), encoding="utf-8")
        print(f"Wrote {args.html}")

    return 1 if args.fail_on_paths and paths else 0


if __name__ == "__main__":
    sys.exit(main())
