"""A small, dependency-light Sigma rule engine.

Implements the parts of the Sigma specification (https://sigmahq.io) that
SOC detection rules use most:

* logsource matching (product / service / category)
* selections as maps (AND of fields) or lists of maps (OR)
* value lists (OR), wildcards (* ?), case-insensitive matching
* modifiers: contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte, windash
* keyword lists (search any field)
* conditions with and / or / not / parentheses, "1 of sel*", "all of sel*", "1 of them"

Rules are plain Sigma YAML, so they can be converted for Splunk or Microsoft
Sentinel with the official pySigma tooling.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Rule:
    id: str
    title: str
    level: str
    status: str
    description: str
    logsource: dict
    detection: dict
    condition: str
    tags: list[str]
    falsepositives: list[str]
    path: str
    fields: list[str] = field(default_factory=list)
    custom: dict = field(default_factory=dict)  # non-standard keys, e.g. risk scoring

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t)]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags
                if t.startswith("attack.") and not re.match(r"attack\.[tgs]\d{4}", t)]


def load_rule(path: Path) -> Rule:
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    det = dict(d["detection"])
    cond = det.pop("condition")
    known = {"title", "id", "status", "description", "logsource", "detection", "tags", "falsepositives",
             "level", "author", "date", "modified", "references", "fields", "related"}
    return Rule(d["id"], d["title"], d.get("level", "medium"), d.get("status", "experimental"),
                d.get("description", ""), d.get("logsource", {}), det, cond if isinstance(cond, str) else cond[0],
                d.get("tags", []), d.get("falsepositives", []), str(path), d.get("fields", []),
                {k: v for k, v in d.items() if k not in known})


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #
def _windash(v: str) -> list[str]:
    # Windows command-line flags work with '-' or '/', so match both.
    return [v, v.replace("-", "/")] if "-" in v else [v, v.replace("/", "-")] if "/" in v else [v]


def _match_value(actual, expected, mods: list[str]) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        try:
            a, x = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > x, "gte": a >= x, "lt": a < x, "lte": a <= x}[next(m for m in mods if m in ("gt", "gte", "lt", "lte"))]
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    a = str(actual)
    if "re" in mods:
        return re.search(str(expected), a) is not None
    a = a.lower()
    candidates = _windash(str(expected).lower()) if "windash" in mods else [str(expected).lower()]
    for x in candidates:
        if "contains" in mods:
            if x in a:
                return True
        elif "startswith" in mods:
            if a.startswith(x):
                return True
        elif "endswith" in mods:
            if a.endswith(x):
                return True
        elif "*" in x or "?" in x:
            if fnmatch.fnmatchcase(a, x):
                return True
        elif a == x:
            return True
    return False


def _match_field(event: dict, key: str, expected) -> bool:
    name, *mods = key.split("|")
    actual = event.get(name)
    values = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(_match_value(actual, v, mods) for v in values)
    return any(_match_value(actual, v, mods) for v in values)


def _match_selection(event: dict, sel) -> bool:
    if isinstance(sel, dict):
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return any(_match_selection(event, x) for x in sel)
        # keyword search: any value of any field contains the keyword
        hay = " ".join(str(v) for k, v in event.items() if not k.startswith("_")).lower()
        return any(str(kw).lower() in hay for kw in sel)
    return False


# --------------------------------------------------------------------------- #
# Condition parsing (recursive descent)
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokens(cond: str) -> list[str]:
    pos, out = 0, []
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise ValueError(f"bad condition near: {cond[pos:]}")
        out.append(m.group(1))
        pos = m.end()
    return out


def evaluate_condition(cond: str, results: dict[str, bool]) -> bool:
    toks = _tokens(cond)
    i = 0

    def peek():
        return toks[i].lower() if i < len(toks) else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def names(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            return [k for k in results if not k.startswith("_")]
        return [k for k in results if fnmatch.fnmatchcase(k, pattern)]

    def primary() -> bool:
        t = peek()
        if t == "(":
            take()
            v = expr()
            take()  # ')'
            return v
        if t == "not":
            take()
            return not primary()
        if t in ("1", "all", "any"):
            quant = take().lower()
            if peek() == "of":
                take()
                group = [results[n] for n in names(take())]
                return all(group) if quant == "all" else any(group)
            raise ValueError("expected 'of'")
        name = take()
        if name not in results:
            raise ValueError(f"unknown selection '{name}'")
        return results[name]

    def term() -> bool:
        v = primary()
        while peek() == "and":
            take()
            rhs = primary()
            v = v and rhs
        return v

    def expr() -> bool:
        v = term()
        while peek() == "or":
            take()
            rhs = term()
            v = v or rhs
        return v

    return expr()


def logsource_matches(rule: Rule, event: dict) -> bool:
    ls = event.get("_logsource", {})
    return all(str(ls.get(k, "")).lower() == str(v).lower() for k, v in rule.logsource.items()
               if k in ("product", "service", "category"))


def matches(rule: Rule, event: dict) -> bool:
    if not logsource_matches(rule, event):
        return False
    results = {name: _match_selection(event, sel) for name, sel in rule.detection.items()}
    return evaluate_condition(rule.condition, results)


def load_rules(folder: Path) -> list[Rule]:
    return [load_rule(p) for p in sorted(folder.glob("*.yml"))]
