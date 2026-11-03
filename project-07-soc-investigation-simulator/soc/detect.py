"""Detection pipeline: Sigma rules -> alerts, plus Sigma correlation rules.

Correlation rules follow the Sigma correlation specification
(https://github.com/SigmaHQ/sigma-specification), supporting:

* event_count      N or more matching events per group within a timespan
* value_count      N or more distinct values of a field per group within a timespan
* temporal_ordered rule A, then rule B (then ...) for the same group within a timespan

Correlations can reference detection rules or other correlations, so
"brute force" -> "brute force followed by a successful logon" works as a chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .sigma import Rule, load_rule, matches

RISK_BY_LEVEL = {"informational": 0, "low": 10, "medium": 25, "high": 45, "critical": 80}


@dataclass
class Alert:
    id: str
    rule_name: str
    rule_id: str
    title: str
    level: str
    risk: int
    techniques: list[str]
    tactics: list[str]
    time: datetime
    end: datetime
    events: list[dict]
    group: dict = field(default_factory=dict)
    building_block: bool = False
    correlation: str | None = None

    @property
    def first(self) -> dict:
        return self.events[0]


@dataclass
class Correlation:
    id: str
    name: str
    title: str
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: timedelta
    condition: dict
    level: str
    tags: list[str]
    risk: int
    description: str
    path: str

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t)]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags if t.startswith("attack.") and not re.match(r"attack\.[tgs]\d{4}", t)]


def parse_timespan(s: str) -> timedelta:
    n, unit = int(s[:-1]), s[-1]
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


def load_correlation(path: Path) -> Correlation:
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    c = d["correlation"]
    return Correlation(d["id"], d.get("name", d["id"]), d["title"], c["type"], c["rules"], c.get("group-by", []),
                       parse_timespan(c["timespan"]), c.get("condition", {}), d.get("level", "medium"),
                       d.get("tags", []), d.get("risk_score", RISK_BY_LEVEL[d.get("level", "medium")]),
                       d.get("description", ""), str(path))


def rule_risk(rule: Rule) -> int:
    return int(rule.custom.get("risk_score", RISK_BY_LEVEL.get(rule.level, 25)))


def _dedupe_key(rule: Rule, e: dict) -> tuple:
    # Sysmon 1 and Security 4688 describe the same process start: alert once.
    detail = e.get("CommandLine") or e.get("TargetObject") or e.get("TargetImage") or e.get("_id")
    return rule.id, str(e.get("Hostname", "")).split(".")[0].lower(), str(detail).lower()


def run_rules(rules: list[Rule], events: list[dict]) -> dict[str, list[Alert]]:
    """Return alerts per rule name (building blocks included, flagged)."""
    out: dict[str, list[Alert]] = {}
    for rule in rules:
        alerts: list[Alert] = []
        recent: dict[tuple, Alert] = {}
        for e in events:
            if not matches(rule, e):
                continue
            key = _dedupe_key(rule, e)
            prev = recent.get(key)
            same_process = e.get("_pid") is not None and prev is not None and prev.first.get("_pid") == e.get("_pid")
            if prev and not rule.custom.get("building_block") and (same_process or (e["_time"] - prev.end) <= timedelta(seconds=5)):
                prev.events.append(e)
                prev.end = e["_time"]
                continue
            a = Alert(f"{rule.custom.get('name', rule.id)}:{e['_id']}", rule.custom.get("name", rule.id), rule.id,
                      rule.title, rule.level, rule_risk(rule), rule.techniques, rule.tactics,
                      e["_time"], e["_time"], [e], building_block=bool(rule.custom.get("building_block")))
            alerts.append(a)
            recent[key] = a
        out[a.rule_name if alerts else rule.custom.get("name", rule.id)] = alerts
    return out


def _group_key(group_by: list[str], item: Alert) -> tuple | None:
    vals = []
    for f in group_by:
        v = item.group.get(f, item.first.get(f))
        if v in (None, "", "-"):
            return None
        vals.append(str(v).lower())
    return tuple(vals)


def _make(c: Correlation, items: list[Alert], key: tuple) -> Alert:
    events = [e for it in items for e in it.events]
    return Alert(f"{c.name}:{items[0].id}", c.name, c.id, c.title, c.level, c.risk, c.techniques, c.tactics,
                 items[0].time, items[-1].end, events, dict(zip(c.group_by, key)), correlation=c.type)


def run_correlation(c: Correlation, inputs: dict[str, list[Alert]]) -> list[Alert]:
    out: list[Alert] = []
    if c.type in ("event_count", "value_count"):
        items = sorted((a for r in c.rules for a in inputs.get(r, [])), key=lambda a: a.time)
        groups: dict[tuple, list[Alert]] = {}
        for it in items:
            k = _group_key(c.group_by, it)
            if k is not None:
                groups.setdefault(k, []).append(it)
        threshold = int(c.condition.get("gte", c.condition.get("gt", 0) + 1))
        for k, its in groups.items():
            start = 0
            emitted_until = None
            for end in range(len(its)):
                while its[end].time - its[start].time > c.timespan:
                    start += 1
                window = its[start:end + 1]
                if c.type == "event_count":
                    n = len(window)
                else:
                    n = len({str(w.first.get(c.condition["field"], "")).lower() for w in window})
                if n >= threshold and (emitted_until is None or its[end].time > emitted_until):
                    # extend to every event inside the window so the alert carries full evidence
                    j = end
                    while j + 1 < len(its) and its[j + 1].time - its[start].time <= c.timespan:
                        j += 1
                    window = its[start:j + 1]
                    out.append(_make(c, window, k))
                    emitted_until = window[-1].time + c.timespan
    elif c.type == "temporal_ordered":
        per_rule = [{} for _ in c.rules]
        for i, r in enumerate(c.rules):
            for a in inputs.get(r, []):
                k = _group_key(c.group_by, a)
                if k is not None:
                    per_rule[i].setdefault(k, []).append(a)
        for k in per_rule[0]:
            for first in sorted(per_rule[0][k], key=lambda a: a.time):
                chain, cursor = [first], first.end
                for nxt in per_rule[1:]:
                    cand = [a for a in sorted(nxt.get(k, []), key=lambda a: a.time)
                            if a.time >= cursor and a.time - first.time <= c.timespan]
                    if not cand:
                        break
                    chain.append(cand[0])
                    cursor = cand[0].end
                if len(chain) == len(c.rules):
                    out.append(_make(c, chain, k))
                    break  # one alert per group is enough
    else:
        raise ValueError(f"unsupported correlation type {c.type}")
    return out


def detect(rules: list[Rule], correlations: list[Correlation], events: list[dict]) -> list[Alert]:
    by_name = run_rules(rules, events)
    pending = list(correlations)
    while pending:  # resolve correlations whose inputs are ready (they may chain)
        ready = [c for c in pending if all(r in by_name for r in c.rules)]
        if not ready:
            missing = {r for c in pending for r in c.rules if r not in by_name}
            raise ValueError(f"correlation rules reference unknown rules: {sorted(missing)}")
        for c in ready:
            by_name[c.name] = run_correlation(c, by_name)
            pending.remove(c)
    alerts = [a for lst in by_name.values() for a in lst if not a.building_block]
    return sorted(alerts, key=lambda a: a.time)


def load_all(rule_dir: Path, include_deprecated: bool = False) -> tuple[list[Rule], list[Correlation]]:
    rules = [load_rule(p) for p in sorted((rule_dir / "detection").glob("*.yml"))]
    if include_deprecated:
        rules += [load_rule(p) for p in sorted((rule_dir / "deprecated").glob("*.yml"))]
    corrs = [load_correlation(p) for p in sorted((rule_dir / "correlation").glob("*.yml"))]
    return rules, corrs
