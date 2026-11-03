"""Validate detection rules against real recorded attack telemetry.

Each OTRF dataset records one atomic attack technique together with the
normal background activity of the lab machine (Wireshark, monitoring agents,
the search indexer, LSASS housekeeping...). That gives two checks:

* detection: does the rule written for a technique fire on its dataset?
* false positives: does any rule fire on a dataset recording a *different*
  technique? Those alerts are false positives on real-world noise.

Alerts on a rule's own dataset were reviewed by hand to confirm they are the
recorded attack (see README).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .detect import load_all, run_rules
from .events import load_otrf_zip

# Which rule(s) each dataset is expected to trigger
EXPECTED = {
    "empire_shell_net_localgroup_administrators": {"net_localgroup_admins"},
    "psh_lsass_memory_dump_comsvcs": {"lsass_dump_comsvcs", "lsass_process_access"},
    "empire_shell_reg_dump_sam": {"reg_save_sensitive_hive"},
    "schtask_create": {"schtasks_create_from_shell"},
    "empire_persistence_registry_modification_run_keys_elevated_user": {"run_key_persistence", "run_key_naive"},
}

TECHNIQUE = {
    "empire_shell_net_localgroup_administrators": "T1069.001 Local group discovery",
    "psh_lsass_memory_dump_comsvcs": "T1003.001 LSASS memory dump",
    "empire_shell_reg_dump_sam": "T1003.002 SAM hive export",
    "schtask_create": "T1053.005 Scheduled task",
    "empire_persistence_registry_modification_run_keys_elevated_user": "T1547.001 Run key persistence",
}


@dataclass
class Cell:
    rule: str
    dataset: str
    alerts: int
    expected: bool
    samples: list[str]

    @property
    def kind(self) -> str:
        if self.expected:
            return "TP" if self.alerts else "FN"
        return "FP" if self.alerts else "TN"


def validate(dataset_dir: Path, rule_dir: Path) -> dict:
    rules, _ = load_all(rule_dir, include_deprecated=True)
    rule_names = [r.custom.get("name", r.id) for r in rules if not r.custom.get("building_block")]
    status = {r.custom.get("name", r.id): r.status for r in rules}
    cells: list[Cell] = []
    datasets = []
    for z in sorted(dataset_dir.glob("*.zip")):
        events = load_otrf_zip(z)
        datasets.append({"name": z.stem, "events": len(events), "technique": TECHNIQUE.get(z.stem, "?"),
                         "hosts": sorted({str(e.get("Hostname")) for e in events if e.get("Hostname")})})
        res = run_rules(rules, events)
        for name in rule_names:
            alerts = res.get(name, [])
            samples = [str(a.first.get("CommandLine") or a.first.get("TargetObject") or
                           f"{a.first.get('SourceImage')} -> {a.first.get('TargetImage')}")[:140] for a in alerts[:3]]
            cells.append(Cell(name, z.stem, len(alerts), name in EXPECTED.get(z.stem, set()), samples))

    def summary(names: list[str]) -> dict:
        cs = [c for c in cells if c.rule in names]
        return {"detected": sum(1 for c in cs if c.kind == "TP"), "expected": sum(1 for c in cs if c.expected),
                "false_positive_alerts": sum(c.alerts for c in cs if c.kind == "FP"),
                "missed": sum(1 for c in cs if c.kind == "FN")}

    active = [n for n in rule_names if status[n] != "deprecated"]
    return {
        "datasets": datasets,
        "total_events": sum(d["events"] for d in datasets),
        "cells": [c.__dict__ | {"kind": c.kind} for c in cells],
        "rules": rule_names,
        "status": status,
        "active": summary(active),
        "naive_run_key": summary(["run_key_naive"]),
        "tuned_run_key": summary(["run_key_persistence"]),
    }


def to_markdown(v: dict) -> str:
    short = {d["name"]: d["technique"].split(" ", 1)[0] for d in v["datasets"]}
    out = ["# Detection validation on real attack telemetry", "",
           f"{len(v['datasets'])} OTRF Security-Datasets, {v['total_events']:,} real Windows events.", "",
           f"**Active rules: {v['active']['detected']}/{v['active']['expected']} expected detections, "
           f"{v['active']['false_positive_alerts']} false-positive alerts, {v['active']['missed']} missed.**", "",
           "| Rule | " + " | ".join(short[d["name"]] for d in v["datasets"]) + " |",
           "|---|" + "---|" * len(v["datasets"])]
    for r in v["rules"]:
        row = []
        for d in v["datasets"]:
            c = next(x for x in v["cells"] if x["rule"] == r and x["dataset"] == d["name"])
            row.append({"TP": f"✅ {c['alerts']}", "FP": f"❌ {c['alerts']} FP", "FN": "⚠️ missed", "TN": "·"}[c["kind"]])
        label = r + (" *(deprecated)*" if v["status"][r] == "deprecated" else "")
        out.append(f"| {label} | " + " | ".join(row) + " |")
    out += ["", "Columns: " + "; ".join(f"{short[d['name']]} = {d['technique']} ({d['events']} events)" for d in v["datasets"])]
    return "\n".join(out)
