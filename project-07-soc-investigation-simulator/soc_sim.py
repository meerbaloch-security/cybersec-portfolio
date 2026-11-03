#!/usr/bin/env python3
"""soc-sim: a miniature SOC, from raw telemetry to incident reports.

Commands:
    python3 soc_sim.py run        # scenarios -> alerts -> incidents -> reports + analyst console
    python3 soc_sim.py validate   # test the detection rules on real OTRF attack telemetry
    python3 soc_sim.py rules      # list rules with their ATT&CK mapping
    python3 soc_sim.py all        # validate + run (what CI does)

Outputs go to ./output/: incident reports (Markdown), incidents.json,
validation.md and the interactive console (soc_console.html).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from soc.detect import detect, load_all
from soc.evaluate import evaluate
from soc.events import load_jsonl
from soc.incidents import enrich, investigate, load_threat_intel
from soc.report import incident_json, incident_markdown
from soc.validate import to_markdown as validation_markdown
from soc.validate import validate

ROOT = Path(__file__).parent
RULES = ROOT / "rules"
SCEN = ROOT / "datasets" / "scenarios"
OTRF = ROOT / "datasets" / "otrf"


def run_scenarios(out: Path, quiet: bool = False) -> dict:
    events = load_jsonl(SCEN / "harbor_pine_2026-10-27.jsonl")
    enrich(events, load_threat_intel(SCEN / "threat_intel.csv"))
    rules, corrs = load_all(RULES)
    alerts = detect(rules, corrs, events)
    ctx = json.loads((SCEN / "context.json").read_text(encoding="utf-8"))
    incidents = investigate(alerts, events, ctx)
    labels = json.loads((SCEN / "labels.json").read_text(encoding="utf-8"))
    score = evaluate(alerts, incidents, labels)

    rep = out / "reports"
    rep.mkdir(parents=True, exist_ok=True)
    for inc in incidents:
        (rep / f"{inc.id}.md").write_text(incident_markdown(inc), encoding="utf-8")
    data = {"company": ctx.get("company"), "events": len(events), "alerts": len(alerts),
            "incidents": [incident_json(i) for i in incidents], "evaluation": score}
    (out / "incidents.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    if not quiet:
        print(f"{len(events)} events -> {len(alerts)} alerts -> {len(incidents)} incidents")
        for r in score["incidents"]:
            mark = "✔" if r["correct"] else "✘"
            print(f"  {mark} {r['incident']}  {r['verdict']:<13} ({r['confidence']:<6}) expected {r['expected']:<13} {r['title']}")
        print(f"Verdicts correct: {score['correct']}/{score['total']}  |  attacks confirmed: {score['attacks_confirmed']}  |  "
              f"alerts on benign activity: {score['alerts_on_benign']} (closed or held: {score['benign_alerts_closed']})")
    return data


def run_validation(out: Path, quiet: bool = False) -> dict:
    v = validate(OTRF, RULES)
    out.mkdir(parents=True, exist_ok=True)
    (out / "validation.md").write_text(validation_markdown(v), encoding="utf-8")
    (out / "validation.json").write_text(json.dumps(v, indent=2, default=str), encoding="utf-8")
    if not quiet:
        a, n, t = v["active"], v["naive_run_key"], v["tuned_run_key"]
        print(f"Real telemetry: {len(v['datasets'])} OTRF datasets, {v['total_events']:,} events")
        print(f"  Active rules: {a['detected']}/{a['expected']} detections, {a['false_positive_alerts']} false positives, {a['missed']} missed")
        print(f"  Run-key rule tuning: naive {n['false_positive_alerts']} FPs -> tuned {t['false_positive_alerts']} FPs")
    return v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "validate", "rules", "all"])
    ap.add_argument("-o", "--out", type=Path, default=ROOT / "output")
    args = ap.parse_args(argv)

    if args.command == "rules":
        rules, corrs = load_all(RULES, include_deprecated=True)
        for r in rules:
            print(f"{r.level:<13} {r.custom.get('name', r.id):<30} {', '.join(r.techniques):<22} {r.title}"
                  + ("  [building block]" if r.custom.get("building_block") else "")
                  + ("  [deprecated]" if r.status == "deprecated" else ""))
        for c in corrs:
            print(f"{c.level:<13} {c.name:<30} {', '.join(c.techniques):<22} {c.title}  [correlation: {c.type}]")
        return 0

    v = run_validation(args.out) if args.command in ("validate", "all") else None
    d = run_scenarios(args.out) if args.command in ("run", "all") else None
    if args.command == "all" and v and d:
        from soc.console import render
        (args.out / "soc_console.html").write_text(render(d, v), encoding="utf-8")
        print(f"Analyst console: {args.out / 'soc_console.html'}")
    ok = True
    if d:
        ok &= d["evaluation"]["correct"] == d["evaluation"]["total"]
    if v:
        ok &= v["active"]["missed"] == 0 and v["active"]["false_positive_alerts"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
