"""Score the pipeline against the scenario ground truth.

Labels are only read here, after detection and triage have finished.
"""

from __future__ import annotations

from collections import Counter

from .detect import Alert
from .incidents import Incident


def evaluate(alerts: list[Alert], incidents: list[Incident], labels: dict) -> dict:
    ev_labels = labels["events"]
    expected = labels["expected_incidents"]

    def scenario_of(items) -> str:
        c = Counter(ev_labels[e["_id"]]["scenario"] for a in items for e in a.events if e["_id"] in ev_labels)
        return c.most_common(1)[0][0] if c else "?"

    rows = []
    for inc in incidents:
        s = scenario_of(inc.alerts)
        exp = expected.get(s, {}).get("verdict", "?")
        rows.append({"incident": inc.id, "scenario": s, "expected": exp, "verdict": inc.verdict,
                     "confidence": inc.confidence, "correct": exp == inc.verdict, "title": inc.title})

    malicious_alerts = [a for a in alerts if any(ev_labels.get(e["_id"], {}).get("malicious") for e in a.events)]
    benign_alerts = [a for a in alerts if a not in malicious_alerts]
    malicious_scenarios = {s for s, v in expected.items() if v["verdict"] == "True positive"}
    detected = {r["scenario"] for r in rows if r["verdict"] == "True positive"}
    seen_scenarios = {r["scenario"] for r in rows}
    return {
        "incidents": rows,
        "correct": sum(r["correct"] for r in rows),
        "total": len(rows),
        "missed_scenarios": sorted(set(expected) - seen_scenarios),
        "alerts_total": len(alerts),
        "alerts_on_malicious": len(malicious_alerts),
        "alerts_on_benign": len(benign_alerts),
        "benign_alerts_closed": sum(1 for a in benign_alerts
                                    if any(a in inc.alerts and inc.verdict != "True positive" for inc in incidents)),
        "attacks_confirmed": f"{len(detected & malicious_scenarios)}/{len(malicious_scenarios)}",
        "false_positive_incidents": sum(1 for r in rows if r["verdict"] == "True positive" and r["expected"] != "True positive"),
    }
