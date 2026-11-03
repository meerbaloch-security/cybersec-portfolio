"""Loading and normalising security telemetry.

Two sources are supported:

* OTRF Security-Datasets: real Windows Security, Sysmon and PowerShell events
  recorded during attack simulations (zipped JSON lines).
* Scenario files: fictional JSON-lines telemetry for the simulated company,
  covering Windows hosts plus email gateway, web proxy and firewall logs.

Normalisation works like a Sigma "processing pipeline": it attaches a
logsource (product / service / category) to every event and maps a few field
names so one rule can match both Sysmon and native Windows events, e.g.
Security 4688 `NewProcessName` -> `Image`.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

SYSMON_CATEGORIES = {
    1: "process_creation", 3: "network_connection", 7: "image_load", 10: "process_access",
    11: "file_event", 12: "registry_event", 13: "registry_set", 14: "registry_event", 22: "dns_query",
}

FIELD_MAP_4688 = {"NewProcessName": "Image", "ParentProcessName": "ParentImage"}


def parse_time(e: dict) -> datetime:
    # Record time first. In the OTRF LSASS dataset, Sysmon's own UtcTime field is
    # 16 hours away from the record time of the same event, so it is a last resort.
    for key in ("@timestamp", "TimeCreated", "EventTime", "timestamp", "UtcTime"):
        v = e.get(key)
        if not v:
            continue
        v = str(v).replace("Z", "+00:00")
        for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                t = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v, fmt)
                return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
            except ValueError:
                continue
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def normalise(e: dict, source: str, index: int) -> dict:
    """Attach _logsource, _time, _id and field aliases. Never alters original fields."""
    e = dict(e)
    channel = str(e.get("Channel", "")).lower()
    try:
        eid = int(e.get("EventID", 0))
    except (TypeError, ValueError):
        eid = 0
    e["EventID"] = eid
    ls: dict[str, str] = {}

    if "_logsource" in e:                      # scenario events declare their source
        ls = dict(e["_logsource"])
    elif "sysmon" in channel:
        ls = {"product": "windows", "service": "sysmon"}
        if eid in SYSMON_CATEGORIES:
            ls["category"] = SYSMON_CATEGORIES[eid]
    elif channel == "security":
        ls = {"product": "windows", "service": "security"}
        if eid == 4688:
            ls["category"] = "process_creation"
    elif "powershell" in channel:
        ls = {"product": "windows", "service": "powershell"}
    elif channel:
        ls = {"product": "windows", "service": channel}

    if eid == 4688 and ls.get("service") == "security":
        for src, dst in FIELD_MAP_4688.items():
            if src in e and dst not in e:
                e[dst] = e[src]
    e.setdefault("Hostname", e.get("Computer") or e.get("host"))
    # Process identity, comparable across Sysmon (decimal ProcessId) and 4688 (hex NewProcessId)
    if ls.get("category") == "process_creation":
        raw_pid = e.get("NewProcessId") if eid == 4688 else e.get("ProcessId")
        try:
            e["_pid"] = int(str(raw_pid), 16) if str(raw_pid).lower().startswith("0x") else int(raw_pid)
        except (TypeError, ValueError):
            pass
    e["_logsource"] = ls
    e["_time"] = parse_time(e)
    e["_source"] = source
    e.setdefault("_id", f"{source}#{index}")
    return e


def load_otrf_zip(path: Path) -> list[dict]:
    with zipfile.ZipFile(path) as zf:
        raw = zf.read(zf.namelist()[0]).decode("utf-8", "replace")
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    out = [normalise(e, path.stem, i) for i, e in enumerate(events)]
    out.sort(key=lambda e: e["_time"])
    return out


def load_jsonl(path: Path) -> list[dict]:
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if line.strip():
            out.append(normalise(json.loads(line), path.stem, i))
    out.sort(key=lambda e: e["_time"])
    return out
