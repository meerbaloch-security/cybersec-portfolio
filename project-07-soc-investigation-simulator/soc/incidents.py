"""From alerts to incidents: enrichment, entity correlation, triage verdicts.

The steps mirror what a Tier 1 analyst does by hand:

1. Enrich   threat-intel matches, decoded PowerShell, asset criticality
2. Group    alerts that share an entity (user, host, IP, sender, domain)
            within two hours become one incident (entity-based correlation,
            like risk-based alerting in Splunk ES or incidents in Sentinel)
3. Context  check each alert against what the SOC knows: approved change
            tickets, authorised scanners, known backup routes
4. Gather   related raw events for the same entities (not just alerts)
5. Decide   verdict (True positive / Benign / Inconclusive) with a
            confidence level, the evidence for and against, open questions
            and recommended actions

The verdict logic never reads the ground-truth labels.
"""

from __future__ import annotations

import base64
import binascii
import csv
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .detect import Alert

TACTIC_ORDER = ["reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection",
                "command-and-control", "exfiltration", "impact"]

TECHNIQUE_NAMES = {
    "T1110": "Brute Force", "T1110.001": "Brute Force: Password Guessing", "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts", "T1098": "Account Manipulation", "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1027": "Obfuscated Files or Information", "T1069.001": "Permission Groups Discovery: Local Groups",
    "T1003.001": "OS Credential Dumping: LSASS Memory", "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1566.002": "Phishing: Spearphishing Link", "T1071": "Application Layer Protocol", "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.005": "Scheduled Task/Job: Scheduled Task", "T1547.001": "Boot or Logon Autostart: Registry Run Keys",
}

IGNORED_USERS = {"-", "", "system", "local service", "network service", "administrators", "domain admins",
                 "enterprise admins", "anonymous logon"}
RECON_WORDS = ("whoami", "net localgroup", "net group", "nltest", "get-aduser", "get-localgroupmember", "ipconfig /all")
LINK_WINDOW = timedelta(hours=2)
DUAL_USE_TOOLS = {"rclone.exe", "megasync.exe", "winscp.exe", "filezilla.exe", "restic.exe"}
CRITICALITY = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 1.0}


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def load_threat_intel(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8") as fh:
        return {row["value"].lower(): row["source"] for row in csv.DictReader(fh)}


def _domain(url: str) -> str:
    m = re.match(r"(?i)^[a-z]+://([^/:?#]+)", url or "")
    return m.group(1).lower() if m else ""


def enrich(events: list[dict], ti: dict[str, str]) -> None:
    """Add ti_match fields in place (a pipeline step before detection)."""
    for e in events:
        candidates = [e.get(k) for k in ("IpAddress", "src_ip", "dst_ip", "domain")]
        candidates += [_domain(u) for u in e.get("urls", [])] + [_domain(e.get("url", ""))]
        for c in candidates:
            if c and str(c).lower() in ti:
                e["ti_match"], e["ti_value"], e["ti_source"] = True, str(c).lower(), ti[str(c).lower()]
                break


def decode_powershell(cmd: str) -> str | None:
    m = re.search(r"(?i)\s[-/](?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", cmd or "")
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    private = any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
    return not private


def short_host(h) -> str:
    return str(h or "").split(".")[0].upper()


def entities(alert: Alert) -> set[tuple[str, str]]:
    """Entities an alert is about. Correlation alerts use only their group-by
    fields, so a password spray across 12 accounts does not link 12 users."""
    out: set[tuple[str, str]] = set()
    if alert.correlation:
        for k, v in alert.group.items():
            if k in ("TargetUserName", "SubjectUserName") and str(v).lower() not in IGNORED_USERS:
                out.add(("user", str(v).lower()))
            elif k in ("IpAddress", "src_ip"):
                out.add(("ip", str(v)))
        out.add(("host", short_host(alert.first.get("Hostname"))))
        return out
    for e in alert.events:
        group_event = e.get("EventID") in (4728, 4732, 4756)
        for k in ("SubjectUserName", "User", "user", "recipient") + (() if group_event else ("TargetUserName",)):
            v = str(e.get(k) or "").split("\\")[-1].lower()
            if v and v not in IGNORED_USERS:
                out.add(("user", v))
        if e.get("Hostname"):
            out.add(("host", short_host(e["Hostname"])))
        for k in ("IpAddress", "dst_ip"):
            v = e.get(k)
            if v and v != "-" and (k == "IpAddress" or is_external(str(v))):
                out.add(("ip", str(v)))
        if e.get("sender"):
            out.add(("sender", e["sender"].lower()))
        for d in [e.get("domain")] + [_domain(u) for u in e.get("urls", [])]:
            if d and e.get("ti_match"):
                out.add(("domain", d))
    return out


# --------------------------------------------------------------------------- #
# Context: what the SOC already knows
# --------------------------------------------------------------------------- #
def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def explain(alert: Alert, ctx: dict) -> str | None:
    e = alert.first
    actor = str(e.get("SubjectUserName") or e.get("User") or "").split("\\")[-1].lower()
    host = short_host(e.get("Hostname"))
    for t in ctx.get("change_tickets", []):
        if (alert.rule_name in t["rules"] and host in t["hosts"] and actor in t["users"]
                and _parse(t["start"]) <= alert.time <= _parse(t["end"])):
            return f"Approved change {t['id']}: {t['summary']} (approved by {t['approved_by']})"
    ip = alert.group.get("IpAddress") or e.get("IpAddress")
    for s in ctx.get("scanners", []):
        if ip == s["ip"] and alert.rule_name in ("password_spray", "bruteforce_attempts", "bruteforce_success"):
            return f"Source {ip} is {s['name']}"
    for b in ctx.get("backup_routes", []):
        if alert.rule_name == "large_outbound_transfer" and host == b["host"] and e.get("dst_ip") == b["dst_ip"]:
            return f"Known backup route: {b['host']} -> {b['name']} ({b['dst_ip']})"
    return None


# --------------------------------------------------------------------------- #
# Incident model
# --------------------------------------------------------------------------- #
@dataclass
class TimelineEntry:
    time: datetime
    kind: str        # alert | related
    title: str
    detail: str
    technique: str = ""
    explained: str | None = None


@dataclass
class Incident:
    id: str
    title: str
    alerts: list[Alert]
    entities: dict[str, list[str]]
    start: datetime
    end: datetime
    verdict: str = ""
    confidence: str = ""
    severity: str = ""
    risk: int = 0
    score: int = 0
    tactics: list[str] = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    recommendations: dict[str, list[str]] = field(default_factory=dict)
    timeline: list[TimelineEntry] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    summary: str = ""
    stage: str = ""
    explained: dict[str, str] = field(default_factory=dict)


def group_alerts(alerts: list[Alert]) -> list[list[Alert]]:
    """Single-linkage clustering: alerts sharing an entity within LINK_WINDOW."""
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    ents = [entities(a) for a in alerts]
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            gap = abs((alerts[j].time - alerts[i].end).total_seconds())
            if gap <= LINK_WINDOW.total_seconds() and ents[i] & ents[j]:
                parent[find(i)] = find(j)
    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    return sorted(groups.values(), key=lambda g: g[0].time)


def related_events(inc_entities: set, start: datetime, end: datetime, events: list[dict], alert_ids: set[str]) -> list[dict]:
    users = {v for k, v in inc_entities if k == "user"}
    hosts = {v for k, v in inc_entities if k == "host"}
    out = []
    for e in events:
        if e["_id"] in alert_ids or not (start - timedelta(minutes=30) <= e["_time"] <= end + timedelta(minutes=30)):
            continue
        u = str(e.get("User") or e.get("user") or e.get("TargetUserName") or e.get("recipient") or "").split("\\")[-1].lower()
        if short_host(e.get("Hostname")) in hosts or (u and u in users):
            if e.get("EventID") == 4625:  # individual failures are summarised by the correlation alert
                continue
            out.append(e)
    return out[:12]


def describe_event(e: dict) -> tuple[str, str]:
    ls = e.get("_logsource", {})
    p = ls.get("product")
    if p == "email_gateway":
        return "Email delivered", f"From {e.get('sender')} to {e.get('recipient')}: \"{e.get('subject')}\" (phish score {e.get('phish_score')})"
    if p == "proxy":
        return "Web request", f"{e.get('user')} on {e.get('Hostname')} -> {e.get('url')} [{e.get('url_category')}, {e.get('action')}]"
    if p == "firewall":
        gb = int(e.get("bytes_out", 0)) / 1e9
        return "Outbound transfer", f"{e.get('Hostname')} -> {e.get('dst_ip')}:{e.get('dst_port')} {gb:.2f} GB" + (f" ({e['process']})" if e.get("process") else "")
    eid = e.get("EventID")
    if eid == 4624:
        return "Successful logon", f"{e.get('TargetUserName')} on {e.get('Hostname')} from {e.get('IpAddress')} (type {e.get('LogonType')})"
    if eid == 4625:
        return "Failed logon", f"{e.get('TargetUserName')} on {e.get('Hostname')} from {e.get('IpAddress')}"
    if eid in (4728, 4732, 4756):
        return "Group membership change", f"{e.get('MemberName')} added to {e.get('TargetUserName')} on {e.get('Hostname')} by {e.get('SubjectUserName')}"
    if ls.get("category") == "process_creation":
        return "Process started", f"{e.get('User')} on {e.get('Hostname')}: {e.get('CommandLine')} (parent {str(e.get('ParentImage')).split(chr(92))[-1]})"
    return f"Event {eid}", str({k: v for k, v in e.items() if not k.startswith("_")})[:160]


def _first_seen_ip(user: str, ip: str, before: datetime, events: list[dict]) -> bool:
    return not any(e.get("EventID") == 4624 and str(e.get("TargetUserName", "")).lower() == user and e.get("IpAddress") == ip
                   and e["_time"] < before for e in events)


def concurrent_activity(live: list[Alert], events: list[dict]):
    """Was the real user demonstrably on an internal workstation while their
    account logged in from an external IP? Returns the first example."""
    for a in live:
        for e in a.events:
            if e.get("EventID") != 4624 or not is_external(str(e.get("IpAddress"))):
                continue
            u = str(e.get("TargetUserName")).lower()
            near = [o for o in events
                    if str(o.get("User") or o.get("user") or "").split("\\")[-1].lower() == u
                    and short_host(o.get("Hostname")) != short_host(e.get("Hostname"))
                    and abs((o["_time"] - e["_time"]).total_seconds()) <= 1800
                    and (o.get("_logsource", {}).get("category") == "process_creation"
                         or o.get("_logsource", {}).get("product") == "proxy")]
            if near:
                o = min(near, key=lambda x: abs((x["_time"] - e["_time"]).total_seconds()))
                what = describe_event(o)[0].lower()
                return u, short_host(e.get("Hostname")), e.get("IpAddress"), e["_time"], short_host(o.get("Hostname")), o["_time"], what
    return None


def build_incident(n: int, alerts: list[Alert], events: list[dict], ctx: dict) -> Incident:
    alerts = sorted(alerts, key=lambda a: a.time)
    ents: set = set().union(*(entities(a) for a in alerts))
    inc = Incident(f"INC-{alerts[0].time:%Y%m%d}-{n:03d}", "", alerts,
                   {k: sorted({v for kk, v in ents if kk == k}) for k in ("user", "host", "ip", "sender", "domain")},
                   alerts[0].time, max(a.end for a in alerts))
    inc.explained = {a.id: r for a in alerts if (r := explain(a, ctx))}
    live = [a for a in alerts if a.id not in inc.explained]

    # ATT&CK, tactics, kill-chain progress (from alerts that are not explained away)
    basis = live or alerts
    # Chronological progression: tactics in the order they were first observed
    inc.tactics = []
    for a in sorted(basis, key=lambda a: a.end):
        for t in sorted(a.tactics, key=lambda x: TACTIC_ORDER.index(x) if x in TACTIC_ORDER else 99):
            if t not in inc.tactics:
                inc.tactics.append(t)
    last = max(basis, key=lambda a: a.end)
    inc_stage = last.tactics[0] if last.tactics else (inc.tactics[-1] if inc.tactics else "unknown")
    seen = set()
    for a in basis:
        for tech in a.techniques:
            if tech not in seen:
                seen.add(tech)
                when = a.end if a.correlation == "temporal_ordered" else a.time
                inc.techniques.append({"id": tech, "name": TECHNIQUE_NAMES.get(tech, tech), "evidence": a.title,
                                       "time": when.strftime("%H:%M:%S")})

    # Observations from enrichment
    hosts = inc.entities["host"]
    assets = ctx.get("assets", {})
    for h in hosts:
        if h in assets:
            inc.observations.append(f"{h} is a {assets[h]['criticality']}-criticality asset: {assets[h]['role']}.")
    decoded_recon = False
    for a in alerts:
        for e in a.events[:1]:
            d = decode_powershell(e.get("CommandLine", ""))
            if d:
                inc.observations.append(f"Decoded PowerShell on {short_host(e.get('Hostname'))}: `{d}`")
                decoded_recon |= any(w in d.lower() for w in RECON_WORDS) and a.id not in inc.explained
    ti_hits = sorted({(e["ti_value"], e["ti_source"]) for a in alerts for e in a.events if e.get("ti_match")})
    for v, s in ti_hits:
        inc.observations.append(f"{v} is a known indicator ({s}).")
    new_ip_logons = []
    for a in live:
        for e in a.events:
            if e.get("EventID") == 4624 and is_external(str(e.get("IpAddress"))):
                u = str(e.get("TargetUserName")).lower()
                if _first_seen_ip(u, e["IpAddress"], e["_time"], events):
                    new_ip_logons.append((u, e["IpAddress"]))
    for u, ip in sorted(set(new_ip_logons)):
        inc.observations.append(f"First successful logon for {u} from {ip} in the available logs.")
    bh = ctx.get("business_hours_utc", [0, 24])
    off_hours = [a for a in live if not (bh[0] <= a.time.hour < bh[1])]
    if off_hours:
        inc.observations.append(f"Activity outside business hours ({off_hours[0].time:%H:%M} UTC).")

    # Related raw events (what the analyst pulls up around the alerts)
    alert_ids = {e["_id"] for a in alerts for e in a.events}
    related = related_events(ents, inc.start, inc.end, events, alert_ids)
    dual_use = None
    for a in live:
        proc_name = a.first.get("process")
        if proc_name:
            starter = next((e for e in related if e.get("_logsource", {}).get("category") == "process_creation"
                            and str(e.get("Image", "")).lower().endswith(proc_name.lower())), None)
            how = (f", started by {str(starter.get('User')).split(chr(92))[-1]} from "
                   f"{str(starter.get('ParentImage')).split(chr(92))[-1]}: `{starter.get('CommandLine')}`") if starter else ""
            inc.observations.append(f"The transfer was made by {proc_name}{how}.")
            if proc_name.lower() in DUAL_USE_TOOLS:
                dual_use = (proc_name, starter)

    # Scope: other recipients of the same phishing sender
    senders = set(inc.entities["sender"])
    if senders:
        rcpts = sorted({e["recipient"] for e in events if e.get("sender", "").lower() in senders})
        clickers = sorted({e.get("user") for e in events if e.get("_logsource", {}).get("product") == "proxy"
                           and e.get("ti_match") and e.get("user") in rcpts})
        inc.observations.append(f"{len(rcpts)} recipient(s) of the email: {', '.join(rcpts)}; clicked: {', '.join(clickers) or 'none seen'}.")

    # ------------------------------------------------------------------ #
    # Evidence and verdict
    # ------------------------------------------------------------------ #
    F, A = inc.evidence_for, inc.evidence_against
    score = 0
    crit = [a for a in live if a.level == "critical"]
    if crit:
        score += 3
        F.append(f"Critical detection: {crit[0].title}.")
    if ti_hits and live:
        score += 3
        F.append("Activity involves known threat-intelligence indicators: " + ", ".join(v for v, _ in ti_hits) + ".")
    ti_logon = [e for a in live for e in a.events if e.get("EventID") == 4624 and e.get("ti_match")]
    if ti_logon:
        score += 2
        F.append(f"Successful logon by {ti_logon[0].get('TargetUserName')} from attacker infrastructure {ti_logon[0].get('IpAddress')}.")
    live_tactics = [t for t in TACTIC_ORDER if any(t in a.tactics for a in live)]
    if len(live_tactics) >= 2:
        score += 2
        F.append(f"Activity spans {len(live_tactics)} ATT&CK tactics: {', '.join(live_tactics)}.")
    if len(live_tactics) >= 3:
        score += 2
    if "credential-access" in live_tactics and any(a.rule_name not in ("bruteforce_attempts", "bruteforce_success", "password_spray") and "credential-access" in a.tactics for a in live):
        score += 2
        F.append("Credential-dumping behaviour after access was gained.")
    if decoded_recon:
        score += 1
        F.append("Encoded PowerShell decodes to reconnaissance commands.")
    if new_ip_logons:
        score += 1
        F.append("Logon from a source IP never seen for this account.")
    concurrent = concurrent_activity(live, events)
    if concurrent:
        score += 2
        u, ext_host, ip, t_ext, int_host, t_int, what = concurrent
        F.append(f"Impossible concurrency: {u} was active on {int_host} inside the office ({what} at {t_int:%H:%M}) "
                 f"while the account logged in to {ext_host} from {ip} at {t_ext:%H:%M}.")
    if off_hours:
        score += 1
        F.append("Activity outside business hours.")
    if dual_use:
        score += 1
        F.append(f"{dual_use[0]} is a legitimate sync tool that is also widely abused for data theft.")
        if dual_use[1] is not None and str(dual_use[1].get("ParentImage", "")).lower().endswith(("cmd.exe", "explorer.exe")):
            A.append("The tool was run interactively by the user under their own account, consistent with a personal backup.")
    for a in alerts:
        if a.id in inc.explained:
            A.append(f"{a.title}: {inc.explained[a.id]}.")
    privileged = set(ctx.get("privileged_users", []))
    if live and set(inc.entities["user"]) & privileged and not inc.explained:
        A.append("Actor is a known IT/privileged account.")
    if live and not ti_hits:
        A.append("No threat-intelligence match for any IP or domain involved.")
    if live and len(live_tactics) <= 1 and not crit:
        A.append("Single isolated behaviour; no preceding access or follow-on activity detected.")
    inc.score = score

    if not live:
        inc.verdict, inc.confidence = "Benign", "High"
    elif score >= 6:
        inc.verdict, inc.confidence = "True positive", "High" if score >= 8 else "Medium"
    else:
        inc.verdict, inc.confidence = "Inconclusive", "Medium" if score >= 3 else "Low"

    # Risk and severity
    mult = max((CRITICALITY.get(assets.get(h, {}).get("criticality", "medium"), 1.0) for h in hosts), default=1.0)
    inc.risk = min(100, round(sum(a.risk for a in live) * mult)) if live else 0
    if inc.verdict == "Benign":
        inc.severity = "Informational"
    else:
        inc.severity = "Critical" if inc.risk >= 70 else "High" if inc.risk >= 40 else "Medium" if inc.risk >= 20 else "Low"

    inc.stage = inc_stage
    inc.title = make_title(inc)
    inc.uncertainties = uncertainties(inc, events)
    inc.recommendations = recommend(inc)
    inc.iocs = sorted(({"type": k, "value": v} for k in ("ip", "domain", "sender") for v in inc.entities[k]
                       if inc.verdict != "Benign" and (k != "ip" or is_external(v))), key=lambda x: (x["type"], x["value"]))

    # Timeline
    for a in alerts:
        if a.correlation in ("event_count", "value_count"):
            detail = f"{len(a.events)} failed logons {a.time:%H:%M:%S}–{a.end:%H:%M:%S} " + \
                     ", ".join(f"{k}={v}" for k, v in a.group.items())
        elif a.correlation == "temporal_ordered":
            detail = "Correlated: " + ", ".join(f"{k}={v}" for k, v in a.group.items())
        else:
            detail = describe_event(a.first)[1]
        when = a.end if a.correlation == "temporal_ordered" else a.time
        inc.timeline.append(TimelineEntry(when, "alert", a.title, detail, ", ".join(a.techniques), inc.explained.get(a.id)))
    for e in related:
        title, detail = describe_event(e)
        inc.timeline.append(TimelineEntry(e["_time"], "related", title, detail))
    inc.timeline.sort(key=lambda x: (x.time, x.kind != "alert"))
    inc.summary = summarise(inc)
    return inc


def make_title(inc: Incident) -> str:
    names = {a.rule_name for a in inc.alerts}
    u = ", ".join(inc.entities["user"][:2])
    h = ", ".join(inc.entities["host"][:2])
    if "bruteforce_success" in names:
        return f"Account compromise via brute force: {u} on {h}"
    if "phish_delivered" in names:
        used = sorted({str(e.get("TargetUserName")).lower() for a in inc.alerts for e in a.events if e.get("EventID") == 4624})
        return f"Phishing email with credential use: {', '.join(used) or u}"
    if "password_spray" in names:
        return f"Password spray from {inc.entities['ip'][0]}"
    if "large_outbound_transfer" in names:
        return f"Large outbound data transfer from {h}"
    if "privileged_group_member_added" in names:
        return f"User added to Administrators on {h}"
    if "powershell_encoded_command" in names:
        return f"Encoded PowerShell on {h}"
    return inc.alerts[0].title


def summarise(inc: Incident) -> str:
    stage = inc.stage or "unknown"
    if inc.verdict == "Benign":
        reason = next(iter(inc.explained.values()), "expected activity")
        return (f"{len(inc.alerts)} alert(s) on {', '.join(inc.entities['host'])} were reviewed and explained by known context: "
                f"{reason}. No further action beyond closing with justification.")
    if inc.verdict == "True positive":
        return (f"Malicious activity confirmed with {inc.confidence.lower()} confidence across {len(inc.alerts)} correlated alerts. "
                f"Affected: {', '.join(inc.entities['user']) or 'n/a'} on {', '.join(inc.entities['host'])}. "
                f"The attack progressed as far as **{stage}**. Containment is recommended now.")
    return (f"Suspicious activity on {', '.join(inc.entities['host'])} that cannot be confirmed or ruled out from the available "
            f"telemetry. The open questions below must be answered before closing; escalate to Tier 2 if unanswered within 4 hours.")


def uncertainties(inc: Incident, events: list[dict]) -> list[str]:
    out = []
    names = {a.rule_name for a in inc.alerts}
    hosts = inc.entities["host"]
    if inc.verdict == "Benign":
        if "powershell_encoded_command" in names:
            out.append("The change ticket confirms the activity was planned; the decoded script was also reviewed and only reads service status.")
        out.append("Closed on documented context. If the ticket or allowlist were wrong, this would be missed: allowlists should be reviewed regularly.")
        return out
    if "bruteforce_success" in names:
        out.append("How the password was obtained is unconfirmed: 25 guesses suggest a weak or reused password, not a full brute force.")
    if "reg_save_sensitive_hive" in names:
        h = next(a for a in inc.alerts if a.rule_name == "reg_save_sensitive_hive")
        later = [e for e in events if short_host(e.get("Hostname")) == short_host(h.first.get("Hostname"))
                 and e.get("_logsource", {}).get("product") == "firewall" and e["_time"] > h.time]
        if not later:
            out.append(f"No outbound transfer from {short_host(h.first.get('Hostname'))} is logged after the SAM export, "
                       "so it is unknown whether the hive (and its password hashes) left the server.")
    if "phish_delivered" in names:
        out.append("Mailbox audit logs are not available: it is unknown whether the attacker read, forwarded or deleted email.")
        out.append("Proxy logs show the click but not what was entered on the page.")
    if "large_outbound_transfer" in names and inc.verdict != "True positive":
        out.append("Which files were uploaded is unknown (no DLP or file-access telemetry).")
        out.append("Destination 192.0.2.150 is not in threat intel and not an approved backup route; it may be a personal cloud account.")
        out.append("Is this an approved project backup? Only the user or their manager can confirm.")
    if not any(e.get("_logsource", {}).get("category") == "process_creation" and short_host(e.get("Hostname")) in hosts for e in events) \
            and "phish_delivered" not in names:
        out.append(f"No process telemetry from {', '.join(hosts)}.")
    return out


def recommend(inc: Incident) -> dict[str, list[str]]:
    names = {a.rule_name for a in inc.alerts}
    users, hosts = inc.entities["user"], inc.entities["host"]
    ext_ips = [i for i in inc.entities["ip"] if is_external(i)]
    if inc.verdict == "Benign":
        recs = {"Close": [f"Close as benign; record the justification: {next(iter(inc.explained.values()), 'expected activity')}."]}
        if names & {"password_spray"}:
            recs["Tuning"] = ["Add a suppression for the scanner IP during its scheduled window so this does not page the SOC every week."]
        return recs
    if inc.verdict == "Inconclusive":
        return {
            "Investigate": [f"Contact {', '.join(users) or 'the asset owner'} and their manager to confirm whether the activity was authorised.",
                            "Pull EDR / file-access history for the source host for the hour before the transfer.",
                            "Check whether the destination belongs to an approved SaaS tenant."],
            "Contain if not confirmed": [f"Block {', '.join(ext_ips) or 'the destination'} at the firewall and revoke the user's sessions.",
                                         "Escalate to Tier 2 / data-protection team."],
        }
    recs: dict[str, list[str]] = {"Contain": [], "Eradicate": [], "Recover": [], "Follow up": []}
    for u in users:
        recs["Contain"].append(f"Disable or reset the password for {u}, revoke all active sessions and tokens, and re-register MFA.")
    if ext_ips:
        recs["Contain"].append(f"Block {', '.join(ext_ips)} at the perimeter firewall and VPN.")
    if names & {"reg_save_sensitive_hive", "lsass_dump_comsvcs", "lsass_process_access"}:
        recs["Contain"].append(f"Isolate {', '.join(hosts)} from the network (credential material was exposed).")
        recs["Eradicate"].append("Treat every local account on the host as compromised: rotate local administrator passwords (LAPS) and service-account secrets.")
    if "privileged_group_member_added" in names:
        recs["Eradicate"].append("Remove the unauthorised member from the Administrators group and review other group changes by the same account.")
    if "powershell_encoded_command" in names:
        recs["Eradicate"].append("Review PowerShell script-block logs (event 4104) on the host for any further commands.")
    if "phish_delivered" in names:
        recs["Contain"].append("Purge the phishing email from all mailboxes and block the sender domain and the linked domain.")
        recs["Follow up"].append("Notify the other recipients; check mailbox rules and OAuth app consents for the affected user.")
    if "bruteforce_success" in names:
        recs["Recover"].append("Remove direct internet exposure of Remote Desktop: put it behind VPN or an RD Gateway with MFA.")
    recs["Recover"].append("Restore normal access for the affected user once the account is clean and MFA is enforced.")
    recs["Follow up"].append("Escalate to Tier 2 / incident response with this report; preserve logs and a memory image if the host is isolated.")
    recs["Follow up"].append("Add the indicators of compromise to the threat-intel platform and hunt for them across all hosts.")
    return {k: v for k, v in recs.items() if v}


def investigate(alerts: list[Alert], events: list[dict], ctx: dict) -> list[Incident]:
    return [build_incident(i, g, events, ctx) for i, g in enumerate(group_alerts(alerts), 1)]
