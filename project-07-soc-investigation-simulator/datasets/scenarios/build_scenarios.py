#!/usr/bin/env python3
"""Build the fictional SOC scenario dataset for "Harbor & Pine Logistics".

A 200-person logistics company, one working day (27 October 2026) of
telemetry: Windows Security and Sysmon events, email gateway, web proxy and
firewall logs. Seven scenarios are mixed into ordinary background activity:

  S1  RDP brute force -> account compromise -> admin rights -> recon -> SAM export   (malicious)
  S2  Phishing email -> click -> sign-in from attacker infrastructure               (malicious)
  S3  Encoded PowerShell from the IT management server, approved change            (benign trap)
  S4  User added to local Administrators by the helpdesk, approved change          (benign trap)
  S5  42 GB nightly backup to the off-site backup provider                         (benign trap)
  S6  3.4 GB evening upload from a workstation with rclone, no context             (genuinely unclear)
  S7  Vulnerability scanner causing a burst of failed logons                       (benign trap)

Every event carries a ground-truth label in labels.json (never read by the
detection or verdict logic; used only by the evaluator). All names, IPs and
domains are fictional; IPs come from reserved documentation ranges.
Encoded PowerShell payloads are harmless commands (whoami, Get-Service).

Run:  python3 build_scenarios.py    (deterministic output)
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
DAY = datetime(2026, 10, 27, tzinfo=timezone.utc)
rng = random.Random(7)

events: list[dict] = []
labels: dict[str, dict] = {}


def t(hh: int, mm: int, ss: float = 0) -> datetime:
    return DAY + timedelta(hours=hh, minutes=mm, seconds=ss)


def add(when: datetime, logsource: dict, scenario: str, malicious: bool, **fields) -> None:
    eid = f"evt-{len(events) + 1:04d}"
    events.append({"_id": eid, "@timestamp": when.isoformat().replace("+00:00", "Z"), "_logsource": logsource, **fields})
    labels[eid] = {"scenario": scenario, "malicious": malicious}


SEC = {"product": "windows", "service": "security"}
PROC = {"product": "windows", "service": "sysmon", "category": "process_creation"}
NET = {"product": "windows", "service": "sysmon", "category": "network_connection"}
MAIL = {"product": "email_gateway"}
PROXY = {"product": "proxy"}
FW = {"product": "firewall"}


def enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def logon(when, user, host, ip, ltype, scenario="background", malicious=False):
    add(when, SEC, scenario, malicious, EventID=4624, Hostname=host, TargetUserName=user, TargetDomainName="HPL",
        IpAddress=ip, LogonType=ltype)


def failed(when, user, host, ip, ltype, scenario="background", malicious=False):
    add(when, SEC, scenario, malicious, EventID=4625, Hostname=host, TargetUserName=user, TargetDomainName="HPL",
        IpAddress=ip, LogonType=ltype, Status="0xC000006D", SubStatus="0xC000006A")


def proc(when, host, user, image, cmd, parent, scenario="background", malicious=False):
    add(when, PROC, scenario, malicious, EventID=1, Hostname=host, User=f"HPL\\{user}", Image=image,
        CommandLine=cmd, ParentImage=parent)


# --------------------------------------------------------------------------- #
# Background: a normal working day
# --------------------------------------------------------------------------- #
STAFF = {"j.smith": "WS-JSMITH-01", "a.patel": "WS-APATEL-02", "l.chen": "WS-LCHEN-03", "m.garcia": "WS-MGARCIA-04",
         "k.ross": "WS-KROSS-05", "t.okafor": "WS-TOKAFOR-06", "s.nguyen": "WS-SNGUYEN-07", "r.haddad": "WS-RHADDAD-08"}
NORMAL_SITES = ["outlook.office.com", "teams.microsoft.com", "harborpine.sharepoint.com", "www.maersk.com",
                "www.dhl.com", "github.com", "www.linkedin.com", "news.bbc.co.uk"]
APPS = [("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"'),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", '"OUTLOOK.EXE"'),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", '"Teams.exe"'),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", '"EXCEL.EXE" "Q4 shipments.xlsx"')]

for user, host in STAFF.items():
    start = t(8, rng.randint(0, 40), rng.randint(0, 59))
    logon(start, user, host, "-", 2)
    logon(start + timedelta(seconds=3), user, "DC01", "10.0.1." + str(10 + list(STAFF).index(user)), 3)
    for i in range(3):
        img, cmd = rng.choice(APPS)
        proc(start + timedelta(minutes=5 + i * 37), host, user, img.format(u=user), cmd,
             "C:\\Windows\\explorer.exe")
    for i in range(4):
        site = rng.choice(NORMAL_SITES)
        add(start + timedelta(minutes=10 + i * 50), PROXY, "background", False, user=user, Hostname=host,
            src_ip="10.0.1." + str(10 + list(STAFF).index(user)), url=f"https://{site}/", domain=site,
            url_category="business", action="allowed")
    add(t(16, rng.randint(0, 59)), FW, "background", False, Hostname=host, src_ip="10.0.1." + str(10 + list(STAFF).index(user)),
        dst_ip="192.0.2." + str(rng.randint(10, 60)), dst_port=443, bytes_out=rng.randint(200_000, 40_000_000), app="https")

# A user mistyping a password three times: below the brute-force threshold, no alert expected
for i in range(3):
    failed(t(8, 52, i * 20), "t.okafor", "WS-TOKAFOR-06", "-", 2)
logon(t(8, 53, 30), "t.okafor", "WS-TOKAFOR-06", "-", 2)

# --------------------------------------------------------------------------- #
# S1  RDP brute force -> compromise -> admin -> recon -> credential access
# --------------------------------------------------------------------------- #
ATK = "198.51.100.77"
for i in range(25):
    failed(t(9, 39, i * 4.6), "j.smith", "SRV-RDS-01", ATK, 10, "S1", True)
logon(t(9, 42, 10), "j.smith", "SRV-RDS-01", ATK, 10, "S1", True)
add(t(9, 45, 2), SEC, "S1", True, EventID=4732, Hostname="SRV-RDS-01", TargetUserName="Administrators",
    MemberName="CN=John Smith,OU=Staff,DC=hpl,DC=local", MemberSid="S-1-5-21-1004", SubjectUserName="j.smith")
proc(t(9, 47, 5), "SRV-RDS-01", "j.smith", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + enc("whoami /groups; net localgroup administrators"),
     "C:\\Windows\\explorer.exe", "S1", True)
proc(t(9, 47, 9), "SRV-RDS-01", "j.smith", "C:\\Windows\\System32\\net.exe", '"net.exe" localgroup administrators',
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "S1", True)
proc(t(9, 49, 40), "SRV-RDS-01", "j.smith", "C:\\Windows\\System32\\reg.exe", '"reg.exe" save HKLM\\SAM C:\\Users\\Public\\s.hiv',
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "S1", True)

# --------------------------------------------------------------------------- #
# S2  Phishing -> click -> sign-in from attacker infrastructure
# --------------------------------------------------------------------------- #
for rcpt, when in (("a.patel", t(10, 5, 12)), ("r.haddad", t(10, 5, 14))):
    add(when, MAIL, "S2", True, action="delivered", recipient=rcpt, sender="service@paypa1-secure.xyz",
        sender_display="PayPal Security", subject="Urgent: unusual sign-in activity - account suspended",
        phish_score=100, phish_verdict="malicious", urls=["https://docs-share-portal.xyz/view?id=44812"],
        auth="spf=fail dkim=none dmarc=fail")
add(t(10, 11, 40), PROXY, "S2", True, user="a.patel", Hostname="WS-APATEL-02", src_ip="10.0.1.11",
    url="https://docs-share-portal.xyz/view?id=44812", domain="docs-share-portal.xyz",
    url_category="newly-registered", action="allowed")
logon(t(10, 19, 3), "a.patel", "SRV-MAIL-01", "203.0.113.45", 3, "S2", True)

# --------------------------------------------------------------------------- #
# S3  Encoded PowerShell from the IT management server (approved CHG-1042)
# --------------------------------------------------------------------------- #
proc(t(11, 2, 0), "SRV-MGMT-01", "svc-itops", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "powershell.exe -NoProfile -EncodedCommand " + enc("Get-Service | Where-Object Status -eq 'Stopped' | "
                                                         "Export-Csv C:\\IT\\reports\\stopped-services.csv"),
     "C:\\Program Files\\HarborPine\\RMM\\rmm-agent.exe", "S3", False)

# --------------------------------------------------------------------------- #
# S4  Helpdesk grants local admin (approved CHG-2231)
# --------------------------------------------------------------------------- #
add(t(13, 15, 30), SEC, "S4", False, EventID=4732, Hostname="WS-MGARCIA-04", TargetUserName="Administrators",
    MemberName="CN=Maria Garcia,OU=Staff,DC=hpl,DC=local", MemberSid="S-1-5-21-1007", SubjectUserName="k.ross")

# --------------------------------------------------------------------------- #
# S5  Nightly backup to the off-site provider
# --------------------------------------------------------------------------- #
add(t(2, 0, 4), FW, "S5", False, Hostname="SRV-BACKUP-01", src_ip="10.0.5.20", dst_ip="192.0.2.200", dst_port=443,
    bytes_out=42_310_000_000, app="https")

# --------------------------------------------------------------------------- #
# S6  Evening upload with rclone, no context (genuinely unclear)
# --------------------------------------------------------------------------- #
proc(t(18, 51, 20), "WS-LCHEN-03", "l.chen", "C:\\Users\\l.chen\\Downloads\\rclone-v1.68\\rclone.exe",
     '"rclone.exe" copy "C:\\Users\\l.chen\\Documents\\Projects" remote:backup --progress',
     "C:\\Windows\\System32\\cmd.exe", "S6", False)
add(t(18, 52, 2), FW, "S6", False, Hostname="WS-LCHEN-03", src_ip="10.0.1.12", dst_ip="192.0.2.150", dst_port=443,
    bytes_out=3_412_000_000, app="https", process="rclone.exe")

# --------------------------------------------------------------------------- #
# S7  Authorised vulnerability scan
# --------------------------------------------------------------------------- #
for i, u in enumerate(["administrator", "admin", "backup", "sqlsvc", "test", "guest", "j.smith", "a.patel",
                       "svc-itops", "operator", "support", "scanner-test"]):
    failed(t(7, 30, i * 7), u, "SRV-FILE-01", "10.0.9.50", 3, "S7", False)

events.sort(key=lambda e: e["@timestamp"])

context = {
    "_comment": "What the SOC knows about the environment. Used by the incident engine to explain alerts.",
    "company": "Harbor & Pine Logistics (fictional)",
    "change_tickets": [
        {"id": "CHG-1042", "summary": "Weekly service health report via RMM (encoded script)", "approved_by": "IT Ops manager",
         "hosts": ["SRV-MGMT-01"], "users": ["svc-itops"], "rules": ["powershell_encoded_command"],
         "start": "2026-10-27T10:30:00Z", "end": "2026-10-27T12:00:00Z"},
        {"id": "CHG-2231", "summary": "Temporary local admin for Maria Garcia to install shipping-label printer drivers",
         "approved_by": "IT Service Desk lead", "hosts": ["WS-MGARCIA-04"], "users": ["k.ross"],
         "rules": ["privileged_group_member_added"], "start": "2026-10-27T13:00:00Z", "end": "2026-10-27T14:00:00Z"},
    ],
    "scanners": [{"ip": "10.0.9.50", "name": "SCANNER-01 (authorised vulnerability scanner, weekly Tue 07:30)"}],
    "backup_routes": [{"host": "SRV-BACKUP-01", "dst_ip": "192.0.2.200", "name": "Off-site backup provider"}],
    "assets": {"SRV-RDS-01": {"criticality": "high", "role": "Internet-facing Remote Desktop server"},
               "SRV-MAIL-01": {"criticality": "high", "role": "Webmail server"},
               "DC01": {"criticality": "critical", "role": "Domain controller"},
               "SRV-MGMT-01": {"criticality": "high", "role": "IT management server"},
               "SRV-BACKUP-01": {"criticality": "high", "role": "Backup server"}},
    "privileged_users": ["svc-itops", "k.ross"],
    "business_hours_utc": [7, 18],
}

expected = {
    "S1": {"verdict": "True positive", "summary": "RDP brute force led to account compromise, admin rights and credential access"},
    "S2": {"verdict": "True positive", "summary": "Phishing led to credential use from attacker infrastructure"},
    "S3": {"verdict": "Benign", "summary": "Approved IT maintenance script"},
    "S4": {"verdict": "Benign", "summary": "Approved temporary admin rights"},
    "S5": {"verdict": "Benign", "summary": "Nightly off-site backup"},
    "S6": {"verdict": "Inconclusive", "summary": "Large upload with no context; needs the user's manager to confirm"},
    "S7": {"verdict": "Benign", "summary": "Authorised vulnerability scan"},
}

# Threat intelligence: indicators exported by Project 03 (ioc-extractor) from the SANDFOX threat brief
threat_intel = """type,value,source
ipv4,203.0.113.45,SANDFOX threat brief (Project 03)
ipv4,198.51.100.23,SANDFOX threat brief (Project 03)
domain,docs-share-portal.xyz,SANDFOX threat brief (Project 03)
domain,quick-freight-billing.top,SANDFOX threat brief (Project 03)
domain,cdn-update-sync.com,SANDFOX threat brief (Project 03)
"""

if __name__ == "__main__":
    (HERE / "harbor_pine_2026-10-27.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    (HERE / "labels.json").write_text(json.dumps({"events": labels, "expected_incidents": expected}, indent=2))
    (HERE / "context.json").write_text(json.dumps(context, indent=2))
    (HERE / "threat_intel.csv").write_text(threat_intel)
    print(f"{len(events)} events, {sum(l['malicious'] for l in labels.values())} malicious")
