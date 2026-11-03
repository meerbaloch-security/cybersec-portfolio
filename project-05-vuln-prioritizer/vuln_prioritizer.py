#!/usr/bin/env python3
"""vuln-prioritizer: risk-based prioritization of vulnerable dependencies.

Severity scores alone make every scanner report look urgent. This tool finds
known vulnerabilities in your dependencies and ranks them by how likely they
are to actually be exploited, combining three public data sources:

  * OSV.dev      which package versions are vulnerable, and the fixed version
  * CISA KEV     vulnerabilities confirmed as exploited in the wild
  * FIRST EPSS   probability that a CVE is exploited in the next 30 days

Supported inputs: requirements.txt (PyPI, pinned with ==) and
package-lock.json (npm, lockfile v1-v3).

Usage:
    python3 vuln_prioritizer.py samples/requirements.txt
    python3 vuln_prioritizer.py samples/package-lock.json --format markdown -o report.md
    python3 vuln_prioritizer.py requirements.txt --fail-on P1     # CI gate
    python3 vuln_prioritizer.py requirements.txt --cache .vulncache  # reuse downloads

Needs internet access to the three APIs above. No API keys required.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "vuln-prioritizer/1.0 (+https://github.com/meerbaloch-security/cybersec-portfolio)"

# --------------------------------------------------------------------------- #
# Prioritisation policy. Kept in one place so it is easy to explain and tune.
# --------------------------------------------------------------------------- #
EPSS_HIGH = 0.10    # >= 10% chance of exploitation in the next 30 days
EPSS_MEDIUM = 0.01  # >= 1%

TIERS = {
    "P1": "Fix now (days): exploited in the wild, or likely to be exploited and severe",
    "P2": "Fix soon (weeks): likely to be exploited, or critical severity",
    "P3": "Plan (next release): high severity or some exploitation likelihood",
    "P4": "Backlog: low likelihood and lower severity",
}


def prioritise(cvss: float | None, epss: float | None, in_kev: bool) -> tuple[str, str]:
    """Return (tier, reason). Mirrors common practice: exploitation evidence
    first (KEV), then exploitation likelihood (EPSS), then impact (CVSS)."""
    c = cvss or 0.0
    e = epss or 0.0
    if in_kev:
        return "P1", "listed in CISA KEV (known exploited)"
    if e >= EPSS_HIGH and c >= 7.0:
        return "P1", f"EPSS {e:.1%} and CVSS {c:.1f}"
    if e >= EPSS_HIGH:
        return "P2", f"EPSS {e:.1%}"
    if c >= 9.0:
        return "P2", f"critical CVSS {c:.1f}"
    if c >= 7.0 or e >= EPSS_MEDIUM:
        return "P3", f"CVSS {c:.1f}, EPSS {e:.2%}"
    return "P4", f"CVSS {c:.1f}, EPSS {e:.2%}" if cvss is not None else "no CVSS score, low EPSS"


# --------------------------------------------------------------------------- #
# CVSS v3.x base score from a vector string (OSV gives vectors, not scores)
# --------------------------------------------------------------------------- #
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10))


LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


# --------------------------------------------------------------------------- #
# Dependency parsing
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # PyPI | npm


def parse_requirements(text: str) -> tuple[list[Package], list[str]]:
    pkgs, skipped = [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()  # environment markers
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s,]+)$", line)
        if m:
            pkgs.append(Package(re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2), "PyPI"))
        else:
            skipped.append(line)  # unpinned (>=, ~=) cannot be matched to one version
    return pkgs, skipped


def parse_package_lock(text: str) -> tuple[list[Package], list[str]]:
    data = json.loads(text)
    pkgs: dict[tuple[str, str], Package] = {}
    if "packages" in data:  # lockfile v2 / v3
        for path, info in data["packages"].items():
            if not path or "version" not in info or info.get("link"):
                continue
            name = info.get("name") or path.split("node_modules/")[-1]
            pkgs[(name, info["version"])] = Package(name, info["version"], "npm")
    else:  # lockfile v1
        def walk(deps: dict) -> None:
            for name, info in deps.items():
                if "version" in info:
                    pkgs[(name, info["version"])] = Package(name, info["version"], "npm")
                walk(info.get("dependencies", {}))
        walk(data.get("dependencies", {}))
    return sorted(pkgs.values(), key=lambda p: p.name), []


def load_dependencies(path: Path) -> tuple[list[Package], list[str]]:
    text = path.read_text(encoding="utf-8")
    if path.name.endswith(".json"):
        return parse_package_lock(text)
    return parse_requirements(text)


# --------------------------------------------------------------------------- #
# Data sources (network layer is injectable so tests run offline)
# --------------------------------------------------------------------------- #
Fetch = Callable[[str, dict | None], object]


def http_fetch(url: str, body: dict | None = None, retries: int = 3) -> object:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - network errors are retried then raised
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def cached(fetch: Fetch, cache_dir: Path | None) -> Fetch:
    if not cache_dir:
        return fetch
    cache_dir.mkdir(parents=True, exist_ok=True)

    def inner(url: str, body: dict | None = None):
        key = re.sub(r"[^A-Za-z0-9]+", "_", url + json.dumps(body or {}))[-180:]
        f = cache_dir / f"{key}.json"
        if f.exists() and time.time() - f.stat().st_mtime < 86400:
            return json.loads(f.read_text())
        result = fetch(url, body)
        f.write_text(json.dumps(result))
        return result
    return inner


def osv_lookup(pkgs: list[Package], fetch: Fetch) -> dict[Package, list[str]]:
    hits: dict[Package, list[str]] = {}
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]
        resp = fetch(OSV_BATCH, {"queries": queries})
        for pkg, result in zip(chunk, resp.get("results", [])):
            ids = [v["id"] for v in result.get("vulns", [])]
            if ids:
                hits[pkg] = ids
    return hits


def epss_lookup(cves: list[str], fetch: Fetch) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), 50):
        resp = fetch(EPSS_API.format(",".join(cves[i:i + 50])), None)
        for row in resp.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


def kev_lookup(fetch: Fetch) -> dict[str, dict]:
    feed = fetch(KEV_FEED, None)
    return {v["cveID"]: v for v in feed.get("vulnerabilities", [])}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    cves: list[str]
    summary: str
    cvss: float | None
    cvss_source: str
    epss: float | None
    epss_percentile: float | None
    in_kev: bool
    ransomware: bool
    fixed_versions: list[str]
    tier: str = ""
    reason: str = ""
    kev_due: str | None = None
    aliases: list[str] = field(default_factory=list)


def severity_of(vuln: dict) -> tuple[float | None, str]:
    best: float | None = None
    for s in vuln.get("severity", []) + [s for a in vuln.get("affected", []) for s in a.get("severity", [])]:
        if s.get("type") in {"CVSS_V3", "CVSS_V31", "CVSS_V30"}:
            score = cvss3_base(s.get("score", ""))
            if score is not None and (best is None or score > best):
                best = score
    if best is not None:
        return best, "CVSS v3 vector"
    label = (vuln.get("database_specific") or {}).get("severity", "")
    if label.upper() in LABEL_SCORE:
        return LABEL_SCORE[label.upper()], f"advisory label ({label.lower()})"
    return None, "none"


def fixed_versions(vuln: dict, pkg: Package) -> list[str]:
    out = []
    for a in vuln.get("affected", []):
        ap = a.get("package", {})
        if ap.get("ecosystem") != pkg.ecosystem or re.sub(r"[-_.]+", "-", ap.get("name", "")).lower() != \
                (pkg.name if pkg.ecosystem == "PyPI" else ap.get("name", "")).lower():
            continue
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                continue  # commit hashes, not installable versions
            out += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return sorted(set(out), key=_version_key)


def _version_key(v: str) -> tuple:
    """Sortable key for PEP 440 / semver-ish versions. A final release sorts
    after its pre-releases: 2.0.0rc1 < 2.0.0."""
    key = []
    for part in re.split(r"[.\-+]", v.lstrip("v")):
        m = re.match(r"(\d*)(.*)", part)
        key.append((int(m.group(1) or 0), m.group(2) or "~"))
    return tuple(key)


def analyse(pkgs: list[Package], fetch: Fetch = http_fetch) -> list[Finding]:
    hits = osv_lookup(pkgs, fetch)
    vulns: dict[str, dict] = {}
    for ids in hits.values():
        for vid in ids:
            if vid not in vulns:
                vulns[vid] = fetch(OSV_VULN.format(vid), None)

    findings: list[Finding] = []
    seen_cve_per_pkg: set[tuple[str, str]] = set()
    for pkg, ids in hits.items():
        for vid in ids:
            v = vulns[vid]
            cves = sorted({a for a in [v.get("id", "")] + v.get("aliases", []) if a.startswith("CVE-")})
            # The same CVE is often published by several databases (GHSA + PYSEC). Report it once.
            if cves and all((pkg.name, c) in seen_cve_per_pkg for c in cves):
                continue
            seen_cve_per_pkg.update((pkg.name, c) for c in cves)
            score, source = severity_of(v)
            findings.append(Finding(pkg.name, pkg.version, pkg.ecosystem, vid, cves,
                                    (v.get("summary") or v.get("details", "")[:120]).strip(),
                                    score, source, None, None, False, False, fixed_versions(v, pkg),
                                    aliases=v.get("aliases", [])))

    all_cves = sorted({c for f in findings for c in f.cves})
    epss = epss_lookup(all_cves, fetch) if all_cves else {}
    kev = kev_lookup(fetch) if all_cves else {}

    for f in findings:
        es = [epss[c] for c in f.cves if c in epss]
        if es:
            f.epss, f.epss_percentile = max(es)
        kev_hits = [kev[c] for c in f.cves if c in kev]
        if kev_hits:
            f.in_kev = True
            f.ransomware = any(k.get("knownRansomwareCampaignUse", "").lower() == "known" for k in kev_hits)
            f.kev_due = kev_hits[0].get("dueDate")
        f.tier, f.reason = prioritise(f.cvss, f.epss, f.in_kev)
    findings.sort(key=lambda f: (f.tier, -(f.epss or 0), -(f.cvss or 0)))
    return findings


def next_fix(f: Finding) -> str | None:
    """Smallest fixed version newer than the one installed."""
    newer = [v for v in f.fixed_versions if _version_key(v) > _version_key(f.version)]
    return newer[0] if newer else None


def upgrade_plan(findings: list[Finding]) -> list[dict]:
    """Smallest upgrade per package that fixes everything we know a fix for."""
    plan: dict[str, dict] = {}
    for f in findings:
        p = plan.setdefault(f.package, {"package": f.package, "current": f.version, "target": None,
                                        "fixes": 0, "worst_tier": f.tier, "no_fix": 0})
        p["worst_tier"] = min(p["worst_tier"], f.tier)
        fix = next_fix(f)
        if fix:
            p["fixes"] += 1
            if p["target"] is None or _version_key(fix) > _version_key(p["target"]):
                p["target"] = fix
        else:
            p["no_fix"] += 1
    return sorted(plan.values(), key=lambda p: (p["worst_tier"], p["package"]))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def stats(findings: list[Finding]) -> dict:
    high_cvss = [f for f in findings if (f.cvss or 0) >= 7.0]
    urgent = [f for f in findings if f.tier == "P1"]
    return {
        "total": len(findings),
        "by_tier": {t: sum(1 for f in findings if f.tier == t) for t in TIERS},
        "cvss_high_or_critical": len(high_cvss),
        "in_kev": sum(f.in_kev for f in findings),
        "urgent": len(urgent),
        "noise_reduction": (1 - len(urgent) / len(high_cvss)) if high_cvss else 0.0,
    }


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.1%}" if x >= 0.001 else f"{x:.3%}"


def to_text(findings: list[Finding], pkgs: list[Package], skipped: list[str]) -> str:
    s = stats(findings)
    out = [f"Scanned {len(pkgs)} packages: {s['total']} known vulnerabilities",
           f"  {s['cvss_high_or_critical']} rated High/Critical by CVSS alone, but only {s['urgent']} need fixing now (P1)",
           f"  Tiers: " + ", ".join(f"{t}={n}" for t, n in s["by_tier"].items()), ""]
    out.append(f"{'Tier':<5}{'Package':<22}{'Vuln':<22}{'CVE':<17}{'CVSS':>5}{'EPSS':>9}  KEV  Fix")
    for f in findings:
        out.append(f"{f.tier:<5}{(f.package + ' ' + f.version)[:21]:<22}{f.vuln_id[:21]:<22}"
                   f"{(f.cves[0] if f.cves else '-'):<17}{(f'{f.cvss:.1f}' if f.cvss is not None else '-'):>5}"
                   f"{_pct(f.epss):>9}  {'YES' if f.in_kev else '   '}  {next_fix(f) or 'none'}")
    if skipped:
        out += ["", f"Skipped {len(skipped)} unpinned requirement(s): {', '.join(skipped)}"]
    return "\n".join(out)


def to_markdown(findings: list[Finding], pkgs: list[Package], skipped: list[str], source: str) -> str:
    s = stats(findings)
    out = [f"# Vulnerability priority report: `{source}`", "",
           f"Scanned **{len(pkgs)}** packages and found **{s['total']}** known vulnerabilities.", "",
           f"> **{s['cvss_high_or_critical']}** are rated High or Critical by CVSS alone. "
           f"After adding real-world exploitation data, **{s['urgent']}** need fixing now"
           + (f" — a **{s['noise_reduction']:.0%}** reduction in urgent work." if s["cvss_high_or_critical"] else "."),
           "", "| Tier | Meaning | Count |", "|---|---|---|"]
    out += [f"| **{t}** | {TIERS[t]} | {s['by_tier'][t]} |" for t in TIERS]
    out += ["", "## Upgrade plan", "", "| Package | Current | Upgrade to | Vulns fixed | Worst tier |", "|---|---|---|---|---|"]
    for p in upgrade_plan(findings):
        target = p["target"] or "no fixed version yet"
        out.append(f"| {p['package']} | {p['current']} | **{target}** | {p['fixes']}"
                   + (f" ({p['no_fix']} without fix)" if p["no_fix"] else "") + f" | {p['worst_tier']} |")
    out += ["", "## All findings", "",
            "| Tier | Package | Advisory | CVE | CVSS | EPSS (percentile) | KEV | Fixed in | Why this tier |",
            "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        kev = ("**Yes**" + (" (ransomware)" if f.ransomware else "")) if f.in_kev else "No"
        pct = f" ({f.epss_percentile:.0%})" if f.epss_percentile is not None else ""
        out.append(f"| {f.tier} | {f.package} {f.version} | [{f.vuln_id}](https://osv.dev/vulnerability/{f.vuln_id}) | "
                   f"{', '.join(f.cves) or '-'} | {f'{f.cvss:.1f}' if f.cvss is not None else '-'} | "
                   f"{_pct(f.epss)}{pct} | {kev} | {next_fix(f) or '-'} | {f.reason} |")
    if skipped:
        out += ["", f"_Skipped {len(skipped)} unpinned requirement(s): {', '.join(f'`{x}`' for x in skipped)}._"]
    out += ["", "---", "Data: [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), "
            "[FIRST EPSS](https://www.first.org/epss/). EPSS is the probability of exploitation activity in the next 30 days."]
    return "\n".join(out)


def main(argv: list[str] | None = None, fetch: Fetch | None = None) -> int:
    ap = argparse.ArgumentParser(description="Rank vulnerable dependencies by real-world exploitation risk.")
    ap.add_argument("input", type=Path, help="requirements.txt or package-lock.json")
    ap.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--cache", type=Path, help="Cache API responses here for 24 hours")
    ap.add_argument("--fail-on", choices=list(TIERS), help="Exit 1 if any finding is in this tier or more urgent")
    args = ap.parse_args(argv)

    pkgs, skipped = load_dependencies(args.input)
    findings = analyse(pkgs, cached(fetch or http_fetch, args.cache))

    if args.format == "markdown":
        rendered = to_markdown(findings, pkgs, skipped, args.input.name)
    elif args.format == "json":
        rendered = json.dumps({"stats": stats(findings), "upgrade_plan": upgrade_plan(findings),
                               "findings": [asdict(f) for f in findings], "skipped": skipped}, indent=2)
    else:
        rendered = to_text(findings, pkgs, skipped)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(rendered)

    if args.fail_on and any(f.tier <= args.fail_on for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
