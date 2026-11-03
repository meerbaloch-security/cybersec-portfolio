# Project 05 — Risk-Based Vulnerability Prioritizer (vuln-prioritizer)

Dependency scanners report hundreds of vulnerabilities, and most of them are
rated "High" or "Critical". Teams can't fix everything at once, and a severity
score (CVSS) measures how bad a flaw *could* be, not whether attackers are
actually using it.

vuln-prioritizer finds known vulnerabilities in a project's dependencies and
ranks them by **real-world exploitation risk**, combining three free public
data sources the way mature vulnerability-management teams do:

| Source | Answers |
|---|---|
| [OSV.dev](https://osv.dev) | Which of my package versions are vulnerable, and which version fixes it? |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Has this vulnerability been **exploited in the wild**? Used in ransomware? |
| [FIRST EPSS](https://www.first.org/epss/) | What is the **probability** it gets exploited in the next 30 days? |

Standard library only. No API keys needed.

## Results from a live scan

GitHub Actions scans two deliberately outdated dependency files every week
using live data. Results from **3 November 2026**:

| Project | Packages | Known vulns | High/Critical by CVSS | Need fixing now (P1) | Urgent work cut by |
|---|---|---|---|---|---|
| Python ([requirements.txt](samples/requirements.txt)) | 11 | 177 | 99 | **12** | **88%** |
| Node.js ([package-lock.json](samples/package-lock.json)) | 8 | 48 | 21 | **3** | **86%** |

A few examples show why severity alone misleads:

- **Pillow, CVE-2023-4863** (the libwebp heap overflow) has a CVSS of 8.8,
  lower than dozens of other findings. But it is in **CISA KEV**, meaning it
  has been exploited in the wild, so it is ranked first.
- **Django, CVE-2022-34265** (SQL injection, CVSS 9.8) has a **73.6% EPSS**
  score, so it goes to P1.
- Many other **CVSS 9.8** findings have EPSS scores of 1–6%. They are still
  serious, so they go to P2, but they don't jump the queue ahead of
  vulnerabilities attackers are actively using.

The tool also produces an **upgrade plan**: for each package, the smallest
version that fixes every known issue. For example, axios `0.21.0` → `0.33.0`
fixes 25 vulnerabilities without a major-version jump.

Full reports: [Python](output/requirements_report.md) · [Node.js](output/npm_report.md)

## How priorities are assigned

The rules live in one function (`prioritise`) so they are easy to explain and tune:

| Tier | Rule | Meaning |
|---|---|---|
| **P1** | In CISA KEV, **or** EPSS ≥ 10% **and** CVSS ≥ 7 | Fix now (days) |
| **P2** | EPSS ≥ 10%, **or** CVSS ≥ 9 | Fix soon (weeks) |
| **P3** | CVSS ≥ 7, **or** EPSS ≥ 1% | Plan for the next release |
| **P4** | Everything else | Backlog |

The order follows the evidence: confirmed exploitation first (KEV), then
predicted exploitation (EPSS), then potential impact (CVSS).

## Quick start

```bash
python3 vuln_prioritizer.py samples/requirements.txt
python3 vuln_prioritizer.py samples/package-lock.json --format markdown -o report.md
python3 vuln_prioritizer.py requirements.txt --format json -o report.json
python3 vuln_prioritizer.py requirements.txt --fail-on P1     # CI gate: exit 1 if anything is P1
python3 vuln_prioritizer.py requirements.txt --cache .vulncache  # reuse API responses for 24h
python3 -m unittest discover -s tests -v                      # offline tests, no network needed
```

Supports `requirements.txt` (pinned `==` versions; unpinned lines are listed
as skipped) and npm `package-lock.json` (lockfile v1, v2 and v3, including
nested dependencies).

## Engineering details

- **CVSS v3 calculator built in.** OSV provides CVSS *vector strings*, not
  scores, so the tool calculates base scores using the official FIRST
  formulas. These are tested against reference vectors (9.8, 10.0, 7.8, 6.1 …).
  If no vector exists, it falls back to the advisory's severity label.
- **De-duplication.** The same CVE is often published by several databases
  (GitHub Advisories and PyPA), so each CVE is reported once per package.
- **Batching and caching.** OSV queries are batched (up to 500 packages per
  request) and EPSS lookups go 50 CVEs at a time. Responses can be cached for
  24 hours.
- **Testable offline.** The network layer is injected, so 9 unit tests run
  against fake fixture data shaped like the real APIs.
- **Weekly scheduled scan** in GitHub Actions, because vulnerability data
  changes daily even when the code doesn't.

## Limitations and next steps

- Only direct version matching. It doesn't check whether the vulnerable
  function is actually reachable from your code (reachability analysis).
- Python support requires pinned versions; reading `poetry.lock` or
  `uv.lock` would remove that restriction.
- CVSS v4 vectors aren't scored yet; the advisory label is used instead.
- Next: add asset context (internet-facing vs internal) as a fourth factor,
  similar to CISA's SSVC decision model.
