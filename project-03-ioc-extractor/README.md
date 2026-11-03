# Project 03 — Threat Intel IOC Extractor (ioc-extractor)

A command-line tool that turns a threat-intelligence report into a clean list
of indicators of compromise (IOCs) that security tools can use.

Analysts receive threat reports as blog posts, PDFs converted to text, vendor
alerts and emails. The indicators inside are usually **defanged**
(`hxxps://evil[.]com`) so nobody clicks them, and mixed with noise such as
internal IPs, reference links and file names. Copying them out by hand is slow
and error-prone. ioc-extractor does it in one command.

It needs only the Python standard library and makes **no network calls**.

## What it does

1. **Refangs** common obfuscation styles: `hxxp`, `[.]`, `(.)`, `[dot]`, `[at]`, `(at)`, `[://]`
2. **Extracts** 10 indicator types: IPv4, IPv6, domains, URLs, email addresses,
   MD5, SHA-1 and SHA-256 hashes, CVE IDs and MITRE ATT&CK technique IDs
3. **Filters noise**:
   - private, loopback and link-local IP addresses (`10.x`, `192.168.x`)
   - well-known benign domains used as references (microsoft.com, mitre.org, github.com …)
   - file names that look like domains (`loader.ps1`, `backup.zip`), unless the author defanged them
   - file names in URL paths (`/dl/payload.zip`)
   - version strings that look like IPs (`version 2.4.1.9`)
   - placeholder hashes (`0000…`)
4. **De-duplicates** each indicator and records the sentence it came from as context
5. **Exports** to the format the next tool needs

| Format | Use it for |
|---|---|
| `text` | Quick look in the terminal |
| `json` | Scripts and automation |
| `csv` | Spreadsheets, SIEM lookup tables, block lists |
| `stix` | **STIX 2.1 bundle** for threat-intel platforms such as MISP or OpenCTI |
| `defanged` | Markdown that is safe to paste into chat, tickets or email |

The STIX output creates `indicator` objects with valid STIX patterns, plus
`vulnerability` objects for CVEs and `attack-pattern` objects for ATT&CK
techniques. IDs are deterministic (UUIDv5), so re-running on the same report
updates the same objects instead of creating duplicates.

## Quick start

```bash
python3 ioc_extractor.py samples/sandfox_report.md
python3 ioc_extractor.py samples/sandfox_report.md --format stix -o bundle.json
python3 ioc_extractor.py samples/sandfox_report.md --format csv -o iocs.csv
python3 ioc_extractor.py samples/sandfox_report.md --format defanged
python3 ioc_extractor.py report.html                      # HTML is converted to text first
cat alert.txt | python3 ioc_extractor.py -                # read from stdin
python3 -m unittest discover -s tests -v                  # run the tests
```

Use `--keep-private` or `--keep-benign` to turn the noise filters off.

## Results on the sample report

[`samples/sandfox_report.md`](samples/sandfox_report.md) is a **fictional**
threat brief written for testing. It mixes defanged indicators in several
styles with deliberate noise.

| Type | Extracted | Noise correctly ignored |
|---|---|---|
| IPv4 / IPv6 | 3 C2 and payload IPs, 1 IPv6 | `10.20.30.40`, `192.168.1.15`, version `2.4.1.9` |
| Domains / URLs | 6 domains, 4 URLs (including a shortener and a `.zip` domain) | `learn.microsoft.com`, `attack.mitre.org`, `loader.ps1`, `backup.zip`, `payload.zip` in a URL path |
| Email | 1 sender address | `soc-team@example.com` contact |
| Hashes | 3 SHA-256, 1 SHA-1, 1 MD5 | All-zero placeholder hash |
| CVE / ATT&CK | 2 CVEs, 4 techniques | - |

Example outputs are in [`output/`](output/): the
[STIX 2.1 bundle](output/sandfox_stix_bundle.json), the [CSV](output/sandfox_iocs.csv)
and the [defanged list](output/sandfox_iocs_defanged.md).

## Design decisions

- **Precision over recall.** A false indicator in a block list can block a
  legitimate service, so the filters lean toward dropping doubtful values.
  `--keep-*` flags exist for when an analyst wants everything.
- **Context is kept.** Each indicator carries the sentence it came from, so an
  analyst can see *why* it was in the report (C2 server or victim?).
- **Ambiguous TLDs handled.** `.zip`, `.mov` and `.sh` are real TLDs and common
  file extensions. They are only treated as domains when the author defanged
  them or they appear as a URL host.
- **Offline.** Reports are often sensitive (TLP:AMBER), so nothing is sent anywhere.

## Limitations and next steps

- Domain detection uses a built-in list of common TLDs rather than the full
  Public Suffix List.
- Only text, Markdown and HTML input. PDF input could be added with a PDF library.
- Optional enrichment: look up IPs on AbuseIPDB and hashes on VirusTotal with an API key.
- Push the STIX bundle straight into MISP or OpenCTI through their APIs.

## Connection to my other work

This builds on the backend work I did for **ThreatLens**, my university
capstone threat-intelligence platform, where I developed the APIs and database
for storing and searching threat indicators. ioc-extractor handles the step
before that: getting clean indicators out of unstructured reports.
