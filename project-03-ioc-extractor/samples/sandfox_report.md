# Threat Brief: SANDFOX Phishing Campaign Targeting Logistics Firms

> **FICTIONAL SAMPLE.** This report, the threat group, every domain, IP address
> and hash below are invented for testing ioc-extractor. IP addresses use the
> reserved documentation ranges, and the hashes are SHA-256/SHA-1/MD5 digests of
> placeholder strings, not real malware.

**TLP:CLEAR · Published 2 November 2026**

## Summary

Since October 2026 the SANDFOX group has sent invoice-themed phishing emails
to logistics companies in the Gulf and Australia. Emails come from
billing[at]quick-freight-billing[.]top and link to a fake document portal at
hxxps://docs-share-portal[.]xyz/view?id=44812. Victims who open the attached
invoice are infected with a loader that beacons to its command-and-control
server every 60 seconds.

Initial access uses spearphishing attachments (T1566.001), and the loader runs
through PowerShell (T1059.001). C2 traffic uses HTTPS (T1071.001), and the group
exfiltrates data over the same channel (T1041). In two cases the actors exploited
CVE-2023-23397 in Microsoft Outlook, and one victim was hit via CVE-2024-21413.

## Infrastructure

| Role | Indicator |
|---|---|
| C2 server | 203.0.113[.]45 |
| C2 server (backup) | 198.51.100(.)23 |
| Payload host | hxxp://192.0.2[.]77/files/invoice_viewer.exe |
| Phishing domain | quick-freight-billing[.]top |
| Fake portal | docs-share-portal[.]xyz |
| Staging domain | cdn-update-sync[.]com |
| IPv6 C2 | 2001:db8:4f2a::17 |

The actors also registered logistics-tracking[dot]online and briefly used
a short link at hxxps://bit[.]ly/sandfox-inv that redirected to the portal.
Archive payloads were hosted at hxxps://cdn-update-sync[.]com/dl/payload.zip,
and one phishing kit page used the domain invoice-portal[.]zip.

## Files

| File | SHA-256 |
|---|---|
| Invoice_88231.pdf.exe (loader) | 424c06f6bb950f45d28ec624fbb3c2788259bc95bd6dc6075db1faa73c38fc98 |
| statement.xlsm (macro document) | 5ea7549a4e8cadde2656db885741c15252114e36834b640d209291db4acdfc81 |
| sync.dll (second stage) | 5e68f6984e5c7f8816462018f6dcab421d5f5e2a3d826f0cbfb8461bb439c8b5 |

The loader's SHA-1 is b9caa74cc372fc23768a87ce00a61a197b7ce399 and its MD5 is
7ba4d347974e4707070b179db633dff8.

## Noise that should NOT be extracted

Analysts reviewed the activity with Microsoft guidance at
https://learn.microsoft.com/security and mapped it on https://attack.mitre.org.
The sample was uploaded from an internal sandbox at 10.20.30.40 and the analyst
workstation 192.168.1.15. The loader drops loader.ps1, config.json and
readme.txt, and archives named backup.zip. Placeholder hash:
0000000000000000000000000000000000000000000000000000000000000000.
Tool version 2.4.1.9 was used for analysis.

## Recommendations

- Block the domains, URLs and IP addresses above at the proxy and firewall.
- Search email logs for the sender address and the subject "Invoice overdue".
- Hunt for the file hashes in EDR telemetry.
- Patch Outlook against CVE-2023-23397 and CVE-2024-21413.
- Report sightings to soc-team (at) example.com.
