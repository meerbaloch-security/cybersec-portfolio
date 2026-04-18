# Project 01 — Network Attack Surface Mapping & Exposure Report

## Target
Metasploitable 2 — 192.168.56.101 (isolated lab environment)

## Summary
Full network enumeration of all 65,535 TCP ports identifying 30 open services.
11 findings documented — 5 Critical, 5 High, 1 Medium.

## Critical Findings
| Finding | CVE | CVSS |
|---------|-----|------|
| vsftpd 2.3.4 backdoor | CVE-2011-2523 | 10.0 |
| OpenSSH weak key generation | CVE-2008-0166 | 10.0 |
| Samba RCE | CVE-2007-2447 | 10.0 |
| UnrealIRCd backdoor | CVE-2010-2075 | 10.0 |
| Bindshell root shell (port 1524) | N/A | 10.0 |

## Tools Used
- Nmap 7.98
- Searchsploit / Exploit-DB
- NVD / NIST SP 800-115
- draw.io

## Files
- scans/ — Raw Nmap XML and text output
- report/cve_mapping.csv — Full CVE spreadsheet
- report/Project01_Report.docx — Full professional report
- evidence/network_topology.png — Network diagram

## Framework
NIST SP 800-115
