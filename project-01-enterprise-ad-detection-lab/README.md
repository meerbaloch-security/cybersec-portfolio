# Project 01: Enterprise Active Directory Detection Lab

> Status: In Progress

## Objective

Build an isolated enterprise-style Active Directory lab where authorised attack techniques can be performed from Kali Linux, investigated through Windows telemetry, and converted into practical security detections.

## Planned Lab Systems

| System | Purpose |
|---|---|
| Kali Linux | Authorised attack simulation and administration |
| Windows Server | Active Directory Domain Services and domain controller |
| Windows Workstation | Domain-joined employee endpoint |
| Splunk Server | Central log collection, searching and detection |
| Optional Workstation | Additional user and lateral-movement testing |

## Project Workflow

1. Build an isolated VirtualBox network.
2. Configure a Windows Active Directory domain.
3. Join a Windows workstation to the domain.
4. Install Sysmon and configure Windows auditing.
5. Forward security telemetry into Splunk.
6. Perform controlled security simulations.
7. Investigate the generated evidence.
8. Create and test Splunk detections.
9. Document findings and defensive recommendations.

## Initial Detection Scenarios

- Repeated failed authentication
- Account lockout
- New local or domain user creation
- Privileged-group membership changes
- Suspicious PowerShell execution
- Scheduled-task creation
- New Windows service creation
- Suspicious process relationships

## Repository Structure

```text
project-01-enterprise-ad-detection-lab/
├── configs/       Configuration files
├── detections/    Splunk searches and detection rules
├── docs/          Architecture and investigation documentation
├── evidence/      Sanitised screenshots and log evidence
├── scripts/       Safe lab automation scripts
└── README.md      Project overview
