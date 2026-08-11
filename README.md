# Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository documents practical, authorized security projects built to develop skills across enterprise infrastructure, security monitoring, detection engineering, and adversary-informed testing.

My work is evidence-driven: each completed project includes the lab design, implementation process, validation steps, technical findings, screenshots, and lessons learned.

## Completed Project

### [Project 01 — Enterprise Active Directory Detection Lab](project-01-enterprise-ad-detection-lab/)

> **Status:** Complete

An isolated enterprise-style lab that connects Windows domain administration, centralized security telemetry, controlled testing, and detection engineering.

The environment includes:

- A Windows Server domain controller running Active Directory Domain Services and DNS
- A domain-joined Windows workstation
- A Kali Linux system for authorized security validation
- A Splunk Enterprise server for centralized monitoring and alerting
- Splunk Universal Forwarder and Sysmon telemetry

The project validates the complete defensive workflow:

```text
Configure telemetry → Generate controlled activity → Investigate events → Build detections → Create dashboards and alerts → Document results
```

### Key Results

- Deployed the `corp.local` Active Directory domain and joined a Windows workstation
- Validated domain authentication and account-lockout controls
- Investigated Windows Security Event ID `4740`
- Performed authorized Nmap reconnaissance and confirmed SMB signing was required
- Centralized Windows Security, System, Application, and Sysmon logs in Splunk
- Built and tested detections for failed authentication, PowerShell execution, account changes, service installation, and scheduled-task activity
- Created a security-monitoring dashboard and enabled scheduled alerts
- Documented false positives, investigation guidance, limitations, and supporting evidence

[View the complete project documentation and evidence →](project-01-enterprise-ad-detection-lab/)

## Skills Demonstrated

- Active Directory Domain Services and DNS administration
- Windows domain enrollment and identity management
- Windows Security event analysis and audit-policy configuration
- Sysmon deployment and troubleshooting
- Splunk Enterprise and Universal Forwarder configuration
- SPL search development and XML event-field extraction
- Detection engineering, dashboards, reports, and scheduled alerts
- PowerShell administration
- Authorized Nmap reconnaissance and SMB security validation
- False-positive analysis and investigation planning
- Security evidence collection and technical documentation

## Portfolio Direction

This portfolio is developing toward authorized offensive security and red teaming while maintaining strong defensive visibility. Future work will build on the enterprise foundation established in Project 01 through web and API security testing, Active Directory attack-path analysis, vulnerability research, and full-scope adversary simulation.

Future projects will be added here only after implementation and validation are complete.

## Portfolio Principles

- Publish evidence, not unsupported claims
- Use only owned or explicitly authorized systems
- Keep testing isolated, safe, and reversible
- Remove credentials, secrets, and sensitive information
- Document failures, limitations, and false positives honestly
- Make every project reproducible and technically defensible

## About Me

I am a cybersecurity student building hands-on capability in authorized offensive security, Active Directory, Windows security telemetry, Splunk, Sysmon, detection engineering, PowerShell, and security investigation.

This portfolio records my progress through completed, evidence-backed projects rather than unverified claims or unfinished demonstrations.

## Ethical Use

All security testing documented in this portfolio is performed only in isolated lab environments or on systems for which explicit authorization has been granted.
