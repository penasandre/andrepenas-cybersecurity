# André Penas — Cybersecurity Portfolio

> Cybersecurity trainee at **BeCode Corp** · Blue Team specialist in training · Belgium, 2026

[![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)](01-Python/)
[![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnubash&logoColor=white)](03-Linux/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)](02-Windows/)
[![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat&logo=wireshark&logoColor=white)](04-Blue-Team/)
[![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=flat&logoColor=white)](04-Blue-Team/)
[![Wazuh](https://img.shields.io/badge/Wazuh-00A9E0?style=flat&logoColor=white)](04-Blue-Team/)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=flat&logo=burpsuite&logoColor=white)](06-Pentesting/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)]()

---

## About

I'm building hands-on skills across the full security spectrum — from network protocols and Linux administration to active exploitation and security regulations. This repository documents my practical work, lab exercises, and research notes produced throughout my training.

**Specialisation:** Blue Team · Incident Response · Threat Detection
**GitHub:** [penasandre](https://github.com/penasandre)

---

## Repository Structure

| Folder | Contents |
|--------|----------|
| [`00-Network`](00-Network/) | Network fundamentals, packet analysis, protocol labs |
| [`01-Python`](01-Python/) | Security scripting, automation, tooling with Python |
| [`02-Windows`](02-Windows/) | Windows administration, PowerShell, Active Directory |
| [`03-Linux`](03-Linux/) | Linux hardening, bash scripting, system administration |
| [`04-Blue-Team`](04-Blue-Team/) | Incident response, threat detection, SIEM analysis, IDS rule engineering |
| [`05-Security-And-Regulations`](05-Security-And-Regulations/) | GDPR, ISO 27001, OWASP, risk frameworks |
| [`06-Pentesting`](06-Pentesting/) | Web application and infrastructure penetration testing |

---

## Skills & Tools

| Category | Tools |
|----------|-------|
| **Blue Team** | Suricata, Wazuh, Wireshark |
| **Web Testing** | Burp Suite Community, browser DevTools, curl |
| **Scripting** | Python, PowerShell, Bash |
| **Password Analysis** | John the Ripper, CyberChef |
| **Network** | Nmap, Wireshark |
| **Frameworks** | OWASP Top 10, OWASP Testing Guide, MITRE ATT&CK |
| **Platforms** | Docker, Linux, Windows |

---

## Work

### Blue Team

| Exercise | Scenario | Skills | Report |
|----------|----------|--------|--------|
| Incident Response | NexaCorp INC-2026-001 — CVE-2011-2523 (vsftpd 2.3.4) | PCAP forensics, Suricata rule engineering, SIEM gap analysis | [View](04-Blue-Team/01-NexaCorp-Incident-Response/) |

<details>
<summary>NexaCorp highlights</summary>

- CVE-2011-2523 vsftpd 2.3.4 backdoor — full attack chain reconstructed from PCAP
- 3 Suricata detection rules written and validated (0 false positives)
- Wazuh gap analysis: zero alerts generated during the incident — documented and reported
- Tools: Wireshark, Suricata, Wazuh

</details>

### Pentesting

| Exercise | Target | Findings | Report |
|----------|--------|----------|--------|
| Web App Pentest | OWASP Juice Shop v19.2.1 | 13 (2 Critical, 5 High) | [View](06-Pentesting/01-OWASP-Juice-Shop/) |

<details>
<summary>OWASP Juice Shop highlights</summary>

- 13 findings: 2 Critical · 5 High · 4 Medium · 2 Low
- Key findings: SQL injection (auth bypass), privilege escalation via mass assignment, DOM XSS, IDOR, hardcoded credentials in JS bundles
- Tools: Burp Suite, curl, PowerShell, CyberChef, John the Ripper, DevTools

</details>

### Programming & Data Engineering

| Project | Stack | Description | Link |
|---------|-------|-------------|------|
| euGreenalytics | Python · Plotly | ETL pipeline processing European electricity market data — interactive dashboards for 6 EU countries (Jan 2022–present) | [View](01-Python/02-eugreenalytics/) |

---

*All security exercises were performed in isolated, controlled environments on intentionally vulnerable targets. No real systems or users were involved.*
