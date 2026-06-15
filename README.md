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
| Incident Response | NexaCorp INC-2026-002 — Linux Privilege Escalation (SUID abuse) | Log analysis, attack chain reconstruction, Wazuh live detection, detection gap analysis | [View](04-Blue-Team/02-linux-privilege-escalation/) |
| Incident Response | NexaCorp INC-2026-003 — Lateral Movement & C2 (CRITICAL) | Multi-host correlation, SSH key-theft pivot, sudo escalation, cron C2 beacon, PCAP network forensics | [View](04-Blue-Team/03-lateral-movement/) |
| Incident Response | NexaCorp INC-2026-004 — SQL Injection & Credential Exfiltration | UNION + blind boolean injection, HTTP/PCAP correlation, hash assessment, secure-coding remediation | [View](04-Blue-Team/04-sql-injection/) |
| Incident Response | NexaCorp INC-2026-005 — OS Command Injection, LFI & Web Shell | Command injection analysis, web shell persistence, Suricata rule engineering with FP analysis | [View](04-Blue-Team/05-command-injection-lfi/) |

<details>
<summary>INC-2026-005 highlights</summary>

- OS command injection via unsanitised ping tool — arbitrary commands as `www-data`, web shell dropped at `/var/www/html/shell.php`, then SSH lateral movement as `j.martin`
- LFI path-traversal attempts correctly assessed as **failed** (identical response sizes) — successful vs failed exploitation distinguished from evidence
- 3 Suricata rules written and validated via PCAP replay — fire on attacker traffic with **zero false positives** (fast.log proof included)
- Same host as INC-2026-004 — actor returned within one week and pivoted vector
- Tools: Suricata, Wireshark, Apache log analysis

</details>

<details>
<summary>INC-2026-004 highlights</summary>

- SQL injection on the employee portal — full `users` table exfiltrated (5 accounts, MD5 hashes)
- Combined UNION-based extraction with blind boolean enumeration across multiple sessions
- HTTP response-size + PCAP correlation used to confirm each extraction step
- Remediation centred on parameterised queries, bcrypt/argon2id, DB least-privilege, WAF blocking mode
- Transparent reporting: incomplete missions flagged as open items, auth.log credential-reuse gap prioritised
- Tools: web access log analysis, Wireshark, hash assessment

</details>

<details>
<summary>INC-2026-003 highlights</summary>

- Critical lateral movement across two hosts — stolen `svc_api` SSH key used to pivot to `lge-files-01` in ~90 seconds
- Root via `sudo python3 NOPASSWD`; hidden `sysupdate` backdoor + cron C2 beacon to `34.251.89.142` (still active at report time)
- C2 beacon confirmed in PCAP — plaintext HTTP every 5 min, output to `/dev/null` to evade logging
- Closes the three-incident kill chain (INC-001 → 003), same actor confirmed by shared Tor IP and reused artefacts
- Tools: Wireshark, Linux log/journal analysis, auditd, MITRE ATT&CK

</details>

<details>
<summary>INC-2026-002 highlights</summary>

- SUID `/usr/bin/find` exploited to obtain root — 7-step attack chain reconstructed from auth.log + audit.log
- Live Wazuh detection: 4/7 steps detected (57%) — 3 critical gaps including initial access and privilege escalation
- Proposed custom Wazuh rule 100210 + auditd configuration to close the SUID detection gap (T1548.001)
- Linked to INC-2026-001 — attacker reused SSH key stolen in previous incident
- Tools: Wazuh, auditd, Linux log analysis

</details>

<details>
<summary>INC-2026-001 highlights</summary>

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

*All security exercises were performed in isolated, controlled environments on intentionally vulnerable targets. No real systems or users were harmed.*
