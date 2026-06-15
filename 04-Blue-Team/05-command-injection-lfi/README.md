# INC-2026-005 — OS Command Injection, LFI & Web Shell

> Incident response investigation on an OS command injection attack against the NexaCorp employee portal, including Suricata detection rule engineering with proven false-positive analysis.

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-005 |
| **Classification** | Confidential — High |
| **Target** | `bru-web-01` — NexaCorp employee portal (DVWA) |
| **Attack source** | `172.16.50.10` (external) |
| **Analyst** | André Penas |
| **Date** | 2026-06-05 |

---

## What happened

One week after INC-2026-004, the same actor returned to `bru-web-01` and pivoted to a new vector. The portal's diagnostic ping tool passed the `ip` parameter straight to the OS, so appending `;<command>` let the attacker run arbitrary commands as `www-data`. They mapped the system, then wrote a PHP web shell to the web root and used valid `j.martin` credentials to establish persistent SSH access.

A separate file-viewer feature was probed for Local File Inclusion (path traversal) but **all LFI attempts failed** — confirmed by identical 3868-byte responses across every traversal payload.

**Attack chain:**

| # | Technique | ATT&CK |
|---|-----------|--------|
| 1 | Authenticate to portal with `j.martin` credentials | T1078 |
| 2 | Command injection (`127.0.0.1;id` / `whoami` / `cat /etc/passwd`) | T1059 |
| 3 | LFI path-traversal probes (`page=../../../../etc/passwd`) — **failed** | T1083 |
| 4 | Web shell written to `/var/www/html/shell.php` | T1505.003 |
| 5 | Web shell used (`GET /shell.php?cmd=...`) | T1505.003 |
| 6 | SSH lateral movement as `j.martin` (3 sessions) | T1021.004 |

---

## Investigation

- Full timeline reconstructed from the Apache access log and auth.log, decoding every URL-encoded payload
- Clear distinction drawn between the **successful** command injection and the **failed** LFI, evidenced by response-size analysis
- Web shell and dual persistence (web shell + SSH) documented, linked back to INC-2026-004 on the same host

**Detection engineering:** wrote and validated **3 Suricata rules** (command-separator in POST body, path traversal in URI, `/etc/passwd` content in server response). Rules were tested by replaying the PCAP through Suricata — confirmed to fire on attacker traffic with **zero false positives** on employee or background-scanner traffic, with the `fast.log` proof included.

→ [Full incident report](INC-2026-005_Incident_Report.md)

---

## Skills demonstrated

- Web application incident response (OS command injection, LFI)
- Distinguishing successful vs failed exploitation from log evidence
- Web shell / persistence detection
- **Suricata detection rule engineering** with PCAP replay validation
- False-positive analysis for production-ready rules
- MITRE ATT&CK mapping
- Layered remediation (input allowlisting, WAF, least-privilege web server)
