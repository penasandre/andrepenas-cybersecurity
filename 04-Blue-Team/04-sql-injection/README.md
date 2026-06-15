# INC-2026-004 — SQL Injection & Credential Exfiltration

> Incident response investigation on a SQL injection attack against the NexaCorp employee portal — the threat actor's pivot to the web application layer after server-side remediation.

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-004 |
| **Classification** | High |
| **Target** | `bru-web-01` — NexaCorp employee self-service portal (DVWA, PHP/MySQL) |
| **Attack source** | `172.16.50.10` (external) |
| **Analyst** | André Penas |
| **Date** | 2026-05-30 |

---

## What happened

After three Linux servers were compromised (INC-2026-001 → 003), the same actor switched attack surface and targeted the employee portal. They exploited an unsanitised `id` parameter in the account-lookup form to inject SQL directly into the back-end MySQL database, then enumerated its structure and exfiltrated the complete `users` table.

The attack combined **UNION-based extraction** (fast, visible) with **blind boolean enumeration** (slow, stealthy, character-by-character) across multiple sessions during the day. Five accounts were dumped with their MD5 password hashes.

**Attack chain:**

| # | Technique | ATT&CK |
|---|-----------|--------|
| 1 | Authenticate to portal with valid credentials, set security to `low` | T1078 / T1562 |
| 2 | Error-based probe (`id=1'`) — injection point confirmed | T1190 |
| 3 | `ORDER BY` column count → 2 columns | T1190 |
| 4 | `UNION SELECT` structure probe — column 2 reflected | T1190 |
| 5 | `information_schema` enumeration (db `dvwa`, table `users`) | T1213 |
| 6 | `UNION SELECT user,password FROM users` — full dump (5745 bytes) | T1555 |
| 7 | Blind boolean enumeration (`SUBSTRING`/`ASCII`/`LENGTH`) | T1190 |

---

## Investigation

- Full injection chain reconstructed from `web_access.log` and the packet capture, correlating HTTP response sizes to confirm each extraction step
- **5 accounts confirmed exfiltrated** — `admin`, `j.martin`, `gordonb`, `pablo`, `smithy` (MD5, unsalted; admin hash `5f4dcc3b...` is publicly known)
- 5-technique MITRE ATT&CK mapping and full IOC table (payload patterns, User-Agent, endpoint, timestamps)
- Remediation centred on **parameterised queries** as the only reliable fix, plus bcrypt/argon2id migration, DB least-privilege, and WAF blocking-mode

**Honest reporting:** the report explicitly marks the incomplete missions (Wazuh alert analysis, auth.log credential-reuse check, Suricata rules) as open items, with the auth.log gap flagged as the highest-priority risk.

→ [Full incident report](INC-2026-004_Incident_Report.md)

---

## Four-incident kill chain

| Incident | System | Method | Outcome |
|----------|--------|--------|---------|
| INC-2026-001 | lge-services-01 | FTP backdoor | Initial foothold |
| INC-2026-002 | bru-app-01 | SUID `find` | Root; key harvest |
| INC-2026-003 | lge-files-01 | SSH key pivot; sudo python3 | Root; C2; credential access |
| INC-2026-004 | bru-web-01 | SQL injection | `users` table exfiltrated; 5 accounts compromised |

The pivot to the web layer — out of scope of the earlier server-side remediation — shows adaptive tradecraft and a gap in the response perimeter.

---

## Skills demonstrated

- Web application incident response (SQL injection)
- UNION-based vs blind boolean injection analysis
- HTTP log + PCAP correlation to confirm data exfiltration
- Password hash assessment (MD5 weaknesses, credential-reuse risk)
- MITRE ATT&CK mapping (5 techniques)
- Secure-coding remediation (prepared statements, modern hashing, least-privilege DB)
- Transparent scoping of investigation gaps and open items
