# Incident Report — INC-2026-002
## Linux Privilege Escalation — bru-app-01

---

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-002 |
| **Classification** | CRITICAL — Root-level compromise, data exfiltration risk |
| **Date of Incident** | 2026-05-16 (night of May 16–17) |
| **Date of Report** | 2026-05-19 |
| **Analyst** | André Penas |
| **Organisation** | BeCode Corp SOC — contracted by NexaCorp |
| **Target System** | `bru-app-01` — NexaCorp Brussels internal API server |
| **OS** | Debian 12 (Linux) |
| **Compromised Account** | `svc_api` (uid=1000) |

---

## 1. Executive Summary

On the night of May 16, 2026, NexaCorp's internal API server `bru-app-01` was fully compromised by a threat actor linked to the previous incident INC-2026-001 (Liège server breach). The attacker leveraged an SSH private key stolen during INC-2026-001 to authenticate as the service account `svc_api`, then exploited a misconfigured SUID bit on `/usr/bin/find` to gain root-level access.

With root privileges, the attacker read the system credential file `/etc/shadow`, created a hidden backdoor user account (`it_support`), harvested SSH private keys from user home directories for potential lateral movement, and installed a persistent cron job that continues to execute as root every 10 minutes.

**The attacker likely still has access to this system.** The persistence mechanism remains active and the backdoor account has not been removed. Immediate containment action is required.

---

## 2. How Did the Attacker Get In?

The attacker authenticated via SSH using a **stolen private key** belonging to the `svc_api` service account. This key was obtained during INC-2026-001, when the attacker had shell access to the Liège server — where the `svc_api` private key was stored locally.

The attacker routed all connections through the **Tor anonymisation network** (IP range `185.220.101.0/24`), making source attribution difficult.

A parallel credential stuffing campaign (brute force via password) ran simultaneously from different IP blocks but never succeeded — the attacker did not need it, as they already had the private key.

**Key evidence — auth.log:**
```
2026-05-16T17:43:43 +02:00  bru-app-01  sshd: Accepted publickey for svc_api
from 185.220.101.68 port 58292 ssh2: RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA
```

---

## 3. Attack Chain — Step by Step

### Step 1 — Initial Access via Stolen SSH Key
`2026-05-16T17:43:43 +02:00` | source: `auth.log`

The attacker successfully authenticated as `svc_api` using a private SSH key (fingerprint `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA`) from Tor exit node `185.220.101.68`. This is the same key compromised during INC-2026-001. The attacker repeated this connection across multiple Tor exit nodes throughout the session — a total of 40+ successful publickey logins recorded.

### Step 2 — Parallel Brute Force (background noise)
`2026-05-16T17:45:14 +02:00` | source: `auth.log`

A separate credential stuffing campaign targeting `svc_api` and generic usernames (`admin`, `root`, `backup`, `deploy`, `ubuntu`, `api`, `nexacorp`) ran in parallel from multiple IP ranges — 117 failed attempts in total. This campaign never succeeded and is assessed as automated background noise, not the primary attack vector.

### Step 3 — Privilege Escalation via SUID Misconfiguration
`audit(1778964422.904)` | source: `audit.log`

From the `svc_api` shell, the attacker identified that `/usr/bin/find` had the **SUID bit** incorrectly set with `root` as owner. This means that any user executing `find` runs the process with root-level effective privileges (`euid=0`), regardless of their own user identity.

The attacker executed `find` with the `-exec` flag to run commands directly as root — without ever needing a password.

**Key evidence — audit.log:**
```
uid=1000  euid=0  UID="svc_api"  EUID="root"
exe="/usr/bin/find"  key="suid_escalation"
SYSCALL=execve  success=yes
```

### Step 4 — Credential Dumping (/etc/shadow)
`audit(1778964483.592)` | source: `audit.log`

With root access, the attacker accessed `/etc/shadow` — the Linux file containing password hashes for every account on the system. An initial attempt using `cat` (without root) was denied (`success=no exit=-13`). The attacker subsequently accessed the file via `find -exec` running as `euid=0`, triggering the `key="shadow_access"` audit rule.

**Impact:** Password hashes for all local accounts on `bru-app-01` may be in the attacker's possession. These hashes can be subjected to offline cracking.

### Step 5 — Backdoor Account Creation
`2026-05-16T19:47:07 +02:00` | source: `auth.log`

The attacker created a new local user account designed to blend in with legitimate IT staff:

```
useradd[12909]: new user: name=it_support, UID=1002, GID=1002,
home=/home/it_support, shell=/bin/bash
chpasswd[12917]: password changed for it_support
```

The name `it_support` is deliberately chosen to appear plausible and avoid immediate suspicion. This account provides the attacker with an alternative entry point independent of the `svc_api` key.

### Step 6 — SSH Private Key Harvesting
`audit(1778964483.592)` | source: `audit.log`

The attacker executed `find /home -name id_rsa` repeatedly (using SUID find as root) to locate SSH private keys stored in user home directories. Access to the `.ssh` directory of `svc_api` was recorded.

**Impact:** Any SSH private keys found on `bru-app-01` could be used to access other NexaCorp systems — indicating a risk of further lateral movement beyond this server.

**Key evidence — audit.log:**
```
type=EXECVE msg=audit(1778964483.592): argc=4
a0="find" a1="/home" a2="-name" a3="id_rsa"
```

### Step 7 — Cron Persistence
`2026-05-16T19:50:01 +02:00` | source: `cron.log`

The attacker installed a hidden script at `/tmp/.svc_updater` and configured it to execute automatically as `root` via the system cron scheduler every 10 minutes. The cron job was active from 19:50 and continued executing through at least 23:40 on May 16.

```
CRON[13164]: (root) CMD (/bin/bash /tmp/.svc_updater 2>/dev/null)
```

The `2>/dev/null` flag suppresses all error output, making the execution invisible in standard system logs. The cron entry file (`/etc/cron.d/svc-updater`) was not captured in the audit.log, suggesting it was created before or outside the audit window — however its activity is confirmed by the cron.log.

**Note:** INCIDENT_METADATA described the cron interval as 30 minutes. Log evidence confirms the actual interval is **10 minutes**.

---

## 4. Attack Timeline

| # | Timestamp | Event | Log Source | ATT&CK |
|---|-----------|-------|------------|--------|
| 1 | `2026-05-16T17:43:43 +02:00` | First successful SSH login as `svc_api` from Tor (`185.220.101.68`) using stolen RSA key | auth.log | T1078 |
| 2 | `2026-05-16T17:45:14 +02:00` | Parallel credential stuffing campaign begins (117 failures, never succeeds) | auth.log | T1110 |
| 3 | `audit(1778964422.904)` | SUID `/usr/bin/find` exploited — `svc_api` (uid=1000) obtains root (euid=0) | audit.log | T1548.001 |
| 4 | `audit(1778964483.592)` | `/etc/shadow` access attempted and achieved via SUID find; SSH key harvest begins (`find /home -name id_rsa`) | audit.log | T1003.008 / T1552.004 |
| 5 | `2026-05-16T19:47:07 +02:00` | Backdoor account `it_support` (UID=1002) created with password set | auth.log | T1136.001 |
| 6 | `2026-05-16T19:50:01 +02:00` | Cron persistence activates — `/tmp/.svc_updater` executes as root for the first time | cron.log | T1053.003 |
| 7 | `2026-05-16T23:40:01 +02:00` | Last recorded cron execution in evidence window | cron.log | T1053.003 |

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1078 | Valid Accounts | Authenticated using stolen `svc_api` SSH private key from INC-2026-001 |
| T1110 | Brute Force | Parallel credential stuffing campaign (117 failed attempts) |
| T1548.001 | Abuse Elevation Control — Setuid/Setgid | SUID bit on `/usr/bin/find` used to obtain root (`euid=0`) |
| T1003.008 | OS Credential Dumping — /etc/shadow | `/etc/shadow` accessed as root via SUID find |
| T1136.001 | Create Account — Local Account | Backdoor account `it_support` created post-compromise |
| T1552.004 | Unsecured Credentials — Private Keys | `find /home -name id_rsa` executed to harvest SSH keys |
| T1053.003 | Scheduled Task/Job — Cron | `/etc/cron.d/svc-updater` runs `/tmp/.svc_updater` as root every 10 minutes |
| T1059 | Command and Scripting Interpreter | Commands executed via `find -exec` and `/bin/bash` |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Attacker IP range (SSH via Tor) | `185.220.101.0/24` |
| Brute force IP ranges | `162.247.74.0/24`, `45.142.212.0/24`, `193.32.162.0/24`, `89.248.167.0/24` |
| Compromised account | `svc_api` (uid=1000) |
| Stolen SSH key fingerprint | `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` |
| Backdoor account | `it_support` (uid=1002, gid=1002) |
| Malicious script | `/tmp/.svc_updater` |
| Cron persistence file | `/etc/cron.d/svc-updater` |
| Misconfigured binary | `/usr/bin/find` (SUID bit set, owner: root) |

---

## 7. How Far Did the Attacker Get?

| Area | Status |
|------|--------|
| Shell access as `svc_api` | **Confirmed** |
| Root access via SUID find | **Confirmed** |
| `/etc/shadow` read (all password hashes) | **Confirmed** |
| SSH keys harvested from `/home` | **Confirmed — extent of keys obtained unknown** |
| Backdoor account active | **Confirmed — `it_support` still exists** |
| Cron persistence active | **Confirmed — firing every 10 minutes as root** |
| Lateral movement to other systems | **Unknown — SSH keys may have been reused** |

---

## 8. Immediate Remediation Actions

The following actions must be taken **immediately**, in order:

### Action 1 — Isolate the server
Take `bru-app-01` off the network or block all inbound/outbound connections except for administrative access. The cron job is still running as root. Do not simply reboot — the cron entry survives reboots.

### Action 2 — Remove the persistence mechanism
```bash
rm /etc/cron.d/svc-updater
rm /tmp/.svc_updater
```
Verify no other cron entries exist for unknown scripts:
```bash
ls -la /etc/cron.d/
crontab -l -u root
```

### Action 3 — Delete the backdoor account
```bash
userdel -r it_support
```
Verify no other unexpected accounts exist:
```bash
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3}' /etc/passwd
```

### Action 4 — Remove the SUID bit from /usr/bin/find
```bash
chmod u-s /usr/bin/find
```
Audit all other SUID binaries on the system:
```bash
find / -perm -4000 -type f 2>/dev/null
```
Cross-reference results against [GTFOBins](https://gtfobins.github.io/) to identify any other dangerous SUID misconfigurations.

### Action 5 — Revoke and rotate all SSH keys
The key with fingerprint `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` is compromised. Remove it from all `authorized_keys` files on `bru-app-01` and any other NexaCorp system where it may have been trusted. Issue new keys to legitimate users.

### Action 6 — Force password reset for all local accounts
The attacker obtained `/etc/shadow`. All password hashes are potentially cracked or in the process of being cracked. Force password rotation for all accounts on `bru-app-01` and any accounts that share passwords with this system.

### Action 7 — Investigate INC-2026-001 linkage
The Liège server (INC-2026-001) has not been fully remediated — the attacker retained access after the initial investigation. Confirm that the `svc_api` private key has been removed from the Liège server and that the attacker no longer has any foothold there. Audit all SSH trust relationships between NexaCorp servers.

### Action 8 — Check for lateral movement
Audit SSH authentication logs on all other NexaCorp internal servers for connections using the fingerprint `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` or connections originating from `185.220.101.0/24`.

---

## 9. Recommendations (Medium Term)

- **Implement SSH key management policy**: Private keys must not be stored on servers in plaintext. Use SSH certificates with short TTLs or a secrets management solution.
- **Audit SUID binaries periodically**: No standard utility used for file search or text processing should have the SUID bit set. Establish a baseline and alert on deviations.
- **Block Tor exit nodes at perimeter**: The entire attack was conducted through Tor. Blocking known Tor exit node ranges at the firewall would have prevented access even with a valid key.
- **Enable auditd rules for SUID execution**: The `suid_escalation` rule was already in place and functioned correctly. Ensure alerts from this rule are forwarded to the SIEM and trigger immediate investigation.
- **Implement SSH fail2ban or equivalent**: 117 brute force attempts went unblocked. Automatic IP blocking after a threshold of failures would suppress this noise and reduce attack surface.

---

---

## 10. Phase 2 — Live Detection (Wazuh)

**Live detection date:** 2026-05-20
**SIEM platform:** Wazuh — `https://10.40.0.210`
**Monitored agent:** `tgt-blue06`
**Method:** `lab attack` executed on BeCode workstation; Wazuh Discover monitored in real time (Last 15 min, auto-refresh 5s).

---

### 10.1 Wazuh Alerts — Live Detection Results

| Timestamp | rule.description | rule.id | rule.level | ATT&CK |
|-----------|-----------------|---------|------------|--------|
| 12:00:14 (first hit) | Lab2: /etc/shadow accessed - credential dump attempt | 100201 | **12** | T1003.008 |
| 12:04:04 | Lab2: useradd executed - backdoor account creation | 100202 | 10 | T1136.001 |
| 12:06:06 | Host-based anomaly detection event (rootcheck) | 510 | 7 | — |
| 12:06:08 (first hit) | Lab2: SSH key directory accessed - credential harvest | 100204 | 10 | T1552.004 |
| 12:14:00 | Lab2: useradd executed - backdoor account creation | 100202 | 10 | T1136.001 |
| 12:14:00 | PAM: User changed password | 5555 | 3 | T1136.001 |
| 12:15:58 | Lab2: Cron file modified - persistence mechanism installed | 100203 | 10 | T1053.003 |

**Total Lab2 alerts:** ~35 events across 4 rules (rule 100201 dominant with ~20 hits for /etc/shadow).

**Notable infrastructure alert:** At `12:04:26`, the Wazuh agent reported queue overflow (rule 203, level 9 — "Agent event queue is full. Events may be lost"). The agent recovered at `12:04:29`. This overflow occurred at the peak of attack activity and may have caused event loss during a critical window.

---

### 10.2 Attack Chain Mapping — Phase 1 vs Phase 2

| Attack Step | ATT&CK | Phase 1 Evidence | Phase 2 Wazuh Alert | Detected? |
|-------------|--------|-----------------|--------------------:|-----------|
| SSH login via stolen key | T1078 | auth.log — `Accepted publickey for svc_api` | No alert generated | ❌ **No** |
| Parallel brute force SSH | T1110 | auth.log — 117 failed attempts | No alert generated | ❌ **No** |
| SUID `/usr/bin/find` — privilege escalation | T1548.001 | audit.log — `uid=1000 euid=0 key=suid_escalation` | No alert generated | ❌ **No** |
| `/etc/shadow` access | T1003.008 | audit.log — `key=shadow_access` | rule 100201, level 12 — 20 hits | ✅ **Yes** |
| Backdoor account `it_support` | T1136.001 | auth.log — `useradd[12909]` + `chpasswd` | rule 100202, level 10 + rule 5555 | ✅ **Yes** |
| SSH key harvest (`find /home -name id_rsa`) | T1552.004 | audit.log — `key=ssh_key_access` | rule 100204, level 10 — 9 hits | ✅ **Yes** |
| Cron persistence (`/etc/cron.d/svc-updater`) | T1053.003 | cron.log — CMD `/tmp/.svc_updater` | rule 100203, level 10 | ✅ **Yes** |

**Detection rate: 4 / 7 attack steps (57%)**

The three undetected steps include the initial access vector and the privilege escalation — the two most critical stages of the attack. From a defender's perspective, the SIEM only began generating alerts after the attacker had already gained root access.

---

### 10.3 Detection Gaps

#### Gap 1 — SSH Initial Access (HIGH)

The successful SSH authentication as `svc_api` using a stolen public key from a Tor exit node (`185.220.101.x`) generated no Wazuh alert. The initial compromise of the system was completely invisible to the SIEM.

**Root cause:** The Wazuh agent on `tgt-blue06` does not appear to be forwarding `/var/log/auth.log` in a way that triggers the standard SSH success rules (Wazuh rule 5715), or those rules are not enabled. Successful publickey authentication is not flagged regardless of source IP.

**Remediation:** Configure the Wazuh agent to collect `auth.log`; enable rule 5715 (`sshd: SSH authentication success`); add a custom rule that correlates successful `svc_api` logins against known Tor exit node IP ranges (`185.220.101.0/24`).

#### Gap 2 — SUID Privilege Escalation (CRITICAL)

The exploitation of the SUID bit on `/usr/bin/find` to obtain `euid=0` — the single most dangerous action in the entire attack chain — generated no Wazuh alert. At the moment the attacker achieved root, the SIEM was silent.

**Root cause (probable dual failure):**
1. The auditd rule `-a always,exit -F euid=0 -F uid!=0 -S execve -k suid_escalation` may not be configured on `tgt-blue06`, meaning the event is not audited at the OS level.
2. The Wazuh agent queue overflowed at `12:04:26` (rule 203), coinciding with the peak attack window — any events that were generated may have been dropped before reaching the Wazuh manager.

**Remediation:** See Section 10.4 — proposed rule 100210.

#### Gap 3 — Agent Queue Overflow (MEDIUM — Infrastructure)

The Wazuh agent reached queue capacity during the attack, potentially discarding security-relevant events. This represents a SIEM reliability gap: the system designed to detect attacks was degraded precisely when the attack was most active.

**Remediation:** Increase agent `queue_size` in `ossec.conf`; review auditd rule verbosity to reduce event volume from non-critical syscalls; implement queue monitoring with automated alerting before overflow occurs.

#### Gap 4 — Distributed Brute Force (LOW)

117 SSH authentication failures from multiple IP ranges were not aggregated into a brute force alert. The default Wazuh brute force rules (5710/5720) trigger per source IP, which is evaded by distributing attempts across many IPs.

**Remediation:** Implement a frequency rule that counts total SSH failures against a single target host across all source IPs within a time window.

---

### 10.4 Proposed New Rule — SUID Privilege Escalation Detection

**Target gap:** Gap 2 — undetected SUID abuse resulting in root access (T1548.001)

**Required auditd rule** (add to `/etc/audit/rules.d/privesc.rules` on monitored hosts):

```bash
-a always,exit -F arch=b64 -F euid=0 -F uid!=0 -S execve -k suid_escalation
-a always,exit -F arch=b32 -F euid=0 -F uid!=0 -S execve -k suid_escalation
```

**Proposed Wazuh rule** (add to `/var/ossec/etc/rules/local_rules.xml`):

```xml
<!-- Rule 100210: SUID binary execution — non-root user obtains euid=0 -->
<rule id="100210" level="14">
  <if_group>audit</if_group>
  <field name="data.audit.key">suid_escalation</field>
  <field name="data.audit.euid" type="pcre2">^0$</field>
  <description>CRITICAL: Non-root user executed SUID binary as root - privilege escalation (T1548.001)</description>
  <mitre>
    <id>T1548.001</id>
  </mitre>
  <group>privilege_escalation,suid</group>
</rule>
```

**Logic:** The rule fires whenever auditd records an `execve` syscall where the real UID is non-zero (unprivileged user) but the effective UID is zero (root). This condition is only possible when a SUID binary is involved — it cannot occur under normal, non-exploitative conditions. Level 14 (one step below maximum) ensures the alert surfaces immediately at the top of any SOC dashboard and is appropriate for automated escalation.

**Why this rule matters here:** In INC-2026-002, none of the post-escalation actions — reading `/etc/shadow`, creating `it_support`, harvesting SSH keys, installing cron persistence — would have been possible without this single privilege escalation step. Detecting it would have given defenders the opportunity to contain the incident before any damage was done, rather than only alerting once credential dumping was already underway.

---

*Report prepared by André Penas — BeCode Corp SOC*
*Evidence source: nexacorp-INC2026002-evidence bundle (clean version)*
*All timestamps from auth.log and cron.log are in CEST (UTC+02:00). Audit.log timestamps are Unix epoch.*
*Phase 2 live detection: 2026-05-20, Wazuh agent tgt-blue06.*
