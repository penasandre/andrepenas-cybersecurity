# NexaCorp — Incident Response & Detection Engineering

**Reference:** INC-2026-001  
**Date:** May 2026 | BeCode Corp  
**Type:** Blue Team — Forensic Analysis + Detection Engineering

---

## Scenario

NexaCorp's internal server (`192.168.10.10`) was compromised on the evening of May 9, 2026. Given a network capture (PCAP) and SIEM logs, the task was to reconstruct the attack, identify what was missed, and build detection rules to prevent recurrence.

---

## Phase 1 — Forensic Analysis

Using Wireshark to analyse the PCAP, the full attack chain was reconstructed:

| Timestamp (UTC) | Event |
|---|---|
| 2026-05-09 20:08 | TCP port scan — attacker probes ports 80, 22, 443, 8080, 8443, 21 |
| 2026-05-09 22:08 | FTP session — exploit trigger sent (`USER <user>:)`) |
| 2026-05-09 22:12 | Server banner captured: `220 (vsFTPd 2.3.4)` |
| 2026-05-10 00:53 | TCP connection to port 6200 — backdoor shell active |
| 2026-05-10 00:53+ | Attacker executes commands as root |

**Vulnerability:** CVE-2011-2523 — vsftpd 2.3.4 contains a deliberately planted backdoor. Sending a username containing `:)` triggers the backdoor, which opens an interactive root shell on port 6200.

**Post-compromise activity confirmed via PCAP stream:**
```
id       → uid=0(root) gid=0(root)
whoami   → root
uname -a → Linux metasploitable 2.6.24-16-server
cat /etc/passwd | head -10
ls /home → ftp, msfadmin, service, user
ifconfig → inet addr: 192.168.10.10
netstat -an | grep LISTEN
```

**SIEM finding:** Wazuh generated **zero alerts** throughout the incident. Detection gap analysis identified missing rules, absent firewall controls, and no vulnerability scanning in place.

---

## Phase 2 — Detection Engineering

Three Suricata rules written and validated against the attack PCAP in offline mode:

```suricata
# Rule 9000001 — Detect vsftpd 2.3.4 vulnerable banner
alert tcp $HOME_NET 21 -> any any (
  msg:"VULNERABLE SERVICE vsftpd 2.3.4 banner detected";
  flow:established,to_client;
  content:"220 (vsFTPd 2.3.4)";
  sid:9000001; rev:1;
)

# Rule 9000002 — Detect CVE-2011-2523 exploit trigger
alert tcp any any -> $HOME_NET 21 (
  msg:"EXPLOIT FTP vsftpd 2.3.4 - Backdoor trigger detected CVE-2011-2523";
  flow:to_server,established;
  content:"USER ";
  content:":)";
  sid:9000002; rev:1;
)

# Rule 9000003 — Detect connection to backdoor port 6200
alert tcp any any -> $HOME_NET 6200 (
  msg:"BACKDOOR vsftpd 2.3.4 - Connection to port 6200 detected";
  sid:9000003; rev:1;
)
```

**Test results:**

| Rule | SID | Alerts | False positives |
|---|---|---|---|
| Banner detection | 9000001 | 1 | None |
| Exploit trigger | 9000002 | 1 | None |
| Backdoor connection | 9000003 | 1 | None |

Rules 9000002 and 9000003 fired at the exact timestamps matching the attack — `2026-05-09 22:08:16` and `2026-05-10 00:53:35`.

---

## Tools

| Tool | Purpose |
|---|---|
| Wireshark | PCAP analysis, TCP stream reconstruction, conversation statistics |
| Suricata | IDS rule writing and offline PCAP validation |
| Wazuh | SIEM — alert review and detection gap analysis |

---

## Skills Demonstrated

- Network traffic forensics (TCP/IP, protocol analysis)
- CVE research and exploit mechanics (CVE-2011-2523)
- IDS rule writing (Suricata)
- False positive analysis
- SIEM gap analysis
- Professional incident reporting

---

## Files

| File | Description |
|---|---|
| [`NexaCorp_INC2026001_Report.md`](NexaCorp_INC2026001_Report.md) | Full incident report — timeline, findings, IOCs, recommendations |
| [`myrules.rules`](myrules.rules) | Suricata detection rules (SIDs 9000001–9000003) |
| `screenshot*.png` | Evidence — Wireshark analysis, Suricata alert output |
