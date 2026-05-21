# INC-2026-002 — Linux Privilege Escalation Detection

> Incident response investigation on a root-level Linux compromise via SUID binary abuse — continuation of INC-2026-001 (linked attacker).

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-002 |
| **Classification** | Critical |
| **Target** | `bru-app-01` — NexaCorp Brussels internal API server (Debian 12) |
| **Analyst** | André Penas |
| **Date** | 2026-05-16 |

---

## What happened

An attacker reused an SSH private key stolen during INC-2026-001 to authenticate as the `svc_api` service account on a second NexaCorp server. From there, they exploited a misconfigured SUID bit on `/usr/bin/find` to obtain root access — then dumped credentials, created a backdoor account, harvested SSH keys, and installed cron persistence.

**Attack chain — 7 steps:**

| # | Technique | ATT&CK |
|---|-----------|--------|
| 1 | SSH login via stolen private key (Tor exit node) | T1078 |
| 2 | Parallel brute force campaign (117 failures — background noise) | T1110 |
| 3 | SUID `/usr/bin/find` exploited → `euid=0` (root) | T1548.001 |
| 4 | `/etc/shadow` read — all password hashes extracted | T1003.008 |
| 5 | Backdoor account `it_support` (UID=1002) created | T1136.001 |
| 6 | SSH private keys harvested from `/home` | T1552.004 |
| 7 | Cron persistence: `/tmp/.svc_updater` runs as root every 10 min | T1053.003 |

---

## Phase 1 — Log Analysis

Investigated 4 evidence files: `auth.log`, `audit.log`, `cron.log`, `syslog`.

Reconstructed the full attack chain with timestamps, identified all IOCs, and produced an 8-technique MITRE ATT&CK mapping.

→ [Full incident report](INC-2026-002_Incident_Report.md)

---

## Phase 2 — Live SIEM Detection (Wazuh)

Ran the attack live and monitored Wazuh in real time.

**Result: 4 / 7 attack steps detected (57%)**

| Attack Step | Detected? |
|-------------|-----------|
| SSH initial access | ❌ No alert |
| Brute force campaign | ❌ No alert |
| SUID privilege escalation | ❌ No alert — **most critical gap** |
| `/etc/shadow` credential dump | ✅ rule 100201, level 12 |
| Backdoor account creation | ✅ rule 100202, level 10 |
| SSH key harvest | ✅ rule 100204, level 10 |
| Cron persistence | ✅ rule 100203, level 10 |

The SIEM only started alerting **after** the attacker already had root. The three undetected steps include initial access and privilege escalation — the most critical stages.

**Proposed fix:** Custom Wazuh rule 100210 + auditd configuration to detect SUID abuse in real time (T1548.001). Full rule XML in the report.

---

## Evidence

```
logs/
├── auth.log             — SSH sessions, brute force attempts, account creation
├── audit.log            — Syscall-level events: SUID execution, shadow access, key harvest
├── cron.log             — Cron persistence activation and execution
├── syslog               — General system events
└── INCIDENT_METADATA.txt
```

---

## Skills demonstrated

- Linux log analysis (auth.log, auditd, cron.log)
- Attack chain reconstruction from raw evidence
- SUID privilege escalation — mechanics and detection
- MITRE ATT&CK mapping (8 techniques)
- Wazuh SIEM monitoring and alert interpretation
- Detection gap analysis + custom rule engineering
- Cross-incident correlation (INC-2026-001 → INC-2026-002)
