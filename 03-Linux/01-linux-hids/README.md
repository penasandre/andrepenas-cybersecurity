# Linux HIDS — Host Intrusion Detection System

**Group project** — BeCode Corp, 2026  
**Repository:** [DogukanGNDZ/Linux_HIDS](https://github.com/DogukanGNDZ/Linux_HIDS)  
**Contribution:** Equal across all team members

---

## What it does

A modular Host Intrusion Detection System for Linux servers written entirely in Bash. It monitors system activity across five areas and generates severity-scored alerts to detect suspicious behaviour and potential breaches.

```
main.sh                        — Orchestrator (requires root)
config/config.cfg              — Thresholds and parameters
script/
├── alerting.sh                — Log-based attack detection
├── file_integrity.sh          — SHA256 baseline comparison
├── process_network_audit.sh   — Process and network anomalies
├── system_health.sh           — CPU, memory, disk, network
└── user_activity.sh           — Login behaviour and account changes
baseline/                      — Known-good snapshots
logs/hids.log                  — Centralised alert output
```

---

## Modules

### alerting.sh — Log-based intrusion detection
Parses `journalctl` for security events and assigns severity scores:

| Score | Level | Examples |
|-------|-------|---------|
| +1 | INFO | General log entries |
| +5 | WARNING | Sudo failures, service crashes |
| +10 | CRITICAL | SSH brute force, kernel panics, OOM kills |

Outputs JSON-formatted alerts to the central log file.

### file_integrity.sh — File integrity monitoring
- Creates SHA256 baseline hashes on first run
- Detects file additions, modifications, and deletions against baseline
- Flags new SUID binaries (privilege escalation risk)
- Monitors world-writable files and changes in `/boot/`
- Monitored paths include: `/etc/sudoers`, `/etc/shadow`, `/etc/passwd`, crontab files

### process_network_audit.sh — Process and network audit
- Lists all listening ports and the processes behind them
- Detects executables running from suspicious paths (`/tmp`, `/var/tmp`, `/dev/shm`)
- Identifies active outbound connections (potential C2 beaconing)
- Reports top 5 CPU-consuming processes

### system_health.sh — Resource monitoring
Configurable thresholds from `config.cfg`:

| Metric | WARNING | CRITICAL |
|--------|---------|---------|
| Memory | 50% | 70% |
| Disk (root) | 70% | 90% |
| Network errors | Any | — |

### user_activity.sh — User and login monitoring
- Compares logged-in users against a known-users baseline
- Detects newly created accounts
- Triggers alert if SSH failures exceed threshold (default: 5)
- Flags logins outside operating hours (06:00–22:00)
- Identifies IPs with multiple failed attempts

---

## Key concepts applied

- **Defensive security** — detection without modification of target systems
- **File integrity monitoring** with cryptographic hashing (SHA256)
- **Log analysis** using `journalctl`, `awk`, `grep`
- **Network auditing** with `ss` and process correlation
- **Severity scoring** and structured JSON alerting
- **Bash modular design** — single orchestrator calling independent modules
- **Configuration-driven thresholds** for adaptable deployment

---

## Tools & utilities

`bash` · `journalctl` · `sha256sum` · `ss` · `who` · `last` · `awk` · `grep` · `comm`

Requires **root/sudo** for full functionality.

---

## Ethical note

This tool is intended for monitoring systems you own or are explicitly authorised to administer. It is a defensive security tool — not intended for use on systems without administrative rights.
