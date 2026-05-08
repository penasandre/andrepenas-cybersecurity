# Python Network Scanner

**Group project** — BeCode Corp, 2026  
**Repository:** [charlescambier/python-network-scanner](https://github.com/charlescambier/python-network-scanner)  
**Contribution:** Equal across all team members

---

## What it does

A lightweight, configuration-driven network reconnaissance tool that:

- Pings a range of IPv4 addresses to identify live hosts
- Performs TCP port scans on responsive systems
- Classifies each port as **OPEN**, **CLOSED**, or **FILTERED**
- Exports results to CSV for reporting

---

## Project structure

```
python-network-scanner/
├── main.py       — Orchestrates the scan workflow
├── config.py     — Loads and validates .env configuration
├── utils.py      — Core network functions (ping, TCP connect)
├── .env          — Runtime parameters (IP range, ports, timeout)
└── reports/      — CSV output directory
```

---

## Key concepts applied

- **TCP port scanning** via raw socket connections and errno-based status classification
- **Host discovery** using system ping with cross-platform flag handling (`-n` Windows / `-c` Unix)
- **Configuration management** with python-dotenv and runtime validation
- **IP range generation** using the standard library `ipaddress` module
- **Structured output** — CSV export for offline analysis and reporting

---

## Tools & libraries

| Library | Role |
|---------|------|
| `socket` | TCP connection attempts |
| `subprocess` | Execute system ping |
| `ipaddress` | Parse and iterate IPv4 ranges |
| `csv` | Write scan results |
| `python-dotenv` | Load `.env` configuration |
| `platform` / `errno` | Cross-platform compatibility |

---

## Ethical note

This tool is intended **only** for systems and networks you own or are explicitly authorized to test.
