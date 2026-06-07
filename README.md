```
 ██████╗██╗   ██╗███████╗██╗   ██╗███████╗
██╔════╝██║   ██║██╔════╝╚██╗ ██╔╝██╔════╝
██║     ██║   ██║█████╗   ╚████╔╝ █████╗  
██║     ╚██╗ ██╔╝██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╗ ╚████╔╝ ███████╗   ██║   ███████╗
 ╚═════╝  ╚═══╝  ╚══════╝   ╚═╝   ╚══════╝
```

<div align="center">

**CVEye** — *See every threat. Miss nothing.*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](https://github.com/AryanWaghere24/CVEye)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()
[![NVD API](https://img.shields.io/badge/Powered%20by-NVD%20API%20v2-red?style=for-the-badge)](https://nvd.nist.gov/developers/vulnerabilities)

</div>

---

## What is CVEye?

CVEye is a **production-grade, multi-threaded vulnerability scanner** written in pure Python that combines TCP banner grabbing, intelligent service/version fingerprinting, and live NVD CVE database lookups into a single powerful CLI tool. Point it at any authorized target, and within seconds it maps every open port to its running software, queries the National Vulnerability Database for matching CVEs, scores each finding by CVSS severity, and delivers a color-coded terminal dashboard alongside both JSON and plain-text reports — giving you a clear, actionable picture of your attack surface without spinning up bloated enterprise tooling.

---

## Why CVEye?

| Feature | CVEye | Manual `nmap` + NVD browsing | Generic scanners |
|---|:---:|:---:|:---:|
| Banner grabbing + version detection | ✅ | ✅ (manual) | ⚠️ Partial |
| Live NVD CVE API lookup | ✅ | ❌ Manual | ⚠️ Outdated DB |
| CVSS v3.1 scoring & severity labels | ✅ | ❌ | ⚠️ v2 only |
| Color-coded terminal dashboard | ✅ | ❌ | ❌ |
| JSON + text report export | ✅ | ❌ | ⚠️ Paid |
| Multi-threaded scanning | ✅ | ✅ | ⚠️ Varies |
| CVE detail view (desc, refs, patch) | ✅ | ❌ | ⚠️ Paid |
| Zero external agents / no install bloat | ✅ | ❌ | ❌ |
| 100% Python, single file | ✅ | ❌ | ❌ |

---

## Features

🔍 **Banner Grabbing & Service Fingerprinting**  
Raw TCP + TLS banner capture with 30+ regex signatures covering SSH, HTTP servers, FTP daemons, mail servers, databases, and more.

🗄️ **Live NVD CVE Database Lookup**  
Queries the [NVD CVE 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) in real-time. Every detected service is matched against the latest published CVEs — no stale local databases.

📊 **CVSS v3.1 / v3.0 / v2 Scoring**  
Parses full CVSS base scores and vector strings. Severity auto-labelled: `CRITICAL ≥ 9.0` / `HIGH ≥ 7.0` / `MEDIUM ≥ 4.0` / `LOW > 0`.

🎨 **Color-Coded CLI Dashboard**  
Post-scan summary with severity breakdown and ASCII bar charts rendered right in your terminal. No browser, no GUI needed.

⚡ **Multi-Threaded Port Scanning**  
`ThreadPoolExecutor`-powered scanning with a configurable thread count (default: 50). Scan a full port range in seconds.

📁 **Dual Report Export**  
Auto-saves timestamped `.json` (machine-readable, CI/CD ready) and `.txt` (human-readable) reports after every scan.

🔬 **CVE Detail View**  
Pass `--detail` for full CVE descriptions, CVSS vector strings, patch advisories, and reference URLs printed inline per finding.

🛡️ **Responsible by Design**  
Prominent authorization warnings in the banner, docstring, and help text. Built for defenders.

---

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/AryanWaghere24/CVEye.git
cd CVEye

# 2. Install dependencies
pip install -r requirements.txt
```

### Requirements

```
requests
colorama
tabulate
```

Or install manually:
```bash
pip install requests colorama tabulate
```

### Optional — NVD API Key *(recommended)*

Without an API key, NVD enforces a rate limit of **5 requests / 30 seconds**.  
With a free key, it jumps to **50 requests / 30 seconds** — strongly recommended for wide port ranges.

👉 Get your free key: [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

---

## Usage

```bash
# Basic scan — comma-separated ports
python3 cve_scanner.py --target 192.168.1.1 --ports 22,80,443

# Port range scan with more threads
python3 cve_scanner.py --target 10.0.0.5 --ports 1-1024 --threads 100

# Full detail view (CVE descriptions + reference URLs)
python3 cve_scanner.py --target myserver.local --ports 80,443,8080 --detail

# With NVD API key for higher rate limits
python3 cve_scanner.py --target 10.0.0.1 --ports 22,3306 --nvd-api-key YOUR_KEY

# Specify output filenames manually
python3 cve_scanner.py --target 10.0.0.1 --ports 22,80 \
    --output-json results.json --output-text results.txt
```

### All Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Target host (IP or hostname) |
| `--ports` | `-p` | Ports: `22,80,443` or `1-1024` or mixed |
| `--threads` | `-T` | Thread count for scanning (default: `50`) |
| `--nvd-api-key` | `-k` | NVD API key for higher rate limits |
| `--max-cves` | | Max CVEs per service (default: `10`) |
| `--detail` | `-d` | Show CVE descriptions + refs in terminal |
| `--output-json` | | Save JSON report to specified file |
| `--output-text` | | Save text report to specified file |
| `--output` | `-o` | Auto-save both with timestamped filenames |

---

## Sample Output

```
  SCAN SUMMARY  ·  192.168.1.100  ·  2024-11-14 21:03:17
════════════════════════════════════════════════════════════

Open Ports Scanned    4
Total CVEs Found      11
Scan Duration         6.42s

  SEVERITY BREAKDOWN

  CRITICAL    ██████████████████████████████  4
  HIGH        ████████████████████            3
  MEDIUM      ██████████                      3
  LOW         ███                             1

▸ PORT 22/SSH  OpenSSH 8.9p1
  CVE ID            CVSS  Severity    Published
  CVE-2023-38408     9.8  CRITICAL    2023-07-19
  CVE-2023-28531     5.0  MEDIUM      2023-03-20
```

---

## Project Structure

```
CVEye/
│
├── cve_scanner.py        # Main scanner — single-file, fully self-contained
├── requirements.txt      # Python dependencies
├── README.md             # You are here
└── LICENSE               # MIT License
```

---

## Supported Service Signatures

CVEye fingerprints the following services out of the box:

| Category | Services |
|---|---|
| **Remote Access** | OpenSSH, Cisco SSH, Microsoft RDP, VNC |
| **Web Servers** | Apache HTTP Server, nginx, Microsoft IIS, lighttpd, LiteSpeed |
| **App Servers** | Apache Tomcat, JBoss, Eclipse Jetty |
| **CMS / Frameworks** | WordPress, Drupal, Joomla, PHP |
| **FTP** | vsftpd, ProFTPD, FileZilla Server, Pure-FTPd |
| **Mail** | Postfix, Exim, Sendmail, Dovecot |
| **Databases** | MySQL, MariaDB, PostgreSQL, MongoDB, Redis |

---

## Responsible Disclosure

> ⚠️ **Authorized use only.**  
> CVEye is designed for security professionals, researchers, and system owners testing their **own infrastructure** or systems they have **explicit written permission** to test.  
> Unauthorized scanning is illegal under the CFAA, UK Computer Misuse Act, and equivalent laws globally.  
> The author assumes **no liability** for misuse.

---

## Author

<div align="center">

**Aryan Waghere**  
Security-focused Python developer | Offensive tooling | Cryptography | Network Security

[![GitHub](https://img.shields.io/badge/GitHub-AryanWaghere24-181717?style=for-the-badge&logo=github)](https://github.com/AryanWaghere24)

---

*If CVEye saved you time or helped you find something real — drop a* ⭐ *on the repo. It means a lot.*

</div>

---

<div align="center">
<sub>Built with 🔴 and Python · MIT License · © 2024 Aryan Waghere</sub>
</div>
