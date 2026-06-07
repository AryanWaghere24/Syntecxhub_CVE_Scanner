#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                  CVEye — CVE / Vulnerability Scanner          ║
║                       by Aryan Waghere                        ║
╚═══════════════════════════════════════════════════════════════╝

RESPONSIBLE DISCLOSURE NOTICE:
    This tool is intended exclusively for:
      - Authorized penetration testing
      - Security research on systems you own or have explicit
        written permission to test
      - Educational and defensive security purposes

    Unauthorized scanning of systems without explicit written
    permission is illegal under the Computer Fraud and Abuse Act
    (CFAA), the UK Computer Misuse Act, and similar laws worldwide.

    The author assumes NO liability for misuse of this tool.
    Always obtain proper authorization before scanning any target.

Usage:
    python3 cveye.py --target <host> --ports <port_range>
    python3 cveye.py --target 192.168.1.1 --ports 22,80,443
    python3 cveye.py --target 192.168.1.1 --ports 1-1024 --threads 50
    python3 cveye.py --target 192.168.1.1 --ports 80,443 --detail

CVE Data Source:
    OSV.dev API — https://osv.dev  (free, no key, no rate limits)

Author  : Aryan Waghere (github.com/AryanWaghere24)
License : MIT
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

import requests
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# OSV.dev — completely free CVE/vulnerability API, zero auth required
# Docs: https://google.github.io/osv.dev/api/
OSV_API_QUERY  = "https://api.osv.dev/v1/query"   # POST  — search by package/keyword
OSV_API_VULN   = "https://api.osv.dev/v1/vulns/{}" # GET   — fetch one CVE by ID

# CVSS severity thresholds (CVSS v3)
SEVERITY_CRITICAL = 9.0
SEVERITY_HIGH     = 7.0
SEVERITY_MEDIUM   = 4.0
SEVERITY_LOW      = 0.1

# Default connection timeout for banner grabbing (seconds)
BANNER_TIMEOUT = 3

# ─────────────────────────────────────────────────────────────────────────────
# COLOR HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def severity_color(score: float) -> str:
    """Return ANSI color string based on CVSS score."""
    if score >= SEVERITY_CRITICAL:
        return Fore.RED + Style.BRIGHT
    elif score >= SEVERITY_HIGH:
        return Fore.RED
    elif score >= SEVERITY_MEDIUM:
        return Fore.YELLOW
    elif score >= SEVERITY_LOW:
        return Fore.GREEN
    else:
        return Fore.WHITE

def severity_label(score: float) -> str:
    """Return human-readable severity label."""
    if score >= SEVERITY_CRITICAL:
        return "CRITICAL"
    elif score >= SEVERITY_HIGH:
        return "HIGH"
    elif score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    elif score >= SEVERITY_LOW:
        return "LOW"
    else:
        return "NONE"

def cprint(msg: str, color: str = "", bold: bool = False) -> None:
    """Colored print helper."""
    prefix = (Style.BRIGHT if bold else "") + color
    print(f"{prefix}{msg}{Style.RESET_ALL}")

# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRABBING & SERVICE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

# Mapping of well-known ports → service names
KNOWN_PORTS = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    143:   "imap",
    443:   "https",
    445:   "smb",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http",
    8443:  "https",
    27017: "mongodb",
}

# Each entry: (regex_pattern, product_name)
# Used to extract product name + version string from raw TCP banners
BANNER_SIGNATURES = [
    # SSH
    (r"SSH-(\d+\.\d+)-OpenSSH[_\s](\d+[\.\d]+\w*)", "openssh"),
    (r"SSH-\S+-(Cisco[_\-]\S+)",                      "cisco ssh"),

    # HTTP servers
    (r"Apache/(\d+[\.\d]+\w*)",                       "apache http server"),
    (r"nginx/(\d+[\.\d]+\w*)",                        "nginx"),
    (r"Microsoft-IIS/(\d+[\.\d]+)",                   "microsoft iis"),
    (r"lighttpd/(\d+[\.\d]+\w*)",                     "lighttpd"),
    (r"LiteSpeed[/ ](\S*)",                           "litespeed"),

    # App servers / CMS
    (r"WordPress[/ ](\d+[\.\d]+)",                    "wordpress"),
    (r"Drupal[/ ](\d+[\.\d]+)",                       "drupal"),
    (r"Joomla[/ ](\d+[\.\d]+)",                       "joomla"),
    (r"PHP/(\d+[\.\d]+\w*)",                          "php"),
    (r"Tomcat/(\d+[\.\d]+\w*)",                       "apache tomcat"),
    (r"JBoss[/ ](\S+)",                               "jboss"),
    (r"Jetty[/ ](\d+[\.\d]+\w*)",                     "eclipse jetty"),

    # FTP
    (r"vsFTPd (\d+[\.\d]+)",                          "vsftpd"),
    (r"ProFTPD (\d+[\.\d]+)",                         "proftpd"),
    (r"FileZilla Server (\S+)",                       "filezilla server"),
    (r"Pure-FTPd",                                    "pure-ftpd"),

    # Mail
    (r"Postfix[/ ](\d+[\.\d]+)",                      "postfix"),
    (r"Exim (\d+[\.\d]+)",                            "exim"),
    (r"Sendmail[/ ](\d+[\.\d]+)",                     "sendmail"),
    (r"Dovecot[/ ](\d+[\.\d]+)",                      "dovecot"),

    # Databases
    (r"MySQL[/ ](\d+[\.\d]+\w*)",                     "mysql"),
    (r"MariaDB[/ ](\d+[\.\d]+\w*)",                   "mariadb"),
    (r"PostgreSQL (\d+[\.\d]+)",                      "postgresql"),
    (r'"version"\s*:\s*"(\d+[\.\d]+)',                "mongodb"),
    (r"redis_version:(\d+[\.\d]+)",                   "redis"),

    # RDP
    (r"Microsoft Remote Desktop",                     "microsoft rdp"),
]

# Maps detected product name → OSV.dev ecosystem string
# OSV organises vulns by ecosystem; "OSS-Fuzz" catches generic open-source packages
OSV_ECOSYSTEM_MAP = {
    "openssh":           "OSS-Fuzz",
    "apache http server":"OSS-Fuzz",
    "nginx":             "OSS-Fuzz",
    "php":               "Packagist",
    "apache tomcat":     "Maven",
    "wordpress":         "Packagist",
    "drupal":            "Packagist",
    "mysql":             "OSS-Fuzz",
    "mariadb":           "OSS-Fuzz",
    "postgresql":        "OSS-Fuzz",
    "redis":             "OSS-Fuzz",
    "mongodb":           "OSS-Fuzz",
    "vsftpd":            "OSS-Fuzz",
    "proftpd":           "OSS-Fuzz",
    "postfix":           "OSS-Fuzz",
    "exim":              "OSS-Fuzz",
    "dovecot":           "OSS-Fuzz",
}


def grab_banner(host: str, port: int) -> Optional[str]:
    """
    Attempt to grab a raw TCP banner from host:port.
    Sends a minimal HTTP GET if no immediate push-banner is received.
    Returns banner string or None.
    """
    try:
        sock = socket.create_connection((host, port), timeout=BANNER_TIMEOUT)
        sock.settimeout(BANNER_TIMEOUT)

        # Try immediate push-banner first (SSH, FTP, SMTP send one right away)
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            pass

        # No push banner — probe with HTTP GET to provoke a Server: header
        try:
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            return response
        except Exception:
            pass

        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def grab_https_banner(host: str, port: int) -> Optional[str]:
    """TLS-wrapped HTTP banner grab for HTTPS ports."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Probing only — not validating TLS
        conn = ctx.wrap_socket(
            socket.create_connection((host, port), timeout=BANNER_TIMEOUT),
            server_hostname=host
        )
        conn.settimeout(BANNER_TIMEOUT)
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(4096).decode("utf-8", errors="replace")
        conn.close()
        return response
    except Exception:
        pass
    return None


def detect_service(host: str, port: int) -> dict:
    """
    Grab a banner and parse product + version.
    Returns dict: port, service, product, version, banner.
    """
    result = {
        "port":    port,
        "service": KNOWN_PORTS.get(port, f"unknown/{port}"),
        "product": None,
        "version": None,
        "banner":  None,
    }

    banner = grab_banner(host, port)
    if not banner and port in (443, 8443, 8444, 9443):
        banner = grab_https_banner(host, port)

    if not banner:
        return result

    result["banner"] = banner[:512].replace("\r\n", " ").replace("\n", " ")

    for pattern, product_name in BANNER_SIGNATURES:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            result["product"] = product_name
            groups = match.groups()
            # OpenSSH pattern has 2 groups: protocol version + software version
            if product_name == "openssh" and len(groups) >= 2:
                result["version"] = groups[1]
            elif groups:
                result["version"] = groups[-1]
            break

    return result

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────

def is_port_open(host: str, port: int) -> bool:
    """Quick TCP connect check."""
    try:
        sock = socket.create_connection((host, port), timeout=BANNER_TIMEOUT)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_port(host: str, port: int) -> Optional[dict]:
    """Open-check + service detection for one port."""
    if is_port_open(host, port):
        return detect_service(host, port)
    return None


def parse_port_spec(port_spec: str) -> list:
    """
    Parse port spec string → sorted list of ints.
    Supports: "22,80,443"  |  "1-1024"  |  "22,80,100-200"
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ─────────────────────────────────────────────────────────────────────────────
# OSV.DEV CVE LOOKUP  (free, no API key needed)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_cvss(osv_item: dict) -> tuple:
    """
    Pull the highest CVSS score + vector out of an OSV vulnerability record.
    OSV stores severity as a list under the 'severity' key.
    Returns (score: float, vector: str, version_label: str).
    """
    best_score  = 0.0
    best_vector = "N/A"
    best_ver    = "N/A"

    for sev in osv_item.get("severity", []):
        score_type = sev.get("type", "")
        vector     = sev.get("score", "N/A")

        # Parse base score from CVSS vector string, e.g. "CVSS:3.1/.../7.5/..."
        # The base score is encoded in the vector itself — we extract it via regex
        match = re.search(r"/(\d+\.\d+)$", vector)
        if match:
            score = float(match.group(1))
        else:
            # Fallback: look for a numeric score directly
            try:
                score = float(vector)
            except (ValueError, TypeError):
                score = 0.0

        if score > best_score:
            best_score  = score
            best_vector = vector
            best_ver    = score_type  # e.g. "CVSS_V3", "CVSS_V2"

    return best_score, best_vector, best_ver


def query_osv(product: str, version: Optional[str] = None, max_results: int = 10) -> list:
    """
    Query OSV.dev for vulnerabilities matching a product name + optional version.

    OSV API docs: https://google.github.io/osv.dev/api/
    Completely free — no API key, no rate limits, always up-to-date.

    Strategy:
      1. POST /v1/query with package name + ecosystem to get matching CVE IDs
      2. For each ID, GET /v1/vulns/{id} to fetch full details + CVSS scores
    """
    ecosystem = OSV_ECOSYSTEM_MAP.get(product.lower(), "OSS-Fuzz")

    # Build the query payload
    payload = {
        "package": {
            "name":      product,
            "ecosystem": ecosystem,
        }
    }
    if version:
        # Clean version: strip trailing alpha suffixes like "p1", "b3"
        clean_ver = re.sub(r'[a-zA-Z]\d*$', '', version)
        payload["version"] = clean_ver

    try:
        resp = requests.post(OSV_API_QUERY, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        cprint(f"  [!] Cannot reach OSV API — check internet connection.", Fore.YELLOW)
        return []
    except Exception as e:
        cprint(f"  [!] OSV query failed for '{product}': {e}", Fore.YELLOW)
        return []

    vulns = data.get("vulns", [])
    if not vulns:
        return []

    # Fetch full details for each vuln (capped at max_results)
    cves = []
    for vuln_ref in vulns[:max_results]:
        vuln_id = vuln_ref.get("id", "")
        if not vuln_id:
            continue

        try:
            detail_resp = requests.get(OSV_API_VULN.format(vuln_id), timeout=10)
            detail_resp.raise_for_status()
            item = detail_resp.json()
        except Exception:
            continue

        # Extract CVE alias — OSV uses its own IDs (GHSA-xxx, OSV-xxx) but
        # also lists official CVE IDs in the 'aliases' field
        aliases = item.get("aliases", [])
        cve_id  = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # English summary / detail
        summary = item.get("summary", "")
        details = item.get("details", "")
        description = details if details else summary if summary else "No description available."

        # CVSS score + vector
        cvss_score, cvss_vector, cvss_ver = _extract_cvss(item)

        # Published / modified dates (ISO format → strip to YYYY-MM-DD)
        published = item.get("published", "N/A")[:10]
        modified  = item.get("modified",  "N/A")[:10]

        # References (patches, advisories, PoCs)
        references = [ref.get("url", "") for ref in item.get("references", []) if ref.get("url")]

        cves.append({
            "cve_id":       cve_id,
            "osv_id":       vuln_id,
            "description":  description[:600],
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "cvss_version": cvss_ver,
            "severity":     severity_label(cvss_score),
            "published":    published,
            "modified":     modified,
            "references":   references[:5],
        })

    # Sort by severity descending
    cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return cves

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def build_report(target: str, scan_results: list, scan_duration: float) -> dict:
    """Aggregate scan results into a structured report dict."""
    total_cves = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}

    for entry in scan_results:
        for cve in entry.get("cves", []):
            total_cves += 1
            sev = cve.get("severity", "NONE")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "meta": {
            "tool":       "CVEye",
            "version":    VERSION,
            "author":     "Aryan Waghere (github.com/AryanWaghere24)",
            "cve_source": "OSV.dev (osv.dev)",
            "target":     target,
            "scan_time" : datetime.now().strftime('%Y-%m-%d____AT____%H-%M-%S'),
            "duration_s": round(scan_duration, 2),
        },
        "summary": {
            "open_ports":      len(scan_results),
            "total_cves":      total_cves,
            "severity_counts": severity_counts,
        },
        "findings": scan_results,
    }


def export_json(report: dict, filename: str) -> None:
    """Write the report as a pretty-printed JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    cprint(f"  [✔] JSON report saved → {filename}", Fore.CYAN)


def export_text(report: dict, filename: str) -> None:
    """Write the report as a human-readable plain-text file."""
    lines = []
    meta = report["meta"]
    summ = report["summary"]

    lines.append("=" * 70)
    lines.append("  CVEye — Vulnerability Scanner Report")
    lines.append("=" * 70)
    lines.append(f"  Target      : {meta['target']}")
    lines.append(f"  Scan Time   : {meta['scan_time']}")
    lines.append(f"  Duration    : {meta['duration_s']}s")
    lines.append(f"  CVE Source  : {meta['cve_source']}")
    lines.append(f"  Open Ports  : {summ['open_ports']}")
    lines.append(f"  Total CVEs  : {summ['total_cves']}")
    lines.append("")

    sc = summ["severity_counts"]
    lines.append("  SEVERITY SUMMARY")
    lines.append(f"    CRITICAL : {sc.get('CRITICAL', 0)}")
    lines.append(f"    HIGH     : {sc.get('HIGH', 0)}")
    lines.append(f"    MEDIUM   : {sc.get('MEDIUM', 0)}")
    lines.append(f"    LOW      : {sc.get('LOW', 0)}")
    lines.append("")

    for entry in report["findings"]:
        svc = entry["service"]
        lines.append("─" * 70)
        lines.append(f"  PORT    : {svc['port']}")
        lines.append(f"  SERVICE : {svc['service']}")
        lines.append(f"  PRODUCT : {svc.get('product') or 'Unknown'}")
        lines.append(f"  VERSION : {svc.get('version') or 'Unknown'}")
        if svc.get("banner"):
            lines.append(f"  BANNER  : {svc['banner'][:120]}...")
        lines.append("")

        cves = entry.get("cves", [])
        if not cves:
            lines.append("  No CVEs found for this service.")
        else:
            for cve in cves:
                lines.append(f"  [{cve['severity']}] {cve['cve_id']} — CVSS {cve['cvss_score']}")
                lines.append(f"    Published : {cve['published']}")
                lines.append(f"    Vector    : {cve['cvss_vector']}")
                lines.append(f"    Desc      : {cve['description'][:200]}...")
                if cve.get("references"):
                    lines.append(f"    Ref       : {cve['references'][0]}")
                lines.append("")

    lines.append("=" * 70)
    lines.append("  END OF REPORT — CVEye by Aryan Waghere")
    lines.append("=" * 70)

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    cprint(f"  [✔] Text report saved → {filename}", Fore.CYAN)

# ─────────────────────────────────────────────────────────────────────────────
# CLI DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    banner = f"""
{Fore.RED + Style.BRIGHT}
  ██████╗██╗   ██╗███████╗██╗   ██╗███████╗
 ██╔════╝██║   ██║██╔════╝╚██╗ ██╔╝██╔════╝
 ██║     ██║   ██║█████╗   ╚████╔╝ █████╗  
 ██║     ╚██╗ ██╔╝██╔══╝    ╚██╔╝  ██╔══╝  
 ╚██████╗ ╚████╔╝ ███████╗   ██║   ███████╗
  ╚═════╝  ╚═══╝  ╚══════╝   ╚═╝   ╚══════╝
{Style.RESET_ALL}
{Fore.CYAN}  CVE Scanner v{VERSION}  ·  by Aryan Waghere (github.com/AryanWaghere24){Style.RESET_ALL}
{Fore.CYAN}  Powered by OSV.dev — free, no API key needed{Style.RESET_ALL}
{Fore.YELLOW}  ⚠  Authorized use only — always get written permission first{Style.RESET_ALL}
"""
    print(banner)


def print_summary_dashboard(report: dict) -> None:
    """Color-coded severity dashboard with bar chart."""
    meta = report["meta"]
    summ = report["summary"]
    sc   = summ["severity_counts"]

    print(f"\n{Fore.WHITE + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE + Style.BRIGHT}  SCAN SUMMARY  ·  {meta['target']}  ·  {meta['scan_time']}{Style.RESET_ALL}")
    print(f"{Fore.WHITE + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}\n")

    stats_table = [
        ["Open Ports Scanned", summ["open_ports"]],
        ["Total CVEs Found",   summ["total_cves"]],
        ["CVE Source",         "OSV.dev (osv.dev)"],
        ["Scan Duration",      f"{meta['duration_s']}s"],
    ]
    print(tabulate(stats_table, tablefmt="simple"))

    print(f"\n{Fore.WHITE + Style.BRIGHT}  SEVERITY BREAKDOWN{Style.RESET_ALL}\n")

    bar_max = max(sc.values()) if max(sc.values()) > 0 else 1
    for label, color in [
        ("CRITICAL", Fore.RED + Style.BRIGHT),
        ("HIGH",     Fore.RED),
        ("MEDIUM",   Fore.YELLOW),
        ("LOW",      Fore.GREEN),
    ]:
        count = sc.get(label, 0)
        bar   = "█" * int((count / bar_max) * 30) if count > 0 else ""
        print(f"  {color}{label:<10}{Style.RESET_ALL}  {color}{bar:<30}  {count}{Style.RESET_ALL}")

    print(f"\n{Fore.WHITE + Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}\n")


def print_findings(report: dict, detail: bool = False) -> None:
    """Print each port's findings with color coding."""
    for entry in report["findings"]:
        svc  = entry["service"]
        cves = entry.get("cves", [])

        port_color = Fore.GREEN if not cves else Fore.RED
        print(f"{port_color + Style.BRIGHT}▸ PORT {svc['port']}/{svc['service'].upper()}{Style.RESET_ALL}", end="")
        if svc.get("product"):
            print(f"  {Fore.CYAN}{svc['product']}", end="")
            if svc.get("version"):
                print(f" {svc['version']}", end="")
            print(Style.RESET_ALL, end="")
        print()

        if svc.get("banner"):
            print(f"  {Fore.WHITE}Banner: {svc['banner'][:100]}...{Style.RESET_ALL}")

        if not cves:
            print(f"  {Fore.GREEN}No matching CVEs found.{Style.RESET_ALL}\n")
            continue

        table_rows = []
        for cve in cves:
            col = severity_color(cve["cvss_score"])
            table_rows.append([
                f"{col}{cve['cve_id']}{Style.RESET_ALL}",
                f"{col}{cve['cvss_score']}{Style.RESET_ALL}",
                f"{col}{cve['severity']}{Style.RESET_ALL}",
                cve["published"],
            ])

        print(tabulate(
            table_rows,
            headers=["CVE ID", "CVSS", "Severity", "Published"],
            tablefmt="simple"
        ))

        if detail:
            for cve in cves:
                col = severity_color(cve["cvss_score"])
                print(f"\n  {col}[{cve['cve_id']}]{Style.RESET_ALL}")
                print(f"    Vector  : {cve['cvss_vector']}")
                desc    = cve["description"]
                wrapped = [desc[i:i+76] for i in range(0, min(len(desc), 380), 76)]
                print(f"    Desc    : {wrapped[0]}")
                for w in wrapped[1:]:
                    print(f"              {w}")
                if cve.get("references"):
                    print(f"    Ref[0]  : {cve['references'][0]}")

        print()

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────

def run_scanner(args: argparse.Namespace) -> None:
    """
    Main scan flow:
      1. Multi-threaded port scan + banner grabbing
      2. OSV.dev CVE lookup for each detected service
      3. Build + display report
      4. Export JSON + text reports
    """
    print_banner()

    target = args.target
    ports  = parse_port_spec(args.ports)

    cprint(f"  [*] Target   : {target}", Fore.CYAN)
    cprint(f"  [*] Ports    : {len(ports)} ports queued", Fore.CYAN)
    cprint(f"  [*] Threads  : {args.threads}", Fore.CYAN)
    cprint(f"  [*] CVE API  : OSV.dev (no key needed)", Fore.CYAN)
    print()

    start_time = time.time()

    # ── Phase 1: Port scan + banner grabbing (multithreaded) ────────────────
    cprint("  [1/3] Scanning ports and grabbing banners...", Fore.WHITE, bold=True)
    open_services = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in ports}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            result = future.result()
            if result:
                label = f"OPEN  {result.get('product') or result['service']}"
                if result.get("version"):
                    label += f" {result['version']}"
                cprint(f"    [{done_count:>4}/{len(ports)}] :{futures[future]:<6} {label}", Fore.GREEN)
                open_services.append(result)

    cprint(f"\n  → {len(open_services)} open port(s) found.\n", Fore.CYAN)

    if not open_services:
        cprint("  [!] No open ports found. Exiting.", Fore.YELLOW)
        sys.exit(0)

    # ── Phase 2: CVE lookup via OSV.dev ─────────────────────────────────────
    cprint("  [2/3] Querying OSV.dev CVE database...", Fore.WHITE, bold=True)
    scan_results = []

    for svc in open_services:
        product = svc.get("product")
        if not product:
            cprint(f"    ⚠  Port {svc['port']} — no product detected, skipping.", Fore.YELLOW)
            scan_results.append({"service": svc, "cves": []})
            continue

        cprint(f"    Querying OSV for: {product} {svc.get('version') or ''}...", Fore.WHITE)
        cves = query_osv(product, svc.get("version"), max_results=args.max_cves)
        scan_results.append({"service": svc, "cves": cves})
        cprint(f"    Port {svc['port']}: {len(cves)} CVE(s) matched.", Fore.CYAN)

    # ── Phase 3: Build and display report ────────────────────────────────────
    cprint("\n  [3/3] Building report...", Fore.WHITE, bold=True)
    scan_duration = time.time() - start_time
    report        = build_report(target, scan_results, scan_duration)

    print_summary_dashboard(report)
    print_findings(report, detail=args.detail)

    # ── Export ────────────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = re.sub(r"[^\w\-.]", "_", target)
    base_name = f"cveye_{safe_host}_{timestamp}"

    if args.output_json or args.output:
        export_json(report, args.output_json or f"{base_name}.json")

    if args.output_text or args.output:
        export_text(report, args.output_text or f"{base_name}.txt")

    if not args.output_json and not args.output_text and not args.output:
        export_json(report, f"{base_name}.json")
        export_text(report, f"{base_name}.txt")

    print()
    cprint("  Scan complete. Stay ethical, get authorized. ✊", Fore.CYAN, bold=True)
    print()

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CVEye",
        description="CVE / Vulnerability Scanner powered by OSV.dev — authorized use only",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 cveye.py --target 192.168.1.1 --ports 22,80,443
  python3 cveye.py --target 10.0.0.5 --ports 1-1024 --threads 100
  python3 cveye.py --target myserver.local --ports 80,8080 --detail
        """
    )
    parser.add_argument("--target",      "-t", required=True,  help="Target host (IP or hostname)")
    parser.add_argument("--ports",       "-p", required=True,  help="Ports: 22,80,443 | 1-1024 | 22,80,100-200")
    parser.add_argument("--threads",     "-T", type=int, default=50, help="Scan threads (default: 50)")
    parser.add_argument("--max-cves",          type=int, default=10, help="Max CVEs per service (default: 10)")
    parser.add_argument("--detail",      "-d", action="store_true",  help="Show CVE descriptions + refs in terminal")
    parser.add_argument("--output-json",       metavar="FILE",       help="Save JSON report to FILE")
    parser.add_argument("--output-text",       metavar="FILE",       help="Save text report to FILE")
    parser.add_argument("--output",      "-o", action="store_true",  help="Auto-save both reports (timestamped)")
    return parser


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    try:
        resolved_ip = socket.gethostbyname(args.target)
        if resolved_ip != args.target:
            cprint(f"  [*] Resolved {args.target} → {resolved_ip}", Fore.WHITE)
    except socket.gaierror:
        cprint(f"  [!] Could not resolve hostname: {args.target}", Fore.RED)
        sys.exit(1)

    run_scanner(args)


if __name__ == "__main__":
    main()
