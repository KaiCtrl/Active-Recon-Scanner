#!/usr/bin/env python3
"""
Active Reconnaissance & CVE Vulnerability Assessment Engine (Week 1 - Day 4 v3)
-------------------------------------------------------------------------------
Upgrades the active port scanner with:
  1. Regex-based version extraction and pattern matching.
  2. CVSS v3.1 severity scoring, CVE identifier mapping, and remediation guidance.
  3. Automated FTP anonymous authentication checking.
  4. Client-ready Markdown report generation with vulnerability metrics.

Usage:
    python banner_grabber_v3.py --target 10.0.24.110
    python banner_grabber_v3.py --target 10.0.24.110 --threads 10
"""

import argparse
import datetime
import ftplib
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Top 20 Enterprise Common Ports
TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 8080, 8443]

# Structured CVE Vulnerability Signature Rules with Regex
VULN_DATABASE = [
    {
        "pattern": r"vsFTPd\s+2\.3\.4",
        "cve": "CVE-2011-2523",
        "title": "vsFTPd 2.3.4 Backdoor Command Execution",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "vector": "Network / Unauthenticated",
        "remediation": "Upgrade vsFTPd daemon to version 3.0+ or switch to SFTP/SSH."
    },
    {
        "pattern": r"Apache/2\.2\.\d+",
        "cve": "CVE-2017-9798",
        "title": "Apache HTTP Server 2.2.x Memory Disclosure (Optionsbleed)",
        "cvss": 7.5,
        "severity": "HIGH",
        "vector": "Network / Unauthenticated",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.x branch."
    },
    {
        "pattern": r"OpenSSH[_-]4\.\d+",
        "cve": "CVE-2018-15473",
        "title": "OpenSSH Legacy Version User Enumeration & Outdated Ciphers",
        "cvss": 7.5,
        "severity": "HIGH",
        "vector": "Network / Unauthenticated",
        "remediation": "Upgrade OpenSSH server package to >= 7.7p1 and disable legacy SSHv1."
    },
    {
        "pattern": r"OpenSSH[_-][1-6]\.\d+",
        "cve": "CVE-2016-0777",
        "title": "OpenSSH Client/Server Memory Disclosure (Roaming)",
        "cvss": 7.0,
        "severity": "HIGH",
        "vector": "Network",
        "remediation": "Update OpenSSH to current release and add UseRoaming no to ssh_config."
    },
    {
        "pattern": r"Metasploitable",
        "cve": "CVE-BENCHMARK",
        "title": "Metasploitable Vulnerable Linux Benchmark Target Identified",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "vector": "Network / Unauthenticated",
        "remediation": "Isolate host within host-only lab network; do not expose to public networks."
    }
]


def test_ftp_anonymous(ip: str, timeout: float = 3.0) -> dict:
    """Attempts an unauthenticated anonymous login on Port 21."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=timeout)
        login_res = ftp.login('anonymous', 'anonymous@')
        ftp.quit()
        return {
            "vulnerable": True,
            "cve": "CWE-287 / CAPEC-560",
            "cvss": 9.1,
            "severity": "CRITICAL",
            "title": "Anonymous FTP Access Allowed",
            "message": f"Anonymous FTP Login Allowed ({login_res})",
            "remediation": "Disable anonymous user access in /etc/vsftpd.conf (anonymous_enable=NO)."
        }
    except ftplib.error_perm as e:
        return {
            "vulnerable": False,
            "message": f"FTP Anonymous Login Denied ({e})"
        }
    except Exception as e:
        return {
            "vulnerable": False,
            "message": f"FTP Check Failed: {e}"
        }


def match_vulnerability_signatures(banner: str) -> list:
    """Evaluates service banner against Regex CVE Database."""
    matches = []
    if not banner or banner == "None":
        return matches

    for rule in VULN_DATABASE:
        if re.search(rule["pattern"], banner, re.IGNORECASE):
            matches.append(rule)

    return matches


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Attempts TCP connection, extracts service banner, and runs CVE engine."""
    result = {
        "port": port,
        "status": "Closed / Filtered",
        "banner": "None",
        "vuln_matches": [],
        "extra_info": None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        # Attempt TCP 3-way handshake
        s.connect((ip, port))
        result["status"] = "Open"

        # Probe web ports with a minimal HTTP HEAD request
        if port in [80, 443, 8080, 8443]:
            try:
                probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PythonRecon/3.0\r\n\r\n"
                s.sendall(probe.encode("ascii"))
            except Exception:
                pass

        # Receive banner response
        try:
            banner_bytes = s.recv(1024)
            if banner_bytes:
                banner_str = banner_bytes.decode("utf-8", errors="replace").strip()
                first_line = banner_str.split("\n")[0].strip()
                result["banner"] = first_line if first_line else banner_str[:80]
        except socket.timeout:
            result["banner"] = "Open (No banner received within timeout)"
        except Exception as e:
            result["banner"] = f"Open (Error reading banner: {e})"

        s.close()

    except ConnectionRefusedError:
        result["status"] = "Closed (RST received)"
    except socket.timeout:
        result["status"] = "Filtered (Timeout)"
    except OSError:
        result["status"] = "Closed / Filtered"

    # Match extracted banner against CVE rules
    if result["status"] == "Open" and result["banner"] != "None":
        result["vuln_matches"] = match_vulnerability_signatures(result["banner"])

    # Port 21 Automated Anonymous FTP Check
    if port == 21 and result["status"] == "Open":
        ftp_res = test_ftp_anonymous(ip, timeout=timeout)
        result["extra_info"] = ftp_res["message"]
        if ftp_res["vulnerable"]:
            result["vuln_matches"].append({
                "cve": ftp_res["cve"],
                "title": ftp_res["title"],
                "cvss": ftp_res["cvss"],
                "severity": ftp_res["severity"],
                "vector": "Network / Unauthenticated",
                "remediation": ftp_res["remediation"]
            })

    return result


def scan_target(target_ip: str, ports: list, max_threads: int = 10) -> list:
    """Scans list of ports concurrently using ThreadPoolExecutor."""
    print(f"\n[*] Starting Active Recon Scan (v3 - CVE Engine) against Target IP: {target_ip}")
    print(f"[*] Sweeping {len(ports)} common ports using up to {max_threads} worker threads...")
    print("=" * 80)

    start_time = time.time()
    scan_results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(grab_banner, target_ip, port): port for port in ports
        }
        for future in as_completed(future_to_port):
            res = future.result()
            scan_results.append(res)

    scan_results.sort(key=lambda x: x["port"])
    elapsed = time.time() - start_time
    print(f"[*] Scan completed in {elapsed:.2f} seconds.\n")
    return scan_results


def export_markdown_report(results: list, target_ip: str, filename: str = None) -> str:
    """Generates a client-ready Markdown security assessment report with CVSS scoring."""
    if not filename:
        filename = f"recon_report_{target_ip}.md"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_ports = [r for r in results if r["status"] == "Open"]
    all_vulns = []
    for r in open_ports:
        for v in r["vuln_matches"]:
            all_vulns.append((r["port"], v))

    md = []
    md.append(f"# Active Reconnaissance & CVE Risk Assessment Report")
    md.append(f"**Target Host IP:** `{target_ip}`  ")
    md.append(f"**Scan Date & Time:** `{timestamp}`  ")
    md.append(f"**Scanned Port Scope:** Top `{len(results)}` Enterprise Ports  ")
    md.append(f"**Open Ports Identified:** `{len(open_ports)}`  ")
    md.append(f"**Total Vulnerabilities Flagged:** `{len(all_vulns)}`  \n")

    md.append("---\n")
    md.append("## Executive Summary\n")
    if open_ports:
        md.append(f"An active TCP network reconnaissance scan was executed against target `{target_ip}` across `{len(results)}` common enterprise ports. "
                  f"A total of **{len(open_ports)} open service(s)** were identified. Service banners were dynamically extracted, "
                  f"parsed using Regular Expressions, and cross-referenced against a local CVSS v3.1 vulnerability database. "
                  f"A total of **{len(all_vulns)} security risk(s)** were flagged for immediate remediation.\n")
    else:
        md.append(f"No open TCP ports were detected on target `{target_ip}` during this scan.\n")

    md.append("## Discovered Services & Network Exposure\n")
    md.append("| Port | Status | Service Banner | Discovered Risk Count |")
    md.append("| :--- | :--- | :--- | :--- |")

    for r in results:
        if r["status"] == "Open":
            banner_clean = r["banner"].replace("|", "\\|")
            risk_count = len(r["vuln_matches"])
            risk_str = f"🔴 **{risk_count} Risk(s)**" if risk_count > 0 else "🟢 Clear"
            md.append(f"| `{r['port']}` | **{r['status']}** | `{banner_clean}` | {risk_str} |")

    md.append("\n---\n")
    md.append("## Detailed Vulnerability & CVSS v3.1 Findings\n")

    if all_vulns:
        md.append("| Port | CVE / Identifier | CVSS v3.1 | Severity | Threat Title & Remediation |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for port, v in all_vulns:
            sev_badge = f"🔴 **{v['severity']}**" if v['severity'] in ["CRITICAL", "HIGH"] else f"🟡 **{v['severity']}**"
            md.append(f"| `{port}` | `{v['cve']}` | **{v['cvss']}** | {sev_badge} | **{v['title']}**<br>*Fix:* {v['remediation']} |")
    else:
        md.append("No critical or high severity CVE signatures matched the extracted service banners.\n")

    md.append("\n---\n")
    md.append("## Recommended Next Enumeration Steps\n")

    if not open_ports:
        md.append("- Perform UDP port scanning or check firewall rules blocking ICMP/TCP probes.")
    else:
        for r in open_ports:
            p = r["port"]
            if p == 21:
                md.append("- **Port 21 (FTP)**:")
                if r.get("extra_info") and "Allowed" in r.get("extra_info"):
                    md.append("  - **URGENT**: Anonymous FTP access is active. Log in with `ftp` CLI and inspect directory contents (`ls -la`).")
                else:
                    md.append("  - Test for weak credentials or specific FTP daemon exploits using Metasploit/Hydra.")
            elif p in [80, 443, 8080, 8443]:
                md.append(f"- **Port {p} (HTTP/HTTPS)**:")
                md.append(f"  - Open `http://{target_ip}:{p}` in browser and inspect page source.")
                md.append(f"  - Run web directory enumeration tools (`gobuster dir -u http://{target_ip}:{p}/ -w /usr/share/wordlists/dirb/common.txt`).")
            elif p in [139, 445]:
                md.append(f"- **Port {p} (SMB)**:")
                md.append(f"  - Enumerate SMB shares using `enum4linux -a {target_ip}` or `smbclient -L //{target_ip}`.")
            elif p == 22:
                md.append(f"- **Port {p} (SSH)**:")
                md.append("  - Inspect SSH banner for outdated OpenSSH releases and check for key-based or password authentication policies.")
            else:
                md.append(f"- **Port {p}**: Perform dedicated service banner grabbing and script scanning (`nmap -sC -sV -p {p} {target_ip}`).")

    md.append("\n---\n")
    md.append("*Report generated automatically by `banner_grabber_v3.py` (Week 1 Day 4 Portfolio Tool)*\n")

    report_text = "\n".join(md)
    with open(filename, "w") as f:
        f.write(report_text)

    return filename


def print_report(results: list, target_ip: str):
    """Displays formatted console output table."""
    print(f"{'PORT':<8} | {'STATUS':<18} | {'SERVICE BANNER':<35}")
    print("-" * 80)

    open_ports_count = 0
    for res in results:
        if res["status"] == "Open":
            open_ports_count += 1
            banner_disp = (
                res["banner"][:32] + "..." if len(res["banner"]) > 35 else res["banner"]
            )
            print(f"{res['port']:<8} | {res['status']:<18} | {banner_disp:<35}")
            for v in res["vuln_matches"]:
                print(f"   [!] CVE ALERT [{v['cve']}] (CVSS {v['cvss']} {v['severity']}): {v['title']}")

    print("-" * 80)
    print(f"Summary: Discovered {open_ports_count} OPEN port(s) out of {len(results)} scanned.\n")


def parse_ports(port_str: str) -> list:
    """Parses comma-separated port string into integers."""
    try:
        return [int(p.strip()) for p in port_str.split(",") if p.strip()]
    except ValueError:
        print("[!] Invalid port list format. Use numbers separated by commas (e.g., 21,22,80).")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Active Reconnaissance & CVE Vulnerability Assessment Engine (v3)"
    )
    parser.add_argument("--target", required=True, help="Target IP address (e.g., 10.0.24.110)")
    parser.add_argument("--ports", default=None, help="Comma-separated ports (e.g., 21,22,80,443)")
    parser.add_argument("--threads", type=int, default=10, help="Worker threads (default: 10)")
    parser.add_argument("--output", default=None, help="Custom output Markdown report filename")

    args = parser.parse_args()
    ports_to_scan = parse_ports(args.ports) if args.ports else TOP_20_PORTS
    results = scan_target(args.target, ports_to_scan, max_threads=args.threads)
    print_report(results, args.target)

    # Automatically generate Markdown Report
    report_file = export_markdown_report(results, args.target, filename=args.output)
    print(f"[+] Automated Markdown report saved to: `{report_file}`\n")


if __name__ == "__main__":
    main()
