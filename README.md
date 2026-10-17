# Active-Recon-Scanner

Legal & Ethical Disclaimer 

This repository and its scripts are intended strictly for educational purposes, authorized security testing, and research within controlled lab environments [1, 2]. - \*\*Authorized Testing Only\*\*: Active reconnaissance and scanning against targets without explicit, written permission from the system owner is illegal [2-4]. - \*\*No Liability\*\*: The author assumes no responsibility or liability for any misuse, damage, or unauthorized activities conducted with this tool. - \*\*License\*\*: Released under the [MIT License](LICENSE).
---
Active Reconnaissance & Vulnerability Assessment Tool
A multi-threaded Python TCP port scanner and vulnerability assessment tool that probes network services, extracts service banners, identifies potential CVE signatures using Regular Expressions, and exports structured Markdown assessment reports formatted with CVSS v3.1 risk metrics.

---
## 🛠️ Key Features
- \*\*Multi-Threaded Socket Engine\*\*: Concurrent TCP port sweeping utilizing Python's \`ThreadPoolExecutor\` for high-throughput service discovery.
-  - \*\*Top 20 Common Enterprise Port Scope\*\*: Sweeps default enterprise service ports (FTP, SSH, HTTP/S, SMB, MySQL, RDP, etc.).
 - - \*\*Socket Fault Tolerance\*\*: Handles connection refusals (\`RST\`) and timeouts (\`Filtered\`) cleanly without thread starvation.
- -  \*\*Regex Banner Parsing Engine\*\*: Dynamically extracts software names and version numbers using Regular Expressions rather than static string matching.
 - - \*\*Active Anonymous FTP Probe\*\*: Automatically tests Port 21 for unauthenticated anonymous FTP logins (\`ftplib\`) upon discovery.
- - \*\*CVSS v3.1 Risk Scoring\*\*: Maps identified service banners against a local vulnerability database with CVSS scores (\`CRITICAL\`, \`HIGH\`, \`MEDIUM\`) and remediation guidance.
  -  - \*\*Automated Client-Ready Markdown Exporter\*\*: Generates structured reports (\`recon\_report\_

-----
- \## 🚀 Quick Start Usage
-  ### Prerequisites
-  - Python 3.8+ - Standard libraries: \`socket\`, \`ftplib\`, \`argparse\`, \`concurrent.futures\`, \`re\`
   - ### Basic Command \`\`\`bash python3 banner\_grabber\_v3.py --target 10.0.24.110




## 📊 Sample Assessment Report Output

| Port | Status   | Service Banner          | Discovered Risk Count |
| ---- | -------- | ----------------------- | --------------------- |
| `21` | **Open** | `vsFTPd 2.3.4`          | 🔴 **1 Risk(s)**      |
| `80` | **Open** | `Apache/2.2.8 (Ubuntu)` | 🔴 **1 Risk(s)**      |

### Identified CVE Findings Table

| Port | CVE ID          | CVSS v3.1 | Severity        | Threat Title &amp; Remediation                                                                                  |
| ---- | --------------- | --------- | --------------- | ----------------------------------------------------------------------------------------------------------- |
| `21` | `CVE-2011-2523` | **9.8**   | 🔴 **CRITICAL** | **vsFTPd 2.3.4 Backdoor Command Execution**<br />*Fix:* Upgrade vsFTPd to version 3.0+ or remove FTP service. |
| `80` | `CVE-2017-9798` | **7.5**   | 🟠 **HIGH**     | **Apache HTTP Server 2.2.x Optionsbleed**<br />*Fix:* Patch Apache HTTP Server to 2.4.x branch.               |
