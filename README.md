# Active-Recon-Scanner
Active Reconnaissance &amp; Vulnerability Assessment Tool
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
