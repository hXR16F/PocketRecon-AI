# PocketRecon-AI: Lightweight Cybersecurity Reconnaissance Suite

> **MCP Server for AI-powered security reconnaissance**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)&nbsp;
[![License: MIT](https://img.shields.io/badge/license-GPLv3-orange.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)&nbsp;
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-Compatible-green.svg)](https://www.raspberrypi.org/)

---

## Overview

**PocketRecon-AI** is a **Model Context Protocol (MCP) server** that enables Large Language Models (LLMs) to perform cybersecurity reconnaissance tasks directly within conversational interfaces. Built for **low-power devices** like Raspberry Pi and local PCs, PocketRecon-AI connects AI agents with powerful security tools including **Nmap, Netcat, WhatWeb, Curl, and more**.

The system uses a **two-tier architecture**: an MCP server that communicates with your LLM (LM Studio, VS Code, Cursor, etc.), and a Flask-based backend API that executes the actual system commands.

PocketRecon-AI is **cross-platform**, and runs on both **Linux and Windows** environments.

---

## Features

### Network Reconnaissance
- **ICMP Ping** – Reachability testing with configurable packet counts
- **Traceroute** – Network path analysis to destinations
- **Nmap Scanning** – Port scanning, OS detection, NSE script execution and more
- **Netcat** – TCP connectivity testing and raw socket interaction

### Web Analysis
- **Directory Brute-forcing** – Web directory enumeration using [dirb wordlist](https://salsa.debian.org/pkg-security-team/dirb/-/blob/debian/master/wordlists/common.txt?ref_type=heads)
- **Technology Fingerprinting** – CMS and framework detection
- **HTTP Security Auditing** – Header analysis (HSTS, CSP, etc.)
- **Web Content Extraction** – Structured data extraction from webpages

### Intelligence Gathering
- **WHOIS Lookup** – Domain registration data retrieval
- **DNS Enumeration** – Subdomain discovery and record analysis
- **CVE Lookup** – Passive vulnerability search via NVD
- **IP Reputation** – AbuseIPDB integration for threat intelligence
- **Web Search** – Lightweight DuckDuckGo searching

### LLM Integration
- **MCP Server** – Native Model Context Protocol support
- **Works with**: LM Studio, VS Code, Cursor, Ollama, and any MCP-compatible client
- **Automated security workflows** via conversational interface

---

## Architecture

PocketRecon-AI uses a **two-component architecture** that separates the LLM interface from the command execution:

| Component | Role | File |
|-----------|------|------|
| **MCP Server (client)** | MCP-compatible server, communicates with LLM | `pocket_recon_mcp.py` |
| **Backend API (server)** | Flask server that executes commands | `pocket_recon_server.py` |

The **MCP Server (client)** exposes tools to your LLM and forwards requests to the **Backend API (server)**, which runs the actual security tools on your system.

---

## Installation & Setup

### Prerequisites

- **Python 3.10+**
- **Docker** (optional, for containerized deployment)
- **System Tools** (must be installed on the backend API server):
  - `curl`
  - `ping`
  - `traceroute`
  - `nmap`

---

### Option 1: Local Installation (Recommended for Raspberry Pi)

#### Step 1: Clone repository
```bash
git clone https://github.com/hXR16F/PocketRecon-AI
cd PocketRecon-AI
```

#### Step 2: Create virtual environment
```
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Run Backend API Server
```bash
python pocket_recon_server.py --host 0.0.0.0 --port 5005
```

---

### Option 2: Docker Deployment

#### Build Image
```bash
docker build -t pocket-recon .
```

#### Run Container
```bash
docker run -d \
  --name pocket-recon \
  -p 5005:5005 \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  pocket-recon
```

---

## Connecting to your LLM

### [LM Studio](https://lmstudio.ai/)

1. Open LM Studio and edit `mcp.json`.
2. Configure as follows:
```json
"PocketRecon-AI": {
  "command": "python",
  "args": [
    "/path/to/pocket_recon_mcp.py",
    "--server",
    "http://localhost:5005"
  ],
  "timeout": 900000
}
```

---

## Available Tools

All tools are exposed to your LLM via the MCP protocol and map to backend API endpoints:

| Tool | Description | Parameters | API Endpoint |
|------|-------------|------------|--------------|
| `ping` | ICMP echo requests for reachability testing | `target`, `count` | `POST /api/ping` |
| `nmap` | Network scanning (ports, OS detection, NSE scripts, etc.) | `target`, `ports`, `scan_type`, `scripts`, `os_detection`, `service_detection`, `script_scan`, `script_args`, `top_ports_count`, `timing`, `extra_args` | `POST /api/nmap` |
| `netcat` | TCP connectivity and raw socket interaction | `target`, `port`, `data` | `POST /api/netcat` |
| `traceroute` | Trace network route to destination | `target` | `POST /api/traceroute` |
| `whois` | Retrieve domain registration data | `domain` | `POST /api/whois` |
| `curl` | Perform customizable HTTP requests using curl | `url`, `method`, `data`, `json_body`, `headers`, `query_params`, `cookies`, `follow_redirects`, `timeout`, `connect_timeout`, `verbose`, `extra_args` | `POST /api/curl` |
| `dirbuster` | Web directory brute-force enumeration | `target` | `POST /api/dirbuster` |
| `http_request` | Advanced HTTP interaction with redirect control | `method`, `url`, `headers`, `params`, `data`, `json`, `follow_redirects`, `max_redirects` | `POST /api/http_request` |
| `whatweb` | Technology fingerprinting (CMS, frameworks) | `target` | `POST /api/whatweb` |
| `dns_enum` | DNS record analysis and subdomain discovery | `domain` | `POST /api/dns_enum` |
| `header_security_audit` | Security header audit (HSTS, CSP, etc.) | `url`, `method` | `POST /api/header_security_audit` |
| `cve_lookup` | Passive CVE lookup via NVD keyword search | `product`, `version` | `POST /api/cve_lookup` |
| `abuseipdb_checker` | IP reputation check using AbuseIPDB | `ip` | `POST /api/abuseipdb_checker` |
| `visit_website` | Extract structured content from webpage | `url`, `max_links`, `content_limit`, `timeout` | `POST /api/visit_website` |
| `web_search` | Lightweight web search using DuckDuckGo | `query`, `limit` | `POST /api/web_search` |

---

## Security Best Practices

1. **Network Isolation**: Run PocketRecon-AI in an isolated network segment
2. **Access Control**: Restrict backend API to localhost or trusted IPs
3. **Logging**: Enable audit logging for all tool executions
4. **Updates**: Keep system tools (Nmap, etc.) updated regularly

---

## Safety & Ethics Warning

> **FOR AUTHORIZED CYBERSECURITY PROFESSIONALS AND EDUCATIONAL USE ONLY**

- **Unauthorized Scanning**: Do NOT use this tool to scan networks, systems, or domains you do not own or have explicit written permission to test.
- **Legal Compliance**: Ensure all usage complies with local laws and ethical guidelines.

---

*Built with 💙*
