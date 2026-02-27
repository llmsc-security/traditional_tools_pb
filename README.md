# LLM-Enhanced Security Scanner System v3.0

> Automated web security scanning using 10 industry-standard tools, orchestrated by a single shell script with per-tool log files saved to a mounted output directory.

---

## Table of Contents

1. [Overview](#overview)
2. [Tools Included](#tools-included)
3. [Directory Structure](#directory-structure)
4. [Quick Start](#quick-start)
5. [Building the Docker Image](#building-the-docker-image)
6. [Running a Scan](#running-a-scan)
7. [Output Log Files](#output-log-files)
8. [Tool-by-Tool Reference](#tool-by-tool-reference)
9. [Advanced Usage](#advanced-usage)
10. [Environment Variables](#environment-variables)
11. [Troubleshooting](#troubleshooting)

---

## Overview

`scan.sh` accepts a target URL, runs every installed scanner against it in a logical order (recon → crawl → fuzz → vuln scan → injection tests), and writes each tool's raw output to a **separate, timestamped log file** under a mounted host directory so results survive container restarts.

```
./scan.sh <TARGET_URL> [OUTPUT_DIR]
```

---

## Tools Included

| # | Tool | Purpose | Log file |
|---|------|---------|----------|
| 1 | **nmap** | Port & service fingerprinting | `01_nmap.log` |
| 2 | **testssl.sh** | TLS/SSL cipher & certificate audit | `02_testssl.log` |
| 3 | **nikto** | Web-server misconfigurations | `03_nikto.log` |
| 4 | **katana** | Spider / JS-aware endpoint discovery | `04_katana.log` |
| 5 | **ffuf** | Directory & file fuzzing | `05_ffuf.json` |
| 6 | **nuclei** | CVE & misconfiguration templates | `06_nuclei.log` |
| 7 | **dalfox** | Reflected XSS (feeds on katana URLs) | `07_dalfox.log` |
| 8 | **XSStrike** | Advanced DOM/reflected XSS | `08_xsstrike.log` |
| 9 | **sqlmap** | SQL injection | `09_sqlmap.log` |
| 10 | **4-ZERO-3** | 403/401 bypass techniques | `10_403bypass.log` |

A human-readable summary of all tool statuses is written to `00_SUMMARY.txt`.

---

## Directory Structure

```
/app/
├── scan.sh                        ← orchestration script  (this file)
├── tools/
│   ├── sqlmap                     ← wrapper → sqlmap_lib/sqlmap.py
│   ├── dalfox
│   ├── nuclei
│   ├── katana
│   ├── testssl                    ← wrapper → testssl.sh/testssl.sh
│   ├── 403-bypass                 ← wrapper → 4zero3/403-bypass.sh
│   ├── ffuf
│   ├── hexdump
│   └── xsstrike                   ← wrapper → XSStrike/xsstrike.py
├── security_scanner_system/
├── dashboard/
└── reports/

/mnt/scan_results/                 ← mount this from the host
└── example_com_20250227_143022/   ← one dir per scan (host_timestamp)
    ├── 00_SUMMARY.txt
    ├── 01_nmap.log
    ├── 02_testssl.log
    ├── 03_nikto.log
    ├── 04_katana.log
    ├── 05_ffuf.json
    ├── 06_nuclei.log
    ├── 07_dalfox.log
    ├── 08_xsstrike.log
    ├── 09_sqlmap.log
    ├── 09_sqlmap_data/            ← sqlmap session files
    └── 10_403bypass.log
```

---

## Quick Start

### Prerequisites

- Docker ≥ 20.10
- A target you are **authorised** to test

```bash
# 1. Build the image
docker build -t security-scanner:v3 .

# 2. Create a host directory to receive scan results
mkdir -p ~/scan_results

# 3. Run a scan (interactive — keeps the container alive)
docker run --rm -it \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 \
  bash /app/scan.sh https://example.com /mnt/scan_results

# 4. Results are immediately available on the host
ls ~/scan_results/
```

---

## Building the Docker Image

```bash
# Standard build
docker build -t security-scanner:v3 .

# Build with no cache (forces re-download of all tools)
docker build --no-cache -t security-scanner:v3 .

# Verify tools are installed
docker run --rm security-scanner:v3 bash -c \
  "for t in nmap nikto nuclei katana ffuf dalfox xsstrike sqlmap testssl 403-bypass; do
     echo -n \"$t: \"; which $t || echo NOT FOUND
   done"
```

---

## Running a Scan

### Basic Usage

```bash
docker run --rm -it \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 \
  bash /app/scan.sh https://target.example.com
```

### Custom Output Directory

```bash
docker run --rm -it \
  -v /data/pentest:/mnt/scan_results \
  security-scanner:v3 \
  bash /app/scan.sh https://target.example.com /mnt/scan_results
```

### Non-interactive (CI/CD Pipeline)

```bash
docker run --rm \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 \
  bash /app/scan.sh https://target.example.com /mnt/scan_results 2>&1 | tee scan_run.log
```

### With Custom API Key (for LLM-enhanced analysis)

```bash
docker run --rm -it \
  -e OPENAI_API_KEY="sk-..." \
  -e GPT_MODEL="gpt-4o" \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 \
  bash /app/scan.sh https://target.example.com
```

---

## Output Log Files

Every scan creates a timestamped subdirectory:

```
/mnt/scan_results/<host>_<YYYYMMDD_HHMMSS>/
```

| File | Format | Description |
|------|--------|-------------|
| `00_SUMMARY.txt` | Plain text | Pass/fail status of every tool, timestamps |
| `01_nmap.log` | nmap text | Open ports, versions, HTTP headers, TLS cert |
| `02_testssl.log` | testssl text | All cipher suites, BEAST/POODLE/ROBOT/etc. |
| `03_nikto.log` | Nikto text | Outdated software, dangerous files, headers |
| `04_katana.log` | URL list | All discovered endpoints (one per line) |
| `05_ffuf.json` | JSON | Status codes, sizes, response times per path |
| `06_nuclei.log` | nuclei text | Template matches with severity |
| `07_dalfox.log` | dalfox text | Confirmed/potential XSS endpoints |
| `08_xsstrike.log` | XSStrike text | XSS payloads that triggered |
| `09_sqlmap.log` | sqlmap text | Injection points, DBMS fingerprint |
| `09_sqlmap_data/` | Directory | Full sqlmap session (target.txt, log, etc.) |
| `10_403bypass.log` | Plain text | Bypass attempts and HTTP responses |

Each log starts with a header block:

```
# ============================================================
# Tool     : 06_nuclei
# Target   : https://example.com
# Started  : Fri Feb 27 14:32:05 UTC 2026
# Command  : /app/tools/nuclei -u https://example.com ...
# ============================================================
```

---

## Tool-by-Tool Reference

### 1. nmap — Port & Service Discovery

Scans all 65535 ports, runs default NSE scripts, and performs version detection.

```bash
# Manual equivalent
nmap -sV -sC -p- --open -T4 \
  --script "http-headers,http-methods,ssl-cert,ssl-enum-ciphers" \
  example.com
```

**Key flags:**
- `-sV` — service version detection
- `-sC` — default scripts
- `-p-` — all ports
- `--open` — only show open ports
- `-T4` — aggressive timing (faster; use -T2 on slow networks)

---

### 2. testssl.sh — TLS/SSL Audit

Checks for weak ciphers, expired certs, known TLS vulnerabilities (POODLE, BEAST, ROBOT, CRIME, BREACH, Heartbleed, etc.).

```bash
# Manual equivalent
/app/tools/testssl --color 0 --severity LOW example.com:443
```

**Key flags:**
- `--severity LOW` — report everything from LOW upward
- `--color 0` — no ANSI codes in log files

---

### 3. nikto — Web Server Scanner

Checks for ~7,000 web server issues: outdated components, dangerous HTTP methods, default credentials, information disclosure.

```bash
# Manual equivalent
nikto -h https://example.com -Format txt -Tuning 123456789abcde
```

**Tuning codes used:**
`1` File upload, `2` Misconfiguration, `3` Info disclosure, `4` Injection, `5` Remote file retrieval, `6` Denial of Service, `7` RCE, `8` SQL injection, `9` Auth bypass, `a` Auth, `b` Software ID, `c` Source disclosure, `d` Web service, `e` XSS

---

### 4. katana — Spider / API Endpoint Discovery

JavaScript-aware crawler that discovers hidden endpoints, API routes and form parameters. Its output directly feeds dalfox and sqlmap.

```bash
# Manual equivalent
/app/tools/katana -u https://example.com -depth 3 -js-crawl \
  -known-files all -automatic-form-fill \
  -ef woff,css,png,svg,jpg,gif -o endpoints.txt
```

**Key flags:**
- `-depth 3` — crawl 3 levels deep
- `-js-crawl` — execute JS to find dynamic routes
- `-known-files all` — check robots.txt, sitemap.xml, etc.
- `-ef` — exclude static file extensions

---

### 5. ffuf — Directory & File Fuzzing

Fast HTTP fuzzer that discovers hidden directories, backup files, admin panels and API endpoints.

```bash
# Manual equivalent
/app/tools/ffuf \
  -u https://example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -t 50 -o results.json -of json
```

**Wordlist priority:**
1. `/usr/share/seclists/Discovery/Web-Content/common.txt` (SecLists — best)
2. `/usr/share/wordlists/dirb/common.txt` (dirb fallback)
3. Built-in minimal wordlist (if neither is present)

To use SecLists, mount it into the container:

```bash
docker run --rm -it \
  -v /opt/SecLists:/usr/share/seclists:ro \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 bash /app/scan.sh https://example.com
```

---

### 6. nuclei — CVE & Misconfiguration Templates

Scans using community-maintained templates for thousands of CVEs, misconfigurations, exposed credentials and takeover opportunities.

```bash
# Manual equivalent
/app/tools/nuclei -u https://example.com \
  -severity low,medium,high,critical \
  -tags "cve,misconfig,exposure,takeover,default-login" \
  -rate-limit 50 -o nuclei.log -stats
```

**Updating templates (recommended before each scan):**

```bash
docker run --rm -it security-scanner:v3 bash -c \
  "/app/tools/nuclei -update-templates && echo Done"
```

---

### 7. dalfox — XSS Scanner

Reflected XSS scanner that ingests the URL list from katana for maximum coverage.

```bash
# Manual equivalent — single URL
/app/tools/dalfox url "https://example.com/search?q=test" \
  --silence --no-color --timeout 15

# From URL list (what scan.sh does)
/app/tools/dalfox file endpoints_with_params.txt \
  --silence --no-color --timeout 15
```

---

### 8. XSStrike — Advanced XSS Detection

Context-aware XSS detection engine with DOM analysis and blind XSS support.

```bash
# Manual equivalent
/app/tools/xsstrike --url https://example.com \
  --crawl --blind --skip-dom --timeout 10
```

---

### 9. sqlmap — SQL Injection

Automatic SQL injection detection and exploitation framework.

```bash
# Manual equivalent
/app/tools/sqlmap -u "https://example.com" \
  --batch --random-agent --level=3 --risk=2 \
  --forms --crawl=3
```

**Key flags:**
- `--batch` — never ask for user input, use defaults
- `--level=3 --risk=2` — balanced between thoroughness and safety
- `--forms` — detect and test HTML forms
- `--crawl=3` — crawl site before testing

> ⚠️ Increase `--risk` to 3 only if you accept potentially destructive payloads (UPDATE/DELETE).

---

### 10. 4-ZERO-3 — 403/401 Bypass

Tests dozens of HTTP header tricks, path manipulation and encoding bypasses against forbidden endpoints identified by ffuf.

```bash
# Manual equivalent
/app/tools/403-bypass https://example.com/admin
```

Techniques tested include:
- `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`
- URL path case variation: `/Admin`, `/ADMIN`, `/admin/`
- Double URL encoding, null byte injection
- HTTP verb overriding: `X-HTTP-Method-Override: GET`

---

## Advanced Usage

### Run a Single Tool Only

```bash
docker run --rm -it \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 \
  bash -c "/app/tools/nuclei -u https://example.com \
    -severity critical,high -o /mnt/scan_results/nuclei_quick.log"
```

### Scan Multiple Targets in Parallel

```bash
#!/bin/bash
TARGETS=("https://app1.example.com" "https://app2.example.com" "https://api.example.com")

for target in "${TARGETS[@]}"; do
    docker run --rm -d \
      -v ~/scan_results:/mnt/scan_results \
      security-scanner:v3 \
      bash /app/scan.sh "${target}" /mnt/scan_results &
done
wait
echo "All scans complete."
```

### Use Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  scanner:
    build: .
    volumes:
      - ./scan_results:/mnt/scan_results
      - /opt/SecLists:/usr/share/seclists:ro
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - GPT_MODEL=gpt-4o
    command: bash /app/scan.sh https://example.com /mnt/scan_results
```

```bash
docker-compose run --rm scanner
```

### Copy scan.sh Into the Image at Build Time

Add to the end of the Dockerfile before the CMD line:

```dockerfile
COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | *(empty)* | API key for LLM analysis features |
| `OPENAI_API_BASE_URL` | `http://157.10.162.82:443/v1/` | LLM API endpoint |
| `GPT_MODEL` | `gpt-5.1` | Model name to use |
| `DASHBOARD_PORT` | `14000` | Dashboard HTTP port |

---

## Troubleshooting

### Permission Denied on Output Directory

```bash
# Fix host directory permissions
chmod 777 ~/scan_results
# or
docker run --rm -v ~/scan_results:/mnt/scan_results security-scanner:v3 \
  bash -c "chmod 777 /mnt/scan_results"
```

### nuclei Templates Missing / Outdated

```bash
docker run --rm security-scanner:v3 \
  bash -c "/app/tools/nuclei -update-templates"
```

### sqlmap Takes Too Long

Reduce crawl depth and level:

```bash
/app/tools/sqlmap -u "https://example.com" \
  --batch --level=1 --risk=1 --forms --crawl=1
```

### testssl Fails on Internal Hosts

Ensure DNS resolution works inside the container, or pass an IP directly:

```bash
./scan.sh https://192.168.1.100:8443
```

### Tools Not Found in PATH

The Dockerfile adds `/app/tools` to `$PATH`. Verify:

```bash
docker run --rm security-scanner:v3 bash -c "echo $PATH && which nuclei"
```

### ffuf Returns No Results

Mount SecLists for a comprehensive wordlist:

```bash
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

docker run --rm -it \
  -v /opt/SecLists:/usr/share/seclists:ro \
  -v ~/scan_results:/mnt/scan_results \
  security-scanner:v3 bash /app/scan.sh https://example.com
```

---

## Legal Notice

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized scanning is illegal in most jurisdictions. The authors accept no liability for misuse.

