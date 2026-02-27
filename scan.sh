#!/bin/bash
# =============================================================================
# LLM-Enhanced Security Scanner - scan.sh
# Runs all installed tools against a target URL and saves results to logs.
# Usage: ./scan.sh <TARGET_URL> [OUTPUT_DIR]
# Example: ./scan.sh https://example.com /mnt/scan_results
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# 0. ARGUMENT PARSING & SETUP
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <TARGET_URL> [OUTPUT_DIR]"
    echo "Example: $0 https://example.com /mnt/scan_results"
    exit 1
fi

TARGET_URL="${1}"
BASE_OUTPUT_DIR="${2:-/mnt/scan_results}"

# Strip trailing slash
TARGET_URL="${TARGET_URL%/}"

# Extract scheme, host and port
SCHEME=$(echo "${TARGET_URL}" | grep -oP '^https?')
HOST=$(echo "${TARGET_URL}" | sed -E 's|https?://([^/:]+).*|\1|')
PORT_RAW=$(echo "${TARGET_URL}" | grep -oP ':\d+' | tr -d ':')
if [[ -z "${PORT_RAW}" ]]; then
    PORT_RAW=$([ "${SCHEME}" = "https" ] && echo "443" || echo "80")
fi
HOST_PORT="${HOST}:${PORT_RAW}"

# Sanitise host for directory name (replace dots/colons with underscores)
SAFE_HOST=$(echo "${HOST}" | tr '.' '_')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${BASE_OUTPUT_DIR}/${SAFE_HOST}_${TIMESTAMP}"

mkdir -p "${OUTPUT_DIR}"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SUMMARY_FILE="${OUTPUT_DIR}/00_SUMMARY.txt"

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; echo "[$(date +%H:%M:%S)] $*" >> "${SUMMARY_FILE}"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*";    echo "[OK] $*"    >> "${SUMMARY_FILE}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; echo "[WARN] $*"  >> "${SUMMARY_FILE}"; }
err()  { echo -e "${RED}[ERR]${NC} $*";     echo "[ERR] $*"   >> "${SUMMARY_FILE}"; }

# ---------------------------------------------------------------------------
# Helper: run a tool, tee output to a log, and catch non-zero exits gracefully
# ---------------------------------------------------------------------------
run_tool() {
    local tool_name="$1"
    local log_file="${OUTPUT_DIR}/${tool_name}.log"
    shift                    # remaining args are the actual command

    log "Starting ${BOLD}${tool_name}${NC} → ${log_file}"
    {
        echo "# ============================================================"
        echo "# Tool     : ${tool_name}"
        echo "# Target   : ${TARGET_URL}"
        echo "# Started  : $(date)"
        echo "# Command  : $*"
        echo "# ============================================================"
        echo ""
    } > "${log_file}"

    local exit_code=0
    "$@" >> "${log_file}" 2>&1 || exit_code=$?

    {
        echo ""
        echo "# ============================================================"
        echo "# Finished : $(date)"
        echo "# Exit code: ${exit_code}"
        echo "# ============================================================"
    } >> "${log_file}"

    if [[ ${exit_code} -eq 0 ]]; then
        ok "${tool_name} finished (exit 0) — log: ${log_file}"
    else
        warn "${tool_name} finished with exit code ${exit_code} — check ${log_file}"
    fi
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          LLM-Enhanced Security Scanner v3.0                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
log "Target URL  : ${TARGET_URL}"
log "Host        : ${HOST}"
log "Port        : ${PORT_RAW}"
log "Output dir  : ${OUTPUT_DIR}"
echo ""

# ============================================================================
# 1. NMAP – Port & Service Discovery
# ============================================================================
run_tool "01_nmap" \
    nmap -sV -sC -p- --open -T4 \
         --script "http-headers,http-methods,ssl-cert,ssl-enum-ciphers" \
         -oN "${OUTPUT_DIR}/01_nmap.log" \
         "${HOST}"

# ============================================================================
# 2. TESTSSL – TLS/SSL Analysis
# ============================================================================
run_tool "02_testssl" \
    /app/tools/testssl \
        --color 0 \
        --severity LOW \
        --logfile "${OUTPUT_DIR}/02_testssl.log" \
        "${HOST_PORT}"

# ============================================================================
# 3. NIKTO – Web Server Misconfiguration
# ============================================================================
run_tool "03_nikto" \
    nikto \
        -h "${TARGET_URL}" \
        -output "${OUTPUT_DIR}/03_nikto.log" \
        -Format txt \
        -nointeractive \
        -Tuning 123456789abcde

# ============================================================================
# 4. KATANA – Spider / Endpoint Discovery
# ============================================================================
run_tool "04_katana" \
    /app/tools/katana \
        -u "${TARGET_URL}" \
        -depth 3 \
        -js-crawl \
        -known-files all \
        -automatic-form-fill \
        -ef woff,css,png,svg,jpg,gif,jpeg,ico \
        -o "${OUTPUT_DIR}/04_katana.log"

# ============================================================================
# 5. FFUF – Directory & File Fuzzing
# ============================================================================
# Uses a built-in wordlist if SecLists is absent
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
if [[ ! -f "${WORDLIST}" ]]; then
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
fi
if [[ ! -f "${WORDLIST}" ]]; then
    # Minimal fallback
    WORDLIST="/tmp/ffuf_fallback.txt"
    printf '%s\n' admin api backup config dashboard db login logout panel phpinfo readme robots.txt sitemap.xml .env .git swagger upload v1 v2 > "${WORDLIST}"
fi

run_tool "05_ffuf" \
    /app/tools/ffuf \
        -u "${TARGET_URL}/FUZZ" \
        -w "${WORDLIST}" \
        -mc 200,201,204,301,302,307,401,403,405 \
        -t 50 \
        -timeout 10 \
        -o "${OUTPUT_DIR}/05_ffuf.json" \
        -of json \
        2>&1

# ============================================================================
# 6. NUCLEI – CVE / Misconfiguration Templates
# ============================================================================
run_tool "06_nuclei" \
    /app/tools/nuclei \
        -u "${TARGET_URL}" \
        -severity low,medium,high,critical \
        -tags "cve,misconfig,exposure,takeover,default-login" \
        -rate-limit 50 \
        -bulk-size 25 \
        -o "${OUTPUT_DIR}/06_nuclei.log" \
        -stats

# ============================================================================
# 7. DALFOX – Reflected XSS
# ============================================================================
# Katana output feeds dalfox for a richer endpoint list
KATANA_OUT="${OUTPUT_DIR}/04_katana.log"
if [[ -f "${KATANA_OUT}" ]] && grep -q '?' "${KATANA_OUT}" 2>/dev/null; then
    grep '?' "${KATANA_OUT}" | head -200 > /tmp/dalfox_urls.txt
    run_tool "07_dalfox" \
        /app/tools/dalfox \
            file /tmp/dalfox_urls.txt \
            --silence \
            --no-color \
            --timeout 15 \
            --output "${OUTPUT_DIR}/07_dalfox.log"
else
    run_tool "07_dalfox" \
        /app/tools/dalfox \
            url "${TARGET_URL}" \
            --silence \
            --no-color \
            --timeout 15 \
            --output "${OUTPUT_DIR}/07_dalfox.log"
fi

# ============================================================================
# 8. XSSTRIKE – Advanced XSS Detection
# ============================================================================
run_tool "08_xsstrike" \
    /app/tools/xsstrike \
        --url "${TARGET_URL}" \
        --crawl \
        --blind \
        --skip-dom \
        --timeout 10

# ============================================================================
# 9. SQLMAP – SQL Injection
# ============================================================================
run_tool "09_sqlmap" \
    /app/tools/sqlmap \
        -u "${TARGET_URL}" \
        --batch \
        --random-agent \
        --level=3 \
        --risk=2 \
        --forms \
        --crawl=3 \
        --output-dir="${OUTPUT_DIR}/09_sqlmap_data" \
        --results-file="${OUTPUT_DIR}/09_sqlmap.log"

# ============================================================================
# 10. 403-BYPASS – Forbidden Page Bypass Attempts
# ============================================================================
# Collect 403 paths from ffuf result and nikto log
BYPASS_TARGETS=()
if [[ -f "${OUTPUT_DIR}/05_ffuf.json" ]]; then
    # Extract 403 URLs from ffuf JSON output
    python3 - <<PY >> /tmp/bypass_paths.txt 2>/dev/null || true
import json, sys
try:
    data = json.load(open("${OUTPUT_DIR}/05_ffuf.json"))
    for r in data.get("results", []):
        if r.get("status") == 403:
            print(r.get("url", ""))
except Exception as e:
    pass
PY
fi

# Run 403-bypass on discovered endpoints, or fall back to TARGET_URL
BYPASS_URL_FILE="/tmp/bypass_paths.txt"
if [[ -s "${BYPASS_URL_FILE}" ]]; then
    while IFS= read -r burl; do
        [[ -z "${burl}" ]] && continue
        BYPASS_TARGETS+=("${burl}")
    done < "${BYPASS_URL_FILE}"
else
    BYPASS_TARGETS+=("${TARGET_URL}/admin")
    BYPASS_TARGETS+=("${TARGET_URL}/config")
fi

{
    echo "# ============================================================"
    echo "# Tool     : 10_403bypass"
    echo "# Target   : ${TARGET_URL}"
    echo "# Started  : $(date)"
    echo "# ============================================================"
} > "${OUTPUT_DIR}/10_403bypass.log"

for burl in "${BYPASS_TARGETS[@]}"; do
    log "403-bypass → ${burl}"
    echo "--- Testing: ${burl} ---" >> "${OUTPUT_DIR}/10_403bypass.log"
    /app/tools/403-bypass "${burl}" >> "${OUTPUT_DIR}/10_403bypass.log" 2>&1 || true
    echo "" >> "${OUTPUT_DIR}/10_403bypass.log"
done
ok "10_403bypass finished — log: ${OUTPUT_DIR}/10_403bypass.log"

# ============================================================================
# FINAL SUMMARY
# ============================================================================
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                     SCAN COMPLETE                           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Output directory:${NC} ${OUTPUT_DIR}"
echo ""
echo "Log files:"
ls -lh "${OUTPUT_DIR}"/*.log "${OUTPUT_DIR}"/*.json 2>/dev/null | awk '{print "  " $NF "  (" $5 ")"}'
echo ""

{
    echo ""
    echo "============================================================"
    echo "SCAN FINISHED: $(date)"
    echo "Output dir   : ${OUTPUT_DIR}"
    echo "Log files:"
    ls "${OUTPUT_DIR}" | sed 's/^/  /'
    echo "============================================================"
} >> "${SUMMARY_FILE}"

echo -e "${GREEN}Summary written to:${NC} ${SUMMARY_FILE}"
echo ""
