#!/bin/bash
# =============================================================================
# LLM-Enhanced Security Scanner - scan.sh  (parallel + timeout + fixed)
#
# Fixes applied from first real scan:
#   01_nmap      -p- → --top-ports 1000  (full scan times out on cloud hosts)
#   02_testssl   add --ssl-native        (bash socket probe fails on this env)
#   06_nuclei    add -update-templates   (templates were missing → fatal error)
#   08_xsstrike  fuzzywuzzy pre-check    (tool exits immediately if missing)
#   10_403bypass -u URL --exploit        (tool needs -u flag, not positional arg)
#   00_SUMMARY   strip ANSI codes        (\033[1m was leaking into the text file)
#
# WAVE 1 (parallel): nmap testssl nikto katana ffuf nuclei xsstrike
# WAVE 2 (parallel): dalfox sqlmap 403bypass
#
# Usage: ./scan.sh <TARGET_URL> [OUTPUT_DIR]
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# 0. ARGS & URL PARSING
# ─────────────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <TARGET_URL> [OUTPUT_DIR]"
    exit 1
fi

TARGET_URL="${1%/}"
BASE_OUTPUT_DIR="${2:-/mnt/scan_results}"

SCHEME=$(echo "${TARGET_URL}"   | grep -oP '^https?'                  || true)
HOST=$(echo "${TARGET_URL}"     | sed -E 's|https?://([^/:]+).*|\1|')
PORT_RAW=$(echo "${TARGET_URL}" | grep -oP '(?<=:)\d{2,5}(?=[/?]|$)' || true)
[[ -z "${PORT_RAW}" ]] && PORT_RAW=$( [[ "${SCHEME}" == "https" ]] && echo 443 || echo 80 )
HOST_PORT="${HOST}:${PORT_RAW}"

SAFE_HOST=$(echo "${HOST}" | tr '.' '_')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${BASE_OUTPUT_DIR}/${SAFE_HOST}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

# ─────────────────────────────────────────────────────────────────────────────
# Per-tool timeouts — override via env vars e.g. TIMEOUT_NMAP=300
# ─────────────────────────────────────────────────────────────────────────────
TIMEOUT_NMAP="${TIMEOUT_NMAP:-300}"       # top-1000 scan finishes in ~2-3 min
TIMEOUT_TESTSSL="${TIMEOUT_TESTSSL:-300}"
TIMEOUT_NIKTO="${TIMEOUT_NIKTO:-300}"
TIMEOUT_KATANA="${TIMEOUT_KATANA:-300}"
TIMEOUT_FFUF="${TIMEOUT_FFUF:-300}"
TIMEOUT_NUCLEI="${TIMEOUT_NUCLEI:-600}"
TIMEOUT_XSSTRIKE="${TIMEOUT_XSSTRIKE:-300}"
TIMEOUT_DALFOX="${TIMEOUT_DALFOX:-600}"
TIMEOUT_SQLMAP="${TIMEOUT_SQLMAP:-900}"
TIMEOUT_BYPASS="${TIMEOUT_BYPASS:-300}"

# ─────────────────────────────────────────────────────────────────────────────
# Colours & logging
# FIX: _log_write strips ANSI before writing to SUMMARY so no \033[1m garbage
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

SUMMARY_FILE="${OUTPUT_DIR}/00_SUMMARY.txt"
{
    echo "LLM-Enhanced Security Scanner v3.0"
    echo "Target  : ${TARGET_URL}"
    echo "Host    : ${HOST}  Port: ${PORT_RAW}"
    echo "Started : $(date)"
    echo "Output  : ${OUTPUT_DIR}"
    echo "========================================================"
} > "${SUMMARY_FILE}"

LOCK_FILE="${OUTPUT_DIR}/.log.lock"
# strip_ansi: remove all ESC[ sequences before writing to plain-text summary
strip_ansi() { sed 's/\x1b\[[0-9;]*[mK]//g; s/\\033\[[0-9;]*m//g'; }

_log_write() {
    local colour="$1" tag="$2"; shift 2
    local ts; ts=$(date +%H:%M:%S)
    local plain_msg; plain_msg=$(echo "$*" | strip_ansi)
    (
        flock -x 200
        echo -e "${colour}[${ts}]${NC} ${tag} $*"
        echo "[${ts}] ${tag} ${plain_msg}" >> "${SUMMARY_FILE}"
    ) 200>"${LOCK_FILE}"
}
log()  { _log_write "${CYAN}"   ""        "$*"; }
ok()   { _log_write "${GREEN}"  "[OK]"    "$*"; }
warn() { _log_write "${YELLOW}" "[WARN]"  "$*"; }
info() { _log_write "${BLUE}"   "[>>]"    "$*"; }

# ─────────────────────────────────────────────────────────────────────────────
# run_tool <name> <timeout_secs> <cmd...>
# ─────────────────────────────────────────────────────────────────────────────
run_tool() {
    local tool_name="$1"
    local tool_timeout="$2"
    shift 2
    local log_file="${OUTPUT_DIR}/${tool_name}.log"
    local start_ts; start_ts=$(date +%s)

    info "STARTED  ${BOLD}${tool_name}${NC} (limit ${tool_timeout}s)"
    {
        echo "# ========================================================"
        echo "# Tool    : ${tool_name}"
        echo "# Target  : ${TARGET_URL}"
        echo "# Start   : $(date)"
        echo "# Timeout : ${tool_timeout}s"
        echo "# Cmd     : $*"
        echo "# ========================================================"
        echo ""
    } > "${log_file}"

    local rc=0
    timeout --kill-after=15s "${tool_timeout}" "$@" >> "${log_file}" 2>&1 || rc=$?

    local elapsed=$(( $(date +%s) - start_ts ))
    local status_msg
    if [[ ${rc} -eq 124 || ${rc} -eq 137 ]]; then
        status_msg="TIMED OUT after ${elapsed}s (exit ${rc})"
        warn "FINISHED ${tool_name} — ${status_msg}"
    elif [[ ${rc} -eq 0 ]]; then
        status_msg="OK in ${elapsed}s"
        ok "FINISHED ${tool_name} (${status_msg})"
    else
        status_msg="exit ${rc} in ${elapsed}s"
        warn "FINISHED ${tool_name} (${status_msg}) — see ${log_file}"
    fi

    {
        echo ""
        echo "# ========================================================"
        echo "# End     : $(date)"
        echo "# Elapsed : ${elapsed}s"
        echo "# Status  : ${status_msg}"
        echo "# ========================================================"
    } >> "${log_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# wait_jobs / live_progress
# ─────────────────────────────────────────────────────────────────────────────
wait_jobs() {
    local label="$1"; shift
    local failed=0
    for pid in "$@"; do
        wait "${pid}" || (( failed++ )) || true
    done
    if [[ ${failed} -eq 0 ]]; then
        ok "Wave ${label} — all jobs finished cleanly"
    else
        warn "Wave ${label} — ${failed} job(s) exited non-zero"
    fi
}

live_progress() {
    local label="$1"; shift
    declare -A _pid _log _start
    for item in "$@"; do
        local name="${item%%:*}" pid="${item##*:}"
        _pid["${name}"]="${pid}"
        _log["${name}"]="${OUTPUT_DIR}/${name}.log"
        _start["${name}"]=$(date +%s)
    done
    while true; do
        local any=0 lines=""
        for name in "${!_pid[@]}"; do
            local pid="${_pid[$name]}"
            if kill -0 "${pid}" 2>/dev/null; then
                any=1
                local elapsed=$(( $(date +%s) - ${_start[$name]} ))
                local last=""
                [[ -f "${_log[$name]}" ]] && \
                    last=$(grep -v '^#' "${_log[$name]}" 2>/dev/null \
                           | grep -v '^\s*$' | strip_ansi | tail -1 | cut -c1-80 || true)
                [[ -z "${last}" ]] && last="(no output yet)"
                lines+="    ${BOLD}${name}${NC} [${elapsed}s] ${DIM}${last}${NC}\n"
            fi
        done
        [[ ${any} -eq 0 ]] && break
        echo -e "${BLUE}[$(date +%H:%M:%S)] Wave ${label} — still running:${NC}"
        echo -e "${lines}"
        sleep 30
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks & fixes
# ─────────────────────────────────────────────────────────────────────────────

# FIX nuclei: update templates before scanning (was: fatal "no templates found")
log "Pre-flight: updating nuclei templates..."
/app/tools/nuclei -update-templates >> "${OUTPUT_DIR}/nuclei_update.log" 2>&1 || true

# FIX xsstrike: install fuzzywuzzy now so the tool doesn't abort on first run
log "Pre-flight: ensuring xsstrike dependencies (fuzzywuzzy)..."
python3 -c "import fuzzywuzzy" 2>/dev/null || \
    pip install fuzzywuzzy --quiet --break-system-packages >> "${OUTPUT_DIR}/xsstrike_deps.log" 2>&1 || true

# Wordlist for ffuf
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
[[ ! -f "${WORDLIST}" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
if [[ ! -f "${WORDLIST}" ]]; then
    WORDLIST="/tmp/ffuf_fallback.txt"
    # Expanded fallback — covers juice-shop style endpoints
    printf '%s\n' \
        admin api api/v1 api/v2 assets backup config \
        dashboard db ftp login logout panel phpinfo \
        readme rest robots.txt sitemap.xml .env .git \
        swagger swagger-ui.html upload v1 v2 \
        rest/user rest/products rest/basket \
        > "${WORDLIST}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    LLM-Enhanced Security Scanner v3.0  [PARALLEL+TIMEOUT]       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
log "Target : ${TARGET_URL}   Host : ${HOST}   Port : ${PORT_RAW}"
log "Output : ${OUTPUT_DIR}"
printf "  Timeouts → nmap:%ss testssl:%ss nikto:%ss katana:%ss ffuf:%ss nuclei:%ss xsstrike:%ss\n" \
    "${TIMEOUT_NMAP}" "${TIMEOUT_TESTSSL}" "${TIMEOUT_NIKTO}" \
    "${TIMEOUT_KATANA}" "${TIMEOUT_FFUF}" "${TIMEOUT_NUCLEI}" "${TIMEOUT_XSSTRIKE}"
printf "           dalfox:%ss sqlmap:%ss 403bypass:%ss\n" \
    "${TIMEOUT_DALFOX}" "${TIMEOUT_SQLMAP}" "${TIMEOUT_BYPASS}"
echo ""

# =============================================================================
#  WAVE 1 — 7 independent tools, all parallel
# =============================================================================
echo -e "${BOLD}┌─ WAVE 1: 7 parallel jobs ──────────────────────────────────────────┐${NC}"

# FIX nmap: --top-ports 1000 instead of -p- (full scan times out on Heroku/cloud)
run_tool "01_nmap" "${TIMEOUT_NMAP}" \
    nmap -sV -sC --top-ports 1000 --open -T4 \
         --script "http-headers,http-methods,ssl-cert,ssl-enum-ciphers" \
         "${HOST}" &
PID_NMAP=$!

# FIX testssl: --ssl-native bypasses the bash-socket probe that was failing
run_tool "02_testssl" "${TIMEOUT_TESTSSL}" \
    /app/tools/testssl \
        --color 0 --severity LOW \
        --ssl-native \
        --append \
        --logfile "${OUTPUT_DIR}/02_testssl.log" \
        "${HOST_PORT}" &
PID_TESTSSL=$!

run_tool "03_nikto" "${TIMEOUT_NIKTO}" \
    nikto \
        -h "${TARGET_URL}" \
        -maxtime "${TIMEOUT_NIKTO}s" \
        -output "${OUTPUT_DIR}/03_nikto.log" \
        -Format txt \
        -nointeractive \
        -Tuning 123456789abcde &
PID_NIKTO=$!

run_tool "04_katana" "${TIMEOUT_KATANA}" \
    /app/tools/katana \
        -u "${TARGET_URL}" \
        -depth 3 \
        -js-crawl \
        -known-files all \
        -automatic-form-fill \
        -ef woff,css,png,svg,jpg,gif,jpeg,ico \
        -o "${OUTPUT_DIR}/04_katana.log" &
PID_KATANA=$!

run_tool "05_ffuf" "${TIMEOUT_FFUF}" \
    /app/tools/ffuf \
        -u "${TARGET_URL}/FUZZ" \
        -w "${WORDLIST}" \
        -mc 200,201,204,301,302,307,401,403,405 \
        -t 20 \
        -timeout 8 \
        -o "${OUTPUT_DIR}/05_ffuf.json" \
        -of json &
PID_FFUF=$!

# FIX nuclei: -nt skips the template update check (already done in pre-flight)
run_tool "06_nuclei" "${TIMEOUT_NUCLEI}" \
    /app/tools/nuclei \
        -u "${TARGET_URL}" \
        -severity low,medium,high,critical \
        -tags "cve,misconfig,exposure,takeover,default-login" \
        -rate-limit 30 -bulk-size 20 \
        -nt \
        -o "${OUTPUT_DIR}/06_nuclei.log" \
        -stats &
PID_NUCLEI=$!

# FIX xsstrike: fuzzywuzzy pre-installed in pre-flight; add --timeout
run_tool "08_xsstrike" "${TIMEOUT_XSSTRIKE}" \
    /app/tools/xsstrike \
        --url "${TARGET_URL}" \
        --crawl --blind --skip-dom --timeout 10 &
PID_XSSTRIKE=$!

echo -e "${BOLD}└────────────────────────────────────────────────────────────────────┘${NC}"
log "Wave 1 PIDs → nmap:${PID_NMAP} testssl:${PID_TESTSSL} nikto:${PID_NIKTO} katana:${PID_KATANA} ffuf:${PID_FFUF} nuclei:${PID_NUCLEI} xsstrike:${PID_XSSTRIKE}"
echo ""

live_progress "1" \
    "01_nmap:${PID_NMAP}" \
    "02_testssl:${PID_TESTSSL}" \
    "03_nikto:${PID_NIKTO}" \
    "04_katana:${PID_KATANA}" \
    "05_ffuf:${PID_FFUF}" \
    "06_nuclei:${PID_NUCLEI}" \
    "08_xsstrike:${PID_XSSTRIKE}" &
PID_TICKER1=$!

wait_jobs "1" ${PID_NMAP} ${PID_TESTSSL} ${PID_NIKTO} ${PID_KATANA} ${PID_FFUF} ${PID_NUCLEI} ${PID_XSSTRIKE}
kill "${PID_TICKER1}" 2>/dev/null || true; wait "${PID_TICKER1}" 2>/dev/null || true
echo ""

# =============================================================================
#  WAVE 2 — depend on wave-1 outputs, run parallel with each other
# =============================================================================
echo -e "${BOLD}┌─ WAVE 2: 3 parallel jobs (using wave-1 outputs) ───────────────────┐${NC}"

# Build dalfox / sqlmap input from katana
KATANA_LOG="${OUTPUT_DIR}/04_katana.log"
DALFOX_INPUT="/tmp/dalfox_${SAFE_HOST}_${TIMESTAMP}.txt"
SQLMAP_INPUT="/tmp/sqlmap_${SAFE_HOST}_${TIMESTAMP}.txt"

if [[ -f "${KATANA_LOG}" ]] && grep -q '?' "${KATANA_LOG}" 2>/dev/null; then
    grep '?' "${KATANA_LOG}" | sort -u | head -300 > "${DALFOX_INPUT}"
    grep '?' "${KATANA_LOG}" | sort -u | head -50  > "${SQLMAP_INPUT}"
    log "katana → $(wc -l < "${DALFOX_INPUT}") parameterised URLs for dalfox/sqlmap"
else
    printf '%s\n' "${TARGET_URL}" > "${DALFOX_INPUT}"
    printf '%s\n' "${TARGET_URL}" > "${SQLMAP_INPUT}"
    warn "katana: no parameterised URLs found — falling back to base URL"
fi

# 07_dalfox
run_tool "07_dalfox" "${TIMEOUT_DALFOX}" \
    /app/tools/dalfox \
        file "${DALFOX_INPUT}" \
        --silence --no-color \
        --timeout 15 \
        --output "${OUTPUT_DIR}/07_dalfox.log" &
PID_DALFOX=$!

# 09_sqlmap
(
    {
        echo "# Tool   : 09_sqlmap"
        echo "# Start  : $(date)"
        echo "# Input  : ${SQLMAP_INPUT} ($(wc -l < "${SQLMAP_INPUT}") URLs)"
        echo ""
    } > "${OUTPUT_DIR}/09_sqlmap.log"
    local_rc=0
    timeout --kill-after=15s "${TIMEOUT_SQLMAP}" bash -c '
        while IFS= read -r surl; do
            [[ -z "${surl}" ]] && continue
            echo "### Testing: ${surl}" >> "'"${OUTPUT_DIR}/09_sqlmap.log"'"
            /app/tools/sqlmap \
                -u "${surl}" \
                --batch --random-agent \
                --level=3 --risk=2 --forms \
                --output-dir="'"${OUTPUT_DIR}/09_sqlmap_data"'" \
                >> "'"${OUTPUT_DIR}/09_sqlmap.log"'" 2>&1 || true
        done < "'"${SQLMAP_INPUT}"'"
    ' || local_rc=$?
    echo "# End: $(date)  exit:${local_rc}" >> "${OUTPUT_DIR}/09_sqlmap.log"
    [[ ${local_rc} -eq 124 || ${local_rc} -eq 137 ]] \
        && warn "FINISHED 09_sqlmap — TIMED OUT after ${TIMEOUT_SQLMAP}s" \
        || ok   "FINISHED 09_sqlmap (exit ${local_rc})"
) &
PID_SQLMAP=$!
info "STARTED  ${BOLD}09_sqlmap${NC} (limit ${TIMEOUT_SQLMAP}s, PID ${PID_SQLMAP})"

# 10_403bypass — extract 403 URLs from ffuf JSON
FFUF_JSON="${OUTPUT_DIR}/05_ffuf.json"
BYPASS_FILE="/tmp/bypass_${SAFE_HOST}_${TIMESTAMP}.txt"

python3 - <<PY > "${BYPASS_FILE}" 2>/dev/null || true
import json
try:
    data = json.load(open("${FFUF_JSON}"))
    for r in data.get("results", []):
        if r.get("status") == 403:
            print(r.get("url", ""))
except Exception:
    pass
PY

if [[ ! -s "${BYPASS_FILE}" ]]; then
    # FIX: also try common admin paths that might return 403 on juice-shop
    printf '%s\n' \
        "${TARGET_URL}/admin" \
        "${TARGET_URL}/ftp" \
        "${TARGET_URL}/backup" \
        "${TARGET_URL}/api/v1/users" \
        > "${BYPASS_FILE}"
    warn "ffuf: no 403 hits — using default bypass targets"
fi

(
    {
        echo "# Tool   : 10_403bypass"
        echo "# Start  : $(date)"
        echo ""
    } > "${OUTPUT_DIR}/10_403bypass.log"
    local_rc=0
    # FIX: 403-bypass requires -u flag and --exploit for full scan mode
    timeout --kill-after=15s "${TIMEOUT_BYPASS}" bash -c '
        while IFS= read -r burl; do
            [[ -z "${burl}" ]] && continue
            echo "--- ${burl} ---" >> "'"${OUTPUT_DIR}/10_403bypass.log"'"
            /app/tools/403-bypass -u "${burl}" --exploit \
                >> "'"${OUTPUT_DIR}/10_403bypass.log"'" 2>&1 || true
            echo "" >> "'"${OUTPUT_DIR}/10_403bypass.log"'"
        done < "'"${BYPASS_FILE}"'"
    ' || local_rc=$?
    echo "# End: $(date)  exit:${local_rc}" >> "${OUTPUT_DIR}/10_403bypass.log"
    [[ ${local_rc} -eq 124 || ${local_rc} -eq 137 ]] \
        && warn "FINISHED 10_403bypass — TIMED OUT after ${TIMEOUT_BYPASS}s" \
        || ok   "FINISHED 10_403bypass (exit ${local_rc})"
) &
PID_BYPASS=$!
info "STARTED  ${BOLD}10_403bypass${NC} (limit ${TIMEOUT_BYPASS}s, PID ${PID_BYPASS})"

echo -e "${BOLD}└────────────────────────────────────────────────────────────────────┘${NC}"
log "Wave 2 PIDs → dalfox:${PID_DALFOX} sqlmap:${PID_SQLMAP} 403bypass:${PID_BYPASS}"
echo ""

live_progress "2" \
    "07_dalfox:${PID_DALFOX}" \
    "09_sqlmap:${PID_SQLMAP}" \
    "10_403bypass:${PID_BYPASS}" &
PID_TICKER2=$!

wait_jobs "2" ${PID_DALFOX} ${PID_SQLMAP} ${PID_BYPASS}
kill "${PID_TICKER2}" 2>/dev/null || true; wait "${PID_TICKER2}" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                       SCAN COMPLETE                             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Output:${NC} ${OUTPUT_DIR}"
echo ""
echo "Log files:"
ls -lh "${OUTPUT_DIR}" 2>/dev/null \
    | awk 'NR>1 && $NF !~ /\.$/ {printf "  %-42s %s\n", $NF, $5}'
echo ""
{
    echo ""
    echo "========================================================"
    echo "SCAN FINISHED : $(date)"
    echo "Output dir    : ${OUTPUT_DIR}"
    echo "Files:"
    ls "${OUTPUT_DIR}" | sed 's/^/  /'
    echo "========================================================"
} >> "${SUMMARY_FILE}"
echo -e "${GREEN}Summary → ${SUMMARY_FILE}${NC}"
echo ""

