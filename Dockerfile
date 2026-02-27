# LLM-Enhanced Security Scanner System v3.0 - Dockerfile
# With AutoScanner v3.0 + SPA Support (Playwright)
FROM python:3.12-slim

LABEL maintainer="Security Scanner Team"
LABEL description="LLM-Enhanced Security Scanner System v3.0 with SPA Support (Playwright)"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# =============================================================================
# SYSTEM DEPENDENCIES
# =============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    unzip \
    xxd \
    apt-transport-https \
    gnupg \
    nmap \
    procps \
    bash \
    ca-certificates \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwww-perl \
    libjson-perl \
    libxml-writer-perl \
    dnsutils \
    # Playwright dependencies
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# TOOLS DIRECTORY SETUP
# =============================================================================
RUN mkdir -p /app/tools

# =============================================================================
# INSTALL SQLMAP (SQL Injection Tool)
# =============================================================================
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /app/tools/sqlmap_lib \
    && chmod +x /app/tools/sqlmap_lib/sqlmap.py

# Create sqlmap wrapper
RUN echo '#!/bin/bash\nSCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\nexec python3 "$SCRIPT_DIR/sqlmap_lib/sqlmap.py" "$@"' > /app/tools/sqlmap \
    && chmod +x /app/tools/sqlmap

# =============================================================================
# INSTALL DALFOX (XSS Scanner)
# =============================================================================
RUN wget -q https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz \
    && tar -xzf dalfox-linux-amd64.tar.gz -C /app/tools/ \
    && mv /app/tools/dalfox-linux-amd64 /app/tools/dalfox \
    && rm dalfox-linux-amd64.tar.gz \
    && chmod +x /app/tools/dalfox

# =============================================================================
# INSTALL NUCLEI (Vulnerability Scanner)
# =============================================================================
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.7.0/nuclei_3.7.0_linux_amd64.zip \
    && unzip -q nuclei_3.7.0_linux_amd64.zip -d /app/tools/ \
    && rm nuclei_3.7.0_linux_amd64.zip \
    && chmod +x /app/tools/nuclei

# =============================================================================
# INSTALL KATANA (Crawler for API discovery)
# =============================================================================
# Use GitHub API to fetch the latest linux_amd64 release asset, to avoid hardcoding the version.
RUN set -e; \
    python3 - <<'PY'
import json
import sys
import urllib.request

url = "https://api.github.com/repos/projectdiscovery/katana/releases/latest"
req = urllib.request.Request(url, headers={"User-Agent": "security-scanner"})
with urllib.request.urlopen(req, timeout=30) as r:
    data = json.load(r)

asset = None
for a in data.get("assets", []):
    name = a.get("name", "")
    if name.startswith("katana_") and name.endswith("linux_amd64.zip"):
        asset = a
        break

if not asset:
    print("Could not find katana linux_amd64.zip asset", file=sys.stderr)
    sys.exit(1)

download = asset.get("browser_download_url")
print("Downloading", download)
urllib.request.urlretrieve(download, "/tmp/katana.zip")
PY
RUN unzip -oq /tmp/katana.zip -d /app/tools/ \
    && rm -f /tmp/katana.zip \
    && chmod +x /app/tools/katana

# =============================================================================
# INSTALL TESTSSL.SH (TLS/SSL Scanner)
# =============================================================================
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /app/tools/testssl.sh \
    && chmod +x /app/tools/testssl.sh/testssl.sh

# Create testssl wrapper
RUN echo '#!/bin/bash\nSCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\nexec bash "$SCRIPT_DIR/testssl.sh/testssl.sh" "$@"' > /app/tools/testssl \
    && chmod +x /app/tools/testssl

# =============================================================================
# INSTALL 4-ZERO-3 (403/401 Bypass Techniques)
# =============================================================================
# Upstream: https://github.com/Dheerajmadhukar/4-ZERO-3
# Note: this is a bash tool; we ship it inside the image to avoid relying on a
# non-existent `4zero3/4zero3` Docker image.
RUN mkdir -p /app/tools/4zero3 \
    && curl -fsSL -o /app/tools/4zero3/403-bypass.sh https://raw.githubusercontent.com/Dheerajmadhukar/4-ZERO-3/main/403-bypass.sh \
    && chmod +x /app/tools/4zero3/403-bypass.sh \
    && echo '#!/bin/bash\nexport TERM=xterm\nexec bash /app/tools/4zero3/403-bypass.sh "$@"' > /app/tools/403-bypass \
    && chmod +x /app/tools/403-bypass

# =============================================================================
# INSTALL NIKTO (Web Server Scanner)
# =============================================================================
RUN git clone --depth 1 https://github.com/sullo/nikto.git /app/tools/nikto \
    && chmod +x /app/tools/nikto/program/nikto.pl

# Create nikto wrapper in PATH (can't be /app/tools/nikto because that is a directory)
RUN echo '#!/bin/bash\nexec perl /app/tools/nikto/program/nikto.pl "$@"' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# =============================================================================
# INSTALL FFUF (Fast Fuzz)
# =============================================================================
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz -C /app/tools/ \
    && rm ffuf_2.1.0_linux_amd64.tar.gz \
    && chmod +x /app/tools/ffuf

# =============================================================================
# INSTALL XSSTRIKE (XSS Detection Suite)
# =============================================================================
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /app/tools/XSStrike \
    && chmod +x /app/tools/XSStrike/xsstrike.py

# Create xsstrike wrapper
RUN echo '#!/bin/bash\ncd "$(dirname "${BASH_SOURCE[0]}")/XSStrike"\nexec python3 xsstrike.py "$@"' > /app/tools/xsstrike \
    && chmod +x /app/tools/xsstrike

# =============================================================================
# INSTALL HEXDUMP WRAPPER
# =============================================================================
RUN echo '#!/bin/bash\nexec /usr/bin/xxd "$@"' > /app/tools/hexdump \
    && chmod +x /app/tools/hexdump

# =============================================================================
# PYTHON DEPENDENCIES
# =============================================================================
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# INSTALL PLAYWRIGHT (For SPA Crawling)
# =============================================================================
# First install additional dependencies needed for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    fonts-liberation \
    fonts-noto-color-emoji \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright browsers
RUN pip install playwright && \
    playwright install chromium && \
    playwright install-deps chromium 2>/dev/null || true

# =============================================================================
# COPY APPLICATION FILES
# =============================================================================
COPY security_scanner_system/ ./security_scanner_system/
COPY dashboard/ ./dashboard/
COPY reports/ ./reports/

# =============================================================================
# CREATE NECESSARY DIRECTORIES
# =============================================================================
RUN mkdir -p /app/reports /app/parallel_scan_results /app/logs

# =============================================================================
# SETUP PATH AND ENVIRONMENT
# =============================================================================
ENV PATH=/app/tools:$PATH

# Default environment variables (can be overridden at runtime)
ENV OPENAI_API_KEY=""
ENV OPENAI_API_BASE_URL="http://157.10.162.82:443/v1/"
ENV GPT_MODEL="gpt-5.1"
ENV DASHBOARD_PORT=14000

# =============================================================================
# HEALTH CHECK
# =============================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${DASHBOARD_PORT}/health || exit 1

# =============================================================================
# EXPOSE PORT
# =============================================================================
EXPOSE ${DASHBOARD_PORT}

# =============================================================================
# RUN THE DASHBOARD
# =============================================================================
CMD ["bash"]
