# SOC URL Investigator — Malware URL Analysis Dashboard

A comprehensive **Malware URL Investigation Dashboard** built for SOC analysts to triage, analyze, and track malicious URLs.

## Features

- **URL Submission & Queue** — Submit URLs with priority tagging
- **Automated Static Analysis** — Domain parsing, entropy calculation, suspicious pattern detection
- **DNS & WHOIS Lookups** — Resolve IPs, check domain age, registrar info
- **Threat Intelligence Integration** — VirusTotal, URLScan.io, AbuseIPDB (API key configurable)
- **Risk Scoring** — Weighted 0-100 score based on multiple analysis factors
- **IOC Extraction** — Automatically extract domains, IPs, paths as indicators
- **Case Management** — Track investigation status, add analyst notes, escalate
- **REST API** — Programmatic submission and case retrieval
- **SOC-Themed Dark UI** — Bootstrap 5 dark theme with Chart.js visualizations

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python / Flask |
| Database | SQLAlchemy (SQLite/PostgreSQL) |
| Frontend | Bootstrap 5 Dark, Chart.js, Font Awesome |
| Analysis | tldextract, dnspython, python-whois |
| Threat Intel | VirusTotal API v3, URLScan.io, AbuseIPDB |

## Quick Start

### Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
cd ~/soc-url-investigator

cat > .gitignore << 'EOF'
# Virtual environment
venv/
env/
.venv/

# Database
*.db
data/

# Logs
logs/*.log
logs/*.log.*

# Reports / Screenshots
reports/screenshots/*
reports/*.pdf

# Python cache
__pycache__/
*.pyc
*.pyo
*.pyd
*.egg-info/
dist/
build/

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Environment files
.env
*.env

# Config with secrets (keep template, exclude actual keys)
config/config.yaml
!config/config.yaml.example
