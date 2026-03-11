# SecTester

AI-powered security testing agent built on [OpenClaw](https://github.com/openclaw/openclaw). Performs automated reconnaissance, vulnerability scanning, and delivers findings to Telegram.

## Features

| Skill | What it does |
|-------|-------------|
| **Recon** | Port scanning (nmap + fallback), subdomain enumeration, technology fingerprinting |
| **Web Vulns** | Reflected XSS detection, SQL injection probing, CSRF analysis, directory traversal |
| **Headers/SSL** | HTTP security header audit, SSL/TLS protocol & cipher analysis, certificate checks |
| **Auth Test** | Login form discovery, cookie flag analysis, session management, user enumeration |
| **API Test** | Endpoint brute-force, HTTP method testing, CORS checks, auth bypass, IDOR detection |
| **OSINT** | WHOIS, DNS enumeration, zone transfer attempts, email pattern discovery, Wayback Machine |
| **Telegram Report** | Sends formatted reports with severity badges to your Telegram chat |

## Prerequisites

- Python 3.11+
- Docker & Docker Compose (for OpenClaw)
- [nmap](https://nmap.org/) (optional — falls back to TCP connect scan)
- An OpenAI API key
- A Telegram bot token (from [@BotFather](https://t.me/BotFather))

## Quick Start

### 1. Clone and configure

```bash
cd Sectester
cp .env.example .env
```

Edit `.env` and fill in your keys:

```
OPENCLAW_AUTH_TOKEN=<generate a strong random string>
OPENAI_API_KEY=sk-...
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=<your chat ID>
```

To find your Telegram chat ID, message [@userinfobot](https://t.me/userinfobot).

### 2. Install Python dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start OpenClaw (optional — required for `--use-openclaw` mode)

```bash
docker-compose up -d
```

The OpenClaw UI will be at `http://localhost:3000`.

### 4. Run a scan

```bash
# Full scan with terminal output + Telegram report
python orchestrator.py --target https://example.com --scope full

# Quick passive scan
python orchestrator.py --target example.com --scope quick

# Recon only
python orchestrator.py --target example.com --scope recon

# Web vulnerability focus
python orchestrator.py --target https://example.com --scope web

# API-focused scan
python orchestrator.py --target https://api.example.com --scope api

# Detailed Telegram report
python orchestrator.py --target https://example.com --scope full --report detailed

# Delegate to OpenClaw agent
python orchestrator.py --target https://example.com --scope full --use-openclaw
```

## Scan Profiles

| Profile | Skills |
|---------|--------|
| `full` | OSINT, Recon, Headers/SSL, Web Vulns, Auth Test, API Test |
| `quick` | Headers/SSL, Recon, OSINT |
| `recon` | OSINT, Recon |
| `web` | Web Vulns, Headers/SSL, Auth Test |
| `api` | API Test, Headers/SSL |
| `passive` | OSINT, Headers/SSL |

## Telegram Reports

Three report formats are available:

- **summary** (default) — severity breakdown + top 10 findings
- **detailed** — full report with evidence and remediation for every finding
- **alert** — quick notification of critical/high findings only

## Running Individual Skills

Each skill can also be run standalone:

```bash
# Recon
python skills/recon/recon.py example.com full

# Web vulnerability scan
python skills/web_vulns/web_vulns.py https://example.com full

# Headers & SSL analysis
python skills/headers_ssl/headers_ssl.py https://example.com full

# Authentication testing
python skills/auth_test/auth_test.py https://example.com/login full

# API endpoint testing
python skills/api_test/api_test.py https://example.com full

# OSINT
python skills/osint/osint.py example.com full
```

## Reports

JSON reports are saved to the `reports/` directory after every scan, named:

```
reports/sectester_<domain>_<timestamp>.json
```

## Project Structure

```
Sectester/
├── docker-compose.yml              OpenClaw + Redis
├── config.json                     OpenClaw configuration
├── .env.example                    API key template
├── requirements.txt                Python dependencies
├── orchestrator.py                 CLI entry point
├── agents/
│   └── sectester/
│       └── SOUL.md                 Agent identity & methodology
├── skills/
│   ├── recon/                      Port scan, subdomains, tech stack
│   ├── web_vulns/                  XSS, SQLi, CSRF, traversal
│   ├── headers_ssl/                Security headers, TLS config
│   ├── auth_test/                  Login forms, cookies, sessions
│   ├── api_test/                   API endpoints, methods, auth bypass
│   ├── osint/                      WHOIS, DNS, emails, Wayback
│   └── telegram_report/           Telegram message formatting
└── reports/                        Saved scan results (auto-created)
```

## Ethics & Authorization

This tool is for **authorized security testing only**. Before scanning any target:

1. Obtain **written permission** from the target owner
2. Define the **scope** clearly (which domains, IPs, and tests are allowed)
3. **Never** use this tool against systems you do not have permission to test
4. Findings contain redacted PII — never store or transmit real user data

The agent's SOUL.md enforces these boundaries and will refuse unauthorized actions.

## License

MIT
