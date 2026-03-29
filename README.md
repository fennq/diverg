# Diverg

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Chrome extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white)](https://github.com/fennq/diverg-extension)

**Diverg** is an AI-assisted security testing platform for web applications and APIs. It runs coordinated **skills** (specialized scan modules) across transport, exposure, application logic, authentication, API behavior, and high-impact flaw patterns—deliverable via **CLI**, **HTTP API**, **web console**, or **Chrome extension**—with structured findings, evidence, and remediation guidance.

---

## Highlights

| Area | What you get |
|------|----------------|
| **Web & API** | OSINT, recon, headers/TLS, web vulns, auth, API discovery, client JS surface, dependency/CVE signals, entity reputation |
| **Solana & on-chain** | SPL **token bundle** analysis (holders, shared-funder clusters, coordination score)—**[Chrome extension](https://github.com/fennq/diverg-extension)** + matching **`/api/investigation/solana-bundle`** in the console API; **Helius**-backed Solana account queries and **EVM** address summaries via **`/api/investigation/blockchain`** |
| **Console** | Authenticated **dashboard** (`/dashboard/`), scan history, investigation tools, **points / referrals / leaderboard** (server-issued rewards) |
| **Extension** | Quick scans, full scans against local API, **Solana bundle** UI, PoC simulate—see **`extension/`** (mirror) and **[diverg-extension](https://github.com/fennq/diverg-extension)** for the canonical UX |

---

## What Diverg does

Diverg answers: *What can an attacker do here? What’s exposed? Where are the high-impact gaps?* Findings use a consistent schema: **title**, **severity**, **url**, **category**, **evidence**, **impact**, and **remediation**. The pipeline supports **goal-based scanning**: a natural-language goal narrows which skills run.

### Surface and reconnaissance

- **OSINT** — DNS, historic exposure, public signals  
- **Recon** — Subdomains, ports, technologies, WAFs, sensitive paths  
- **Headers & SSL** — HSTS, TLS, CSP, framing, content-type, referrer, permissions  
- **Company exposure** — Admin, debug, docs, exports, staging-style paths  

### Application and API

- **Web vulns** — Injection, traversal, SSRF, file exposure patterns  
- **Auth test** — Sessions, JWT hygiene, enumeration  
- **API test** — Methods, auth gaps, GraphQL/OpenAPI exposure  
- **Client surface** — Source maps, API extraction from JS, dangerous sinks  

### High-value and business logic

- **High-value flaws** — IDOR, secrets in assets, logic/payment tampering  
- **Workflow / payment / race / logic abuse** — Flow bypass, double processing, numeric abuse  

### Data, crypto, and trust

- **Data leak risks** — Verbose errors, cache issues, PII/tokens in responses  
- **Crypto security** — JWT `alg` issues, weak TLS in stack  
- **Dependency audit** — Versions, CVE watchlist  
- **Entity reputation** — Domain/entity context signals  

### Optional chain-style checks

- **Chain / batch validation** — For crypto-adjacent targets: batch-vs-single and parameter-trust gaps (`crypto` scope + `chain_validation_abuse` skill)  

---

## Solana & extension (quick reference)

| Surface | Role |
|---------|------|
| **[diverg-extension](https://github.com/fennq/diverg-extension)** | **Canonical** Chrome UX: popup, side panel, **Solana token bundle** (mint + optional wallet, **Helius** key in Options), full-scan API pairing |
| **`extension/`** in this repo | **Mirror** of extension tech (background, API auto-detect); sync `sidepanel.*`, `solana_bundle.js`, `options.*`, `icons/` from the canonical repo |
| **`api_server.py`** | **`POST /api/investigation/solana-bundle`** — same bundle methodology as the extension (holders, cluster %, coordination / risk score); requires **Helius API key** (dashboard Settings or `HELIUS_API_KEY`) |
| **`investigation/`** | Python clients: Solana RPC, **Helius**, optional **Bags**, **Arkham**, blockchain fetch pipeline for research scripts |

Solana bundle analysis is **read-only on-chain intelligence** for investigations—not financial advice. Use only on assets and systems you are authorized to assess.

---

## How to run

### Prerequisites

- **Python 3.11+**  
- **OpenAI API key** for LLM-backed steps (set in environment)  
- Optional: [nmap](https://nmap.org/) for recon; Docker only if using OpenClaw integration  
- **Helius** (optional): Solana lookups in API/extension bundle features  

### Setup

```bash
git clone https://github.com/fennq/diverg.git
cd diverg
cp .env.example .env
```

Edit `.env` (at least `OPENAI_API_KEY`). Then:

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### CLI (`orchestrator.py`)

```bash
python orchestrator.py --target https://example.com --scope full
python orchestrator.py --target https://example.com --scope quick
python orchestrator.py --target example.com --scope recon
python orchestrator.py --target https://example.com --scope web
python orchestrator.py --target https://example.com --scope api
python orchestrator.py --target https://example.com --scope passive
python orchestrator.py --target https://example.com --scope crypto
```

Optional: `--report detailed`; `--use-openclaw` if using the OpenClaw backend.

### HTTP API & console

```bash
python api_server.py
# Default: http://127.0.0.1:5000 — use --host / --port to change
```

| Area | Endpoints (summary) |
|------|---------------------|
| **Auth** | `POST /api/auth/register`, `login`, `google`; `GET /api/auth/me` |
| **Scans** | `POST /api/scan`, `POST /api/scan/stream`; `POST /api/poc/simulate` |
| **Investigation** (auth) | `POST /api/investigation/blockchain`, `domain`, `reputation`, **`solana-bundle`** |
| **Dashboard** | `GET /dashboard/`, `/login`; history, stats, **`/api/rewards/me`**, **`/api/rewards/leaderboard`** |
| **Health** | `GET /api/health` |

The extension can call the same API for **full scans** when `api_server.py` is running (auto-detect or configured base URL).

### Chrome extension

Load **unpacked** from **[github.com/fennq/diverg-extension](https://github.com/fennq/diverg-extension)**. Use this repo’s `extension/` folder only when contributing to the **monorepo mirror**—copy canonical assets from **diverg-extension** as described in `extension/README.md`.

---

## Scan profiles (CLI)

| Profile | Skills (summary) |
|---------|-------------------|
| **full** | Full web pipeline: OSINT, recon, headers, crypto_security, data leaks, company exposure, web_vulns, auth, API, high-value, workflow, race, payment, client, dependency, logic, entity_reputation |
| **crypto** | Same as **full** plus **chain_validation_abuse** |
| **quick** | headers_ssl, recon, osint, company_exposure |
| **recon** | osint, recon |
| **web** | web_vulns, headers_ssl, auth_test, company_exposure |
| **api** | api_test, headers_ssl, company_exposure |
| **passive** | osint, headers_ssl, company_exposure |

---

## Project layout

| Path | Purpose |
|------|---------|
| `orchestrator.py` | CLI entry; scan profiles |
| `api_server.py` | Flask API: auth, scans, PoC, investigation, dashboard static, rewards |
| `poc_runner.py` | PoC execution for Simulate |
| `dashboard_points.py` | Points, referrals, leaderboard (SQLite) |
| `intent_skills.py` | Goal → skill mapping |
| `config.json` | LLM / skill configuration |
| `skills/` | Scan modules |
| `investigation/` | On-chain clients, `blockchain_fetch`, optional case scripts |
| `extension/` | Extension mirror (see `extension/README.md`) |
| `rag/` | Citations index (local content; not shipped) |
| `.env.example` | Environment template |

Internal runbooks and RAG content are expected locally for full citation behavior.

---

## Ethics and authorization

Use Diverg only for **authorized** security testing. Obtain permission and a clear scope before testing systems you do not own. Redact PII and secrets in shared reports.

---

## License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE).
