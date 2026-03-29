# Diverg

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/API-Flask-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)

**Diverg** is an AI-assisted security testing platform for web applications and APIs. It runs coordinated **skills** (specialized scan modules)—transport, recon, application logic, auth, APIs, high-value flaw patterns—and returns structured findings with evidence and remediation guidance. Deliver through the **CLI**, **HTTP API** + **web console**, or the **Chrome extension**.

---

## Highlights

| Area | What you get |
|------|----------------|
| **Web & API security** | Multi-vector assessments, goal-based scopes, streaming scans, PoC simulation |
| **Solana & on-chain** | Token **bundle analysis** (holders, cluster %, coordination score), address lookups via **Helius** + EVM via public RPC—in **console API** and **extension** |
| **Investigations** | Domain OSINT, entity reputation, optional **Bags** / **Helius** pipelines in `investigation/` |
| **Console** | Authenticated dashboard, history, stats, **points & referrals**, leaderboard |

---

## Web & API surface (skills)

Diverg answers: *What can an attacker do here? What’s exposed? Where are the high-impact gaps?*

- **OSINT & recon** — DNS, subdomains, ports, tech stack, sensitive paths  
- **Headers & SSL** — HSTS, TLS, CSP, framing, referrer, permissions  
- **Web vulns & auth** — Injection patterns, session/JWT hygiene, enumeration  
- **API test** — Discovery, methods, GraphQL/OpenAPI exposure, abuse patterns  
- **Client surface** — Source maps, API extraction from JS, dangerous sinks  
- **High-value flaws** — IDOR, secrets in assets, workflow / payment / race / logic abuse  
- **Crypto & data** — JWT/TLS issues, dependency/CVE signals, data-leak patterns  
- **Entity reputation** — Domain and entity context from OSINT-style signals  

Findings use a canonical schema (severity, evidence, impact, remediation). The pipeline supports **goal-based scanning**: a natural-language goal narrows which skills run.

---

## Solana & extension parity

Solana work is first-class—not bolted on as an afterthought.

- **Chrome extension** ([**diverg-extension**](https://github.com/fennq/diverg-extension)): paste a **token mint** (and optional wallet), run **Analyze bundle**—holder map, same-funder clusters, coordination score, and a clear risk verdict. Uses **[Helius](https://www.helius.dev/)** (API key in Options). Canonical UX lives in that repo; `extension/` here stays in sync for this monorepo.
- **Web console** (`api_server.py` + dashboard): authenticated **`POST /api/investigation/solana-bundle`** with the same bundle logic; **`POST /api/investigation/blockchain`** for Solana (Helius) or **EVM** (e.g. Cloudflare Ethereum gateway) address summaries.

Set `HELIUS_API_KEY` on the server or pass/configure the key in the console **Settings** where supported.

---

## Quick start

### Prerequisites

- **Python 3.11+**
- **OpenAI API key** for LLM-backed steps (`OPENAI_API_KEY` in `.env`)
- Optional: [nmap](https://nmap.org/) for recon; Docker only if using OpenClaw integration

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
python orchestrator.py --target https://example.com --scope crypto   # adds chain/batch-style checks
```

Optional: `--report detailed`; `--use-openclaw` if using the OpenClaw backend.

### HTTP API & console

```bash
python api_server.py
# http://127.0.0.1:5000 — dashboard at /dashboard/, login at /login
```

| Endpoint | Description |
|----------|-------------|
| `POST /api/scan` | Full scan (`url`, optional `goal`, `scope`) |
| `POST /api/scan/stream` | NDJSON stream with progress, then full report |
| `POST /api/poc/simulate` | PoC for a finding (IDOR, unauthenticated, etc.) |
| `POST /api/investigation/blockchain` | Solana (Helius) or EVM address summary |
| `POST /api/investigation/solana-bundle` | SPL bundle snapshot (extension parity) |
| `POST /api/investigation/domain` | OSINT + recon + headers (full skill JSON) |
| `POST /api/investigation/reputation` | Entity reputation + OSINT context |
| `GET /api/rewards/me` | Points, referral code, recent ledger (authenticated) |
| `GET /api/rewards/leaderboard` | Leaderboard windows (authenticated) |

Auth: `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/google`, `GET /api/auth/me`.

---

## Scan profiles (CLI)

| Profile | Focus |
|---------|--------|
| **full** | Full web pipeline (OSINT, recon, headers, vulns, auth, API, high-value, workflow, race, payment, client, deps, logic, reputation, …) |
| **crypto** | Full + chain/batch validation–style checks for crypto-facing targets |
| **quick** | Headers, recon, OSINT, company exposure |
| **recon** | OSINT + recon |
| **web** | Web vulns, headers, auth, company exposure |
| **api** | API test, headers, company exposure |
| **passive** | OSINT, headers, company exposure |

---

## Repository layout

| Path | Purpose |
|------|---------|
| `orchestrator.py` | CLI; scan profiles and optional OpenClaw |
| `api_server.py` | Flask API, dashboard static files, auth, scans, investigations, rewards |
| `dashboard/` | Web console (HTML/JS/CSS) |
| `dashboard_points.py` | Points, referrals, leaderboard helpers |
| `poc_runner.py` | PoC execution for Simulate |
| `intent_skills.py` | Goal → skills mapping |
| `config.json` | LLM and skill configuration |
| `skills/` | Scan modules |
| `investigation/` | On-chain clients, Solana bundle script, optional Bags API integration |
| `extension/` | Extension worker mirror—sync with [**diverg-extension**](https://github.com/fennq/diverg-extension) |
| `rag/` | Citations index (local content; not always shipped) |
| `.env.example` | Environment template |

Internal runbooks and exploit-catalog content may live locally for full RAG behavior; they are not required for core scans.

---

## Chrome extension

Use the standalone repository for the shipping extension:

**[github.com/fennq/diverg-extension](https://github.com/fennq/diverg-extension)** — load unpacked from there. This repo’s `extension/` folder mirrors shared pieces; see [`extension/README.md`](extension/README.md).

---

## Ethics & authorization

Use Diverg only for **authorized** security testing. Get written permission and a clear scope before testing systems you do not own or operate. Redact PII and secrets in shared reports.

---

## License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE).
