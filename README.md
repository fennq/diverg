# Diverg

**Diverg** is an AI-assisted security testing platform that runs comprehensive, multi-vector assessments against web applications and APIs. It combines automated checks across transport, surface exposure, application logic, authentication, API behaviour, and high-value flaw patterns into a single pipeline—deliverable via CLI, HTTP API, or Chrome extension—with structured findings, evidence, and remediation guidance.

---

## What Diverg Does

Diverg executes a coordinated set of **skills** (specialised scan modules) against a target URL or domain. Each skill focuses on a specific risk surface; results are normalised, deduplicated, and aggregated into a single report with severity, evidence, impact, and remediation. The platform is designed to answer: *What can an attacker do here? What’s exposed? Where are the high-impact gaps?*

### Surface and reconnaissance

- **OSINT** — External intelligence: DNS, historic exposure, internet-facing context, and public signals about the target.
- **Recon** — Subdomains, open ports, technologies, WAFs, and sensitive file paths (e.g. config, backup, debug).
- **Headers & SSL** — Transport and browser trust: HSTS, TLS versions, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and related security headers.
- **Company exposure** — Probing for admin, debug, docs, exports, storage, support, staging, and other high-value paths that should not be publicly reachable.

### Application and API

- **Web vulns** — Web-layer checks: injection, path traversal, SSRF, and file exposure patterns.
- **Auth test** — Login and identity: JWT handling, session hygiene, credential exposure, and enumeration.
- **API test** — Endpoint discovery, HTTP methods, auth gaps, schema exposure (e.g. GraphQL, OpenAPI), and API abuse patterns.
- **Client surface** — Frontend intelligence: source maps, API extraction from JS, dangerous sinks, and client-side data exposure.

### High-value and business logic

- **High-value flaws** — IDOR, secrets in frontend assets, business-logic and payment tampering.
- **Workflow probe** — Business-flow abuse: confirm-without-pay, zero-amount, step-skipping, and state-machine bypass.
- **Payment & financial** — Zero or manipulated payment flows, payment/wallet IDOR, refund abuse—how users can lose money.
- **Race condition** — Concurrent-request testing for double success, duplicate processing, and limit bypass.
- **Logic abuse** — Numeric and bounds abuse (amounts, limits, offsets), overflow, and success-like responses to tampered parameters.

### Data, crypto, and trust

- **Data leak risks** — Verbose errors, cache misconfiguration, PII or tokens in responses and client-side—small leaks that compound.
- **Crypto security** — JWT algorithm weaknesses (e.g. alg:none), weak TLS (1.0/1.1), and weak crypto in frontend JS.
- **Dependency audit** — Detected stack and versions, CVE watchlist, and upgrade recommendations.
- **Entity reputation** — Domain and entity research: foul-play, fraud, litigation, breach history, and reputation signals.

### Optional and scope-dependent

- **Chain / batch validation** — For high-value or crypto-related targets: batch-vs-single path validation gaps, account/subaccount ID substitution, and parameter trust (batch and bulk endpoints that skip checks present on single-operation paths).

Findings are produced in a canonical schema: **title**, **severity**, **url**, **category**, **evidence**, **impact**, and **remediation**. When the API is used, findings can be enriched with citations from an internal knowledge base (exploit catalog, prevention docs). The pipeline supports **goal-based scanning**: a natural-language goal (e.g. “payment bypass”, “admin panel”, “headers”) selects only the skills that match, for faster, focused runs.

---

## How to Run Diverg

### Prerequisites

- **Python 3.11+**
- **OpenAI API key** (for LLM-backed steps; set in environment)
- Optional: [nmap](https://nmap.org/) for recon; Docker only if using OpenClaw integration

### Setup

```bash
git clone https://github.com/fennq/diverg.git
cd diverg
cp .env.example .env
```

Edit `.env` and set at least `OPENAI_API_KEY`. Then:

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### CLI (orchestrator)

The orchestrator runs scan **profiles** (sets of skills) against a target:

```bash
# Full web scan (all skills in the web pipeline)
python orchestrator.py --target https://example.com --scope full

# Quick: headers, recon, OSINT, company exposure
python orchestrator.py --target https://example.com --scope quick

# Recon only
python orchestrator.py --target example.com --scope recon

# Web-focused: web vulns, headers, auth, company exposure
python orchestrator.py --target https://example.com --scope web

# API-focused: API test, headers, company exposure
python orchestrator.py --target https://example.com --scope api

# Passive: OSINT, headers, company exposure
python orchestrator.py --target https://example.com --scope passive

# Crypto scope (adds chain/batch validation for DeFi-style targets)
python orchestrator.py --target https://example.com --scope crypto
```

Optional: `--report detailed` for richer output; `--use-openclaw` if you use the optional OpenClaw multi-agent backend.

### HTTP API

Start the API server for the Chrome extension or other clients:

```bash
python api_server.py
# Serves http://127.0.0.1:5000 by default; use --port and --host to change
```

| Endpoint | Description |
|----------|-------------|
| **POST /api/scan** | Run a full web scan. Body: `{"url": "https://...", "goal": "optional", "scope": "full\|quick\|crypto\|recon\|web\|api\|passive"}`. Returns JSON: `target_url`, `findings`, `scanned_at`, `summary`, `skills_run`, `site_classification`. |
| **POST /api/scan/stream** | Same body. Returns an NDJSON stream: `skill_start`, `skill_done` (with `findings_count`), then `done` with the full report. Use for live progress in the UI. |
| **POST /api/poc/simulate** | Run a minimal proof-of-concept for a finding. Body: `{"finding": {...}}` or explicit `{"type": "idor", "url": "...", "param_to_change": "...", "new_value": "..."}`. Returns `success`, `status_code`, `body_preview`, `conclusion`. Used by the extension “Simulate” button for IDOR and unauthenticated-access checks. |

The API does not perform blockchain or wallet-specific scanning; it is a web and API security pipeline.

### Chrome extension

The **Chrome extension** (popup, side panel, results page, Simulate) lives in a separate repo. It can:

- Run a **quick in-browser scan** (headers, page checks) with no backend.
- Call this API when running a **full scan** (auto-detects `http://127.0.0.1:5000` or configurable base URL).
- Display findings and use **Simulate** to call `POST /api/poc/simulate` for live PoC.

Load the extension from the other repo (e.g. Load unpacked → select the extension folder). This repo contains shared extension **tech** (background worker, API auto-detect) under `extension/` for sync with that repo.

---

## Scan profiles (CLI)

| Profile | Skills included |
|---------|-----------------|
| **full** | OSINT, recon, headers_ssl, crypto_security, data_leak_risks, company_exposure, web_vulns, auth_test, api_test, high_value_flaws, workflow_probe, race_condition, payment_financial, client_surface, dependency_audit, logic_abuse, entity_reputation |
| **crypto** | Same as full, plus chain_validation_abuse (batch/single path and account-id checks for high-value or crypto-style targets) |
| **quick** | headers_ssl, recon, osint, company_exposure |
| **recon** | osint, recon |
| **web** | web_vulns, headers_ssl, auth_test, company_exposure |
| **api** | api_test, headers_ssl, company_exposure |
| **passive** | osint, headers_ssl, company_exposure |

Goal-based scanning (API and optional CLI flow) narrows this further by running only skills that match a natural-language goal (e.g. “payment bypass”, “headers”, “admin panel”).

---

## Project layout

| Path | Purpose |
|------|--------|
| `orchestrator.py` | CLI entry; runs scan profiles and optional OpenClaw integration. |
| `api_server.py` | Flask HTTP API: scan, stream, PoC simulate. |
| `poc_runner.py` | PoC execution for Simulate (IDOR, unauthenticated, etc.). |
| `intent_skills.py` | Maps natural-language goals to skills for goal-based scans. |
| `config.json` | LLM and skill configuration, rate limits. |
| `skills/` | Scan modules (headers_ssl, recon, osint, web_vulns, auth_test, api_test, company_exposure, high_value_flaws, workflow_probe, payment_financial, race_condition, crypto_security, data_leak_risks, client_surface, dependency_audit, logic_abuse, entity_reputation, chain_validation_abuse, etc.). |
| `rag/` | Index and retrieval for citations (reads from local content; not shipped in repo). |
| `extension/` | Shared extension tech (background, API auto-detect) kept in sync with the separate extension repo. |
| `.env.example` | Template for environment variables (copy to `.env` and fill). |

Internal content (runbooks, exploit catalog, prevention docs) is not included in this repository; the pipeline expects it to be present locally for full citation and RAG behaviour.

---

## Ethics and authorization

Use Diverg only for **authorized** security testing. Obtain written permission and a defined scope before testing any system you do not own or are not explicitly permitted to test. Do not probe targets that have not authorized you. Redact PII and sensitive data from findings when sharing or storing reports.

---

## License

MIT
