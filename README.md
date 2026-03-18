# Diverg

**AI-powered security testing** — recon, web vulns, API and auth checks, and blockchain-aware investigation. Run from the CLI or the Chrome extension.

Diverg is our own security testing platform. It is not backed by OpenClaw or any other vendor; [OpenClaw](https://github.com/openclaw/openclaw) is an optional integration for multi-agent runs. The core runs standalone.

---

## Ways to run Diverg

| Interface | Use case |
|-----------|----------|
| **CLI (orchestrator)** | Scriptable scans, CI, one-off targets. |
| **HTTP API + Chrome extension** | Scan from the browser, view findings, run **Simulate** (live PoC) per finding. |

---

## What it does

- **Web** — Recon, headers/SSL, web vulns, auth and API testing, OSINT (WHOIS, DNS, Wayback).
- **Blockchain** — Wallet and token investigation (Solscan, Arkham, Etherscan when keys are set), flow diagrams, Bubblemaps holder/cluster data.
- **Delivery** — JSON/NDJSON from API; Chrome extension with results page and Simulate (PoC) buttons.

---

## Prerequisites

- **Python 3.11+**
- **OpenAI API key** (LLM backend)
- **Optional:** [nmap](https://nmap.org/) (recon); Docker (OpenClaw only)

---

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/fennq/diverg.git
cd diverg
cp .env.example .env
```

Edit `.env`: set at least `OPENAI_API_KEY`.

### 2. Install

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run a scan (CLI)

```bash
# Full web scan
python orchestrator.py --target https://example.com --scope full

# Quick passive
python orchestrator.py --target example.com --scope quick

# Recon only
python orchestrator.py --target example.com --scope recon
```

### 4. Or run the API server (for Chrome extension)

```bash
python api_server.py
# Serves http://127.0.0.1:5000 — extension uses this by default
```

Then load the **Chrome extension** from the `extension/` folder: [chrome://extensions](chrome://extensions) → Developer mode → Load unpacked → select `extension/`. Scan from the popup; open “View last results” to see findings and use **Simulate** for live PoC.

---

## Orchestrator (CLI) — scan profiles

| Profile | Skills |
|---------|--------|
| `full` | OSINT, Recon, Headers/SSL, Web Vulns, Auth Test, API Test |
| `quick` | Headers/SSL, Recon, OSINT |
| `recon` | OSINT, Recon |
| `web` | Web Vulns, Headers/SSL, Auth Test |
| `api` | API Test, Headers/SSL |

---

## HTTP API (for extension or other clients)

Start the server: `python api_server.py [--port 5000] [--host 127.0.0.1]`

| Endpoint | Description |
|----------|-------------|
| **POST /api/scan** | Body: `{"url": "https://...", "goal": "optional"}`. Full web scan; with `goal` (e.g. `"payment bypass"`, `"headers"`) only matching skills run. Returns JSON report. |
| **POST /api/scan/stream** | Same body. Returns NDJSON stream for live progress. |
| **POST /api/poc/simulate** | Body: `{"finding": {...}, "url": "..."}` or finding + optional `param_to_change`, `new_value`, `cookies`. Runs minimal PoC (IDOR / unauthenticated); returns conclusion and status. |

RAG citations from `content/` (exploit catalog, prevention docs) are included when available. See `content/API_STREAM_AND_GOAL.md` and `content/API_POC_SIMULATE.md` for details.

---

## Chrome extension

- **Popup:** Enter URL or “Use current tab” → **Scan**. **View last results** opens the results page.
- **Results page:** List of findings; each finding that supports PoC has a **Simulate** button. Simulate calls `POST /api/poc/simulate` and shows the result in a modal.
- **Options:** Set API base URL (default `http://127.0.0.1:5000`).

Extension lives in `extension/` in this repo. See `extension/README.md` for setup.

---

## Optional: OpenClaw

For multi-agent runs: set `OPENCLAW_AUTH_TOKEN` in `.env`, start OpenClaw (e.g. Docker), and use:

```bash
python orchestrator.py --target https://example.com --scope full --use-openclaw
```

Diverg works fully without OpenClaw.

---

## Project layout

```
diverg/
├── api_server.py          # HTTP API (scan, stream, poc/simulate)
├── orchestrator.py       # CLI entry
├── poc_runner.py         # PoC execution for Simulate
├── intent_skills.py      # Goal → skill mapping for goal-based scans
├── config.json           # LLM, skills, rate limits
├── .env.example
├── requirements.txt
├── extension/             # Chrome extension (popup, results, Simulate)
├── rag/                  # RAG index + citations
├── skills/               # Recon, web vulns, auth, API, blockchain, etc.
├── scripts/
└── content/              # Runbooks, API docs, exploit catalog
```

---

## Ethics and authorization

Use only for **authorized** security testing. Get written permission and define scope. Do not test systems you are not allowed to test. Redact PII in findings.

---

## License

MIT
