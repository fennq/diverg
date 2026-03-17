# Diverg

**Diverg** is our own security testing platform. It runs automated reconnaissance, vulnerability scanning, and blockchain-aware investigation, and can deliver findings via Telegram (with a private dashboard planned).

We are not backed by or founded by OpenClaw or any other vendor. OpenClaw is an optional integration you can use for multi-agent runs; the core product runs standalone.

---

## What it does

- **Web:** Recon, headers/SSL, web vulns, auth and API testing, OSINT (WHOIS, DNS, Wayback).
- **Blockchain:** Wallet and token investigation (Solscan, Arkham, Etherscan when keys are set), flow diagrams, Bubblemaps holder/cluster data.
- **Delivery:** Telegram bot for scan reports today; dashboard coming for richer views.

---

## Prerequisites

- Python 3.11+
- OpenAI API key
- Telegram bot token + chat ID (for report delivery)
- Optional: [nmap](https://nmap.org/) (recon); Docker (only if you use the optional OpenClaw integration)

---

## Quick start

**1. Clone and configure**

```bash
cd diverg
cp .env.example .env
```

Edit `.env`: set `OPENAI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Get your chat ID from [@userinfobot](https://t.me/userinfobot).

**2. Install and run**

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Run the bot (Telegram)**

```bash
python bot.py
```

Then in Telegram: send a URL or “scan https://example.com” (or use `/chain`, `/web` for focused scans).

**4. Or run the CLI orchestrator**

```bash
# Full web scan + report to Telegram
python orchestrator.py --target https://example.com --scope full

# Quick passive
python orchestrator.py --target example.com --scope quick

# Recon only
python orchestrator.py --target example.com --scope recon
```

---

## Scan modes (Telegram bot)

- **Full scan** — Say a URL or “scan &lt;url&gt;” for adaptive web + optional chain.
- **Web only** — “web scan &lt;url&gt;” or `/web &lt;url&gt;`.
- **Blockchain only** — “blockchain scan &lt;wallet&gt;” or `/chain &lt;wallet&gt;` (optional chain flag).
- **Bubblemaps** — Token holder/cluster data when you have an API key.

---

## Orchestrator profiles (CLI)

| Profile | Skills |
|--------|--------|
| `full` | OSINT, Recon, Headers/SSL, Web Vulns, Auth Test, API Test |
| `quick` | Headers/SSL, Recon, OSINT |
| `recon` | OSINT, Recon |
| `web` | Web Vulns, Headers/SSL, Auth Test |
| `api` | API Test, Headers/SSL |

---

## Chrome extension and HTTP API

The **Diverg Chrome extension** (separate repo: `diverg-extension`) talks to this backend for full scans.

**Start the API server** (from this repo):

```bash
python api_server.py [--port 5000]
```

- **POST /api/scan** — Body: `{"url": "https://...", "goal": "optional"}`. Runs full web scan; with `goal` (e.g. `"payment bypass"`, `"headers"`, `"full audit"`) only matching skills run. Returns JSON: `target_url`, `findings`, `scanned_at`, `summary`, `skills_run`. Findings may include **citations** (RAG: sources from exploit catalog and prevention docs).
- **POST /api/scan/stream** — Same body. Returns **NDJSON** stream: `skill_start`, `skill_done`, then `done` with full `report`. Use for live progress in the extension.

**RAG:** Reports are enriched with citations from `content/` (exploit catalog, prevention docs). Optional: set `OPENAI_API_KEY` so the RAG index uses embeddings for better relevance.

See `content/API_STREAM_AND_GOAL.md` for stream event format and example client code.

---

## Optional: OpenClaw

If you use the [OpenClaw](https://github.com/openclaw/openclaw) SDK and run with `--use-openclaw`, the orchestrator can delegate to an OpenClaw multi-agent session. Set `OPENCLAW_AUTH_TOKEN` in `.env` and start OpenClaw (e.g. Docker). This is optional; Diverg works fully without it.

---

## Project layout

```
diverg/
├── api_server.py           # HTTP API for Chrome extension (POST /api/scan, /api/scan/stream)
├── bot.py                  # Telegram bot entry
├── orchestrator.py         # CLI entry; run_web_scan(goal=), run_web_scan_streaming()
├── intent_skills.py        # Natural-language goal → skill list (for goal-based scans)
├── rag/                    # RAG index + retrieve; citations on findings
├── config.json             # LLM, skills, rate limits
├── .env.example
├── requirements.txt
├── agents/                 # Optional OpenClaw-style agents
├── skills/                 # Recon, web vulns, headers/SSL, OSINT, blockchain, bubblemaps, etc.
├── scripts/
└── content/                # Templates, diagrams, runbooks, API_STREAM_AND_GOAL.md
```

---

## Ethics and authorization

Use only for **authorized** security testing. Get written permission, define scope, and never test systems you are not allowed to test. Findings must not expose real user data; redact PII.

---

## License

MIT
