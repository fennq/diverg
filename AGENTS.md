# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

Diverg is an AI-assisted security testing platform. See `README.md` for full details. **Private investigations and security analysis** (beyond self-serve **Diverg Open**) are booked via **company@divergsec.com**. **Diverg Auto** refers to the OpenClaw agent integration layer. The main services are:

| Service | Entry point | How to run |
|---|---|---|
| Flask API + Web Console | `api_server.py` | `python api_server.py` (dev, port 5000) |
| CLI Orchestrator | `orchestrator.py` | `python orchestrator.py --target <url> --scope <profile>` |
| Telegram Bot | `bot.py` | `python bot.py` (needs `TELEGRAM_BOT_TOKEN`) |

### Running the dev environment

1. Activate the venv: `source /workspace/venv/bin/activate`
2. Start the API server: `python api_server.py` — serves dashboard at `http://127.0.0.1:5000/dashboard/` and API at `/api/*`
3. The database (SQLite) is auto-created at `data/dashboard.db` on first run; no migrations needed.

### Testing

- **Unit tests**: `python -m pytest tests/ -v` — covers points ledger, Solana bundle signals, fact/accuracy checks, and Web3 drainer heuristics (`test_wallet_drainer_signals`).
- **Dashboard**: after a scan, **Executive 1-pager** downloads a standalone HTML summary (strict findings, compliance overview, threat intel hits, scan-diff verification line); open in a browser and **Print → Save as PDF** for a PDF. History rows also offer **1-pager** per saved scan.
- **Functional checks**: `python scripts/verify_functional.py` — cache, attack plan, skill execution, and accuracy tests. The "Real skill run" check may fail in sandboxed environments due to DNS restrictions; this is expected.
- **diverg-recon (Rust)**: `cd native/diverg-recon && cargo test` — CI also builds this crate on changes under `native/diverg-recon/`.
- **Security tests**: `python test_security.py` — requires the Flask server to be running on port 5000.
- **Linting**: `flake8 api_server.py --max-line-length=120` — some pre-existing style warnings exist in the codebase.

### Non-obvious caveats

- **No OpenAI key needed for basic testing**: The API server starts and serves the dashboard, auth, investigations (domain, blockchain), and history endpoints without `OPENAI_API_KEY`. Full scan endpoints (`/api/scan`, `/api/scan/stream`) require it for LLM-backed reasoning.
- **Investigations API**: `POST /api/investigation/blockchain` is a fast RPC snapshot (Helius for Solana; EVM balance/nonce plus optional recent mainnet txs when `ETHERSCAN_API_KEY` is set on the server) plus an **Arkham Intel** block (`ARKHAM_API_KEY` required on the server). `POST /api/investigation/solana-bundle` and `POST /api/investigation/blockchain-full` also require `ARKHAM_API_KEY`. `POST /api/investigation/blockchain-full` runs the full `blockchain_investigation` skill (crime-oriented report, flow graph, findings; server API keys only; ~1–2 minutes) — available via authenticated API and the extension **Full API** path, not the dashboard Investigation form. Dashboard deep link: `/dashboard/?page=investigation&inv_address=…` (fills quick lookup). Extension: address harvester → Dashboard or **Full API** (JWT in Options; `DIVERG_ALLOW_EXTENSION_CORS=1` when extension-origin CORS is required).
- **Recon port scan & DNS brute (optional Rust)**: Build the `diverg-recon` helper for async TCP probes and concurrent DNS without the GIL: `cd native/diverg-recon && cargo build --release`. The binary is picked up from `native/diverg-recon/target/release/diverg-recon`, or set `DIVERG_RECON_BIN` to its path, or install `diverg-recon` on `PATH`. If the binary is missing, `recon` falls back to **python-nmap** (needs the **nmap** binary, e.g. `apt install nmap`) and sequential **dnspython** for subdomain brute force.
- **Wappalyzer import issue**: The `Wappalyzer` pip package may have import issues on Python 3.12 (`cannot import name 'Wappalyzer' from 'wappalyzer'`). This affects the recon skill but doesn't block the server or other skills.
- **SSL errors in sandboxed environments**: Domain investigations may show SSL certificate verification errors due to missing CA certificates in the sandbox. This doesn't affect core functionality.
- **`.env` file (local dev only)**: Copy `.env.example` to `.env`. At minimum set `OPENAI_API_KEY` for full scan features. See `.env.example` for all optional keys. **`.env` is gitignored** — it exists only on your machine and is **not** deployed with the app. The **hosted dashboard / production API** does **not** read your laptop’s `.env`; it only sees variables you set on the **host** (e.g. Railway **Variables** / service environment). For shared users to get Arkham-backed investigations on prod, set **`ARKHAM_API_KEY`** (and any other required keys) there — never commit real keys to the repo.
- **The Flask server does NOT hot-reload by default**. Restart the process after code changes.
- **Web3 drainer signals** (`wallet_drainer_signals` via `client_surface`): heuristic pattern matches only — not proof of malicious intent. Third-party scripts on allowlisted hosts (wallet vendors plus the same CDN/domain fragments as `client_surface`’s `THIRD_PARTY_ALLOWLIST`) produce **no** drainer findings by design (noise reduction), so malicious code on those hosts is a **known blind spot** — pair with supply-chain review, subresource integrity, and lockfiles. Use for authorized assessments only.
