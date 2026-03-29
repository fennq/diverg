# Investigation toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Python modules and scripts for **on-chain research** alongside Diverg web scans: Solana RPC, **Helius** (Wallet API, DAS, enhanced transactions), optional **Arkham**, **FrontrunPro**, **Bags**, and a unified **`blockchain_fetch`** pipeline. The **Chrome extension** and **`POST /api/investigation/solana-bundle`** reuse the same bundle methodology as **`solana_bundle.py`** here.

> **Note:** This folder may contain **case-specific** markdown/JSON/PDF outputs. Add large or sensitive artifacts to `.gitignore` if they should not ship in git. The sections below include an **example** workflow (Synq); the **generic** pipeline applies to any wallet list or token.

---

## Generic pipeline (any case)

Core entrypoint: **`blockchain_fetch.py`** → `run_blockchain_research(...)`, also used by thin wrappers like `run_blockchain_research.py`.

```bash
# Wallets only
./venv/bin/python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 ADDR3 --out investigation/my_case_data.json

# Wallets + token mint
./venv/bin/python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 --token TOKEN_MINT --out investigation/my_case_data.json

# From JSON config
./venv/bin/python scripts/run_blockchain_research.py --config investigation/cases/next_case.json
```

Config format: `{"wallets": ["..."], "token": "optional_mint", "output": "optional/path.json"}`.

### Key modules

| File | Role |
|------|------|
| `blockchain_fetch.py` | Orchestrates RPC + optional Helius, Arkham, FrontrunPro, Bags |
| `onchain_clients.py` | Solana RPC + Helius helpers |
| `solana_bundle.py` | SPL bundle snapshot (holders, clusters, coordination score)—**parity with extension + API** |
| `solscan_client.py` | Solscan API v2 (holders, metadata) |
| `arkham_client.py` | Arkham Intel API (`ARKHAM_API_KEY`) |
| `frontrunpro_client.py` | Address finder URL helper; optional paid API |
| `bags_client.py` | Bags API (`BAGS_API_KEY`) — creators, fees, pools, claim stats |

Set keys via **environment** or **`.env`** in the project root (never commit secrets).

---

## Example: Synq case workflow

*(Illustrative only—paths refer to files that may be gitignored locally.)*

1. **Fetch on-chain data** — from repo root:
   ```bash
   ./venv/bin/python scripts/run_synq_research.py
   ```
   - Public Solana RPC by default; **Helius** enriches identity, funded-by, history, DAS, etc. when `HELIUS_API_KEY` is set.
   - Optional: `ARKHAM_API_KEY`, FrontrunPro, **`BAGS_API_KEY`** (see Bags sections in `bags_client.py` / `docs/INTEGRATIONS.md`).
   - Writes e.g. `investigation/synq_data.json`.

2. **Merge into report** — `scripts/update_investigation_report_from_data.py`

3. **PDF** — `scripts/generate_synq_investigation_pdf.py`

**Deliverables** (when present): investigation PDF/MD, Diverg scan PDF cross-reference, wallet register links (Solscan / Arkham / Bubblemaps as applicable).

---

## Manual research tips

- Use explorer links from your report for CEX labels, flows, and holder clusters.
- Cross-check social mentions for addresses and project names; record sources in the case file.

---

## Bags API (optional)

When `BAGS_API_KEY` is set, the pipeline can include creators, lifetime fees, Dexscreener order availability, pool / Meteora DBC resolution, claim stats, launch feed matching, and related summaries. See **`docs/INTEGRATIONS.md`** and **`bags_client.py`** for endpoints and env flags (`BAGS_FETCH_LAUNCH_FEED`, `BAGS_FEE_CLAIMER_VAULTS`, etc.).

---

## License

MIT — see [`LICENSE`](../LICENSE) in the repository root.
