# Investigation tooling

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Solana](https://img.shields.io/badge/Solana-Helius%20%2B%20RPC-9945FF?logo=solana&logoColor=white)](https://www.helius.dev/)

Optional **on-chain and API research** utilities used with Diverg investigations. This folder often contains **case-specific** or **gitignored** outputs (e.g. working PDFs, fetched JSON). **Do not commit** secrets, API keys, or private client data.

| Topic | Jump |
|--------|------|
| Product overview & Solana console API | [Root README](../README.md) |
| Chrome bundle UX | [diverg-extension](https://github.com/fennq/diverg-extension) |
| Generic wallet/token pipeline | [below](#generic-pipeline-any-investigation-not-just-synq) |
| Key Python modules | [below](#key-files) |

---

## Synq case workspace *(example / internal)*

> **Note:** The Synq materials described below are for a concrete investigation. Your tree may differ if this directory is used for other cases.

This folder may hold a working investigation file and fetched data (often gitignored).

### Finished artifacts *(when present)*

- **`SYNQ_Investigation_Report.pdf`** — Full report: executive summary, case summary, Diverg scan summary, on-chain wallet/token data, wallet register (Solscan / Arkham / Bubblemaps links), token of interest, breakdown, and assessment.
- **`SYNQ_Investigation_Report.md`** — Master markdown (source for the PDF).
- **`content/SYNQ_Security_Scan_Report.pdf`** — Diverg security scan of `app.synq.xyz` (referenced in the investigation).

Together, the investigation PDF + security scan PDF form the complete package for referral or further write-up.

### Running the tech

1. **Fetch on-chain data (wallets + token)**  
   From repo root:
   ```bash
   ./venv/bin/python scripts/run_synq_research.py
   ```
   - Uses public Solana RPC (`getBalance`, `getSignaturesForAddress`) — no key.
   - Uses Solscan for token holder total and metadata (when API allows).
   - **Helius (optional):** With `HELIUS_API_KEY` set, the pipeline fetches:
     - **Wallet API:** identity (known labels: exchange, protocol, KOL, scammer, etc.), funded-by (first SOL funder), balances (tokens + USD for top 10k).
     - **History & transfers:** parsed transaction history and token/SOL transfers.
     - **Enhanced Transactions:** parsed tx list with type/source (SWAP, TRANSFER, NFT_SALE, etc.).
     - **DAS:** `getAssetsByOwner` (wallet portfolio) and, for the token mint, `getAsset` (metadata).
     Set the key in the environment or in a `.env` file in the project root (do not commit `.env`):
     ```bash
     export HELIUS_API_KEY=your_helius_key
     # or add HELIUS_API_KEY=... to .env
     ./venv/bin/python scripts/run_synq_research.py
     ```
   - **Arkham (optional):** address intelligence (labels, entities). Request API access at [Arkham Intel API](https://intel.arkm.com/api), then set `ARKHAM_API_KEY` in the environment or `.env`:
     ```bash
     export ARKHAM_API_KEY=your_arkham_key
     ./venv/bin/python scripts/run_synq_research.py
     ```
   - **FrontrunPro (optional, no cost):** Without the paid API, use the public [Address Finder](https://www.frontrun.pro/address-finder) to resolve a Twitter @handle or wallet fragment to a full Solana address. From code: `from frontrunpro_client import address_finder_url; url = address_finder_url("@handle")` — open the URL in a browser or pass it to your pipeline. No API key needed.
   - **FrontrunPro (optional, paid):** Linked wallets, KOL follow list, CA history. $200+/month; contact [t.me/frontrunintern](https://t.me/frontrunintern) for key and `FRONTRUNPRO_BASE_URL`. Set both in `.env` to enable API enrichment.
   - **Bags (optional):** Token intelligence when `BAGS_API_KEY` is set:
    - **Section 1:** `GET /token-launch/creator/v3`, `GET /token-launch/lifetime-fees`, `GET /fee-share/token/claim-events`.
    - **Section 2:** `GET /solana/bags/pools/token-mint` (Meteora DBC + DAMM v2 pool keys for the token).
    - **Section 3:** `GET /token-launch/claim-stats` (per-fee-claimer totals, top1/top3/top5, Herfindahl index, distribution label, creator vs non-creator split); reconciliation vs sampled claim-events; optional `GET /fee-share/admin/list` for creator fee-share scope; optional `GET /solana/bags/pools` when `BAGS_FETCH_POOLS_LIST=true` (set `BAGS_POOLS_ONLY_MIGRATED=true` to filter); response includes whether the requested mint appears in that list.
    - Output includes both `*_raw` API payloads and normalized summaries:
      - `creators` (count, wallets, handles),
      - `lifetime_fees` (lamports + SOL),
      - `pool` + `pool_raw` (DBC config/pool keys, optional DAMM v2 pool; `liquidity_stage`, `pool_addresses_for_tracing`, Solscan `explorer_links`, `consistency_check` vs requested mint),
      - `claim_events` (events count, unique wallets, total claimed, creator-claim totals),
      - `claim_wallet_cex_connections` (claim wallets tagged as CEX identities and/or exchange-funded via Helius),
      - `claim_events_windows` (same summary metrics for `7d` and `30d` windows via time mode),
      - `claim_events_window_trend` (7d vs 30d ratios + `trend`: `accelerating`, `stable`, or `cooling`).
    Set key in `.env`:
    ```bash
    export BAGS_API_KEY=your_bags_key
    ./venv/bin/python scripts/run_synq_research.py
    ```
   - Writes `investigation/synq_data.json`.

2. **Update the investigation report with fetched data**  
   ```bash
   ./venv/bin/python scripts/update_investigation_report_from_data.py
   ```
   - Merges balances and token evidence from `synq_data.json` into `SYNQ_Investigation_Report.md`.

3. **Generate PDF**  
   ```bash
   ./venv/bin/python scripts/generate_synq_investigation_pdf.py
   ```
   - Output: `investigation/SYNQ_Investigation_Report.pdf`.

## Generic pipeline (any investigation, not just Synq)

The same on-chain fetch (RPC, Helius, Arkham, FrontrunPro, Bags when keys set, Solscan) is available for **any** case. Use the generic script with your own wallet list and optional token:

```bash
# Wallets only
./venv/bin/python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 ADDR3 --out investigation/my_case_data.json

# Wallets + token
./venv/bin/python scripts/run_blockchain_research.py --wallets ADDR1 ADDR2 --token TOKEN_MINT --out investigation/my_case_data.json

# From a config file (e.g. investigation/cases/next_case.json)
./venv/bin/python scripts/run_blockchain_research.py --config investigation/cases/next_case.json
```

Config JSON format: `{"wallets": ["addr1", "addr2"], "token": "optional_mint", "output": "optional/path.json"}`.  
The core logic lives in `investigation/blockchain_fetch.py`; `run_synq_research.py` is a thin wrapper that passes the Synq wallets and token and writes to `synq_data.json`.

## Manual research

- **Solscan / Arkham / Bubblemaps:** Open the links in Section 3 and 4 of `SYNQ_Investigation_Report.md` in a browser to inspect CEX labels, fund flows, clusters, and top holders.
- **Twitter / social:** Search each address + "synq" or "synq.xyz" and paste findings into the report tables.

## Key files

- `SYNQ_Investigation_Report.md` — Master investigation doc (police-style).
- `synq_data.json` — On-chain fetch output (balances, signatures, token holder count).
- `SYNQ_Investigation_Report.pdf` — Generated PDF.
- `solscan_client.py` — Solscan api-v2 client (token holders, metadata).
- `onchain_clients.py` — Solana RPC + Helius (Wallet API: identity, funded-by, balances; history, transfers; Enhanced Transactions; DAS getAssetsByOwner/getAsset).
- `arkham_client.py` — Arkham Intel API (address intelligence); requires `ARKHAM_API_KEY`.
- `frontrunpro_client.py` — FrontrunPro: **no-cost** `address_finder_url(query)` (Twitter @ or wallet fragment → Address Finder URL; no key). Optional paid API: set `FRONTRUNPRO_API_KEY` + `FRONTRUNPRO_BASE_URL` for linked wallets, KOL list, CA history.
- `bags_client.py` — Bags API client (Section 1): creators, lifetime fees, claim events for token intelligence. Requires `BAGS_API_KEY`.
- `blockchain_fetch.py` — Generic fetch: `run_blockchain_research(wallet_addresses, token_mint=..., output_path=...)`. Used by `run_synq_research.py` and `run_blockchain_research.py`.
- `solana_bundle.py` — Holder/cluster bundle snapshot logic (shared with **`POST /api/investigation/solana-bundle`** and the Chrome extension).
- `solana_bundle_signals.py` — Coordination heuristics; **CEX/mixer tiers** (`classify_cex_tier` / `classify_mixer_tier`: `none` | `weak` | `strong`). Structural “exchange” labels skip **DEX-shaped** fields (`decentralized`, `dex`, `amm`, liquidity-pool wording) so “Decentralized Exchange” is not scored as CEX. Parallel CEX and privacy/mixer clusters default to **high confidence** only when wallets share a tagged funder **and** first-fund time bucket or matching lamports; **loose** variants appear in `parallel_cex_funding_loose` / `privacy_mixer_funding_loose` for review without full score weight.

**Env (bundle / CEX-mixer):**

| Variable | Effect |
|----------|--------|
| `SOLANA_BUNDLE_CEX_STRICT=1` | `is_cex_identity` requires **strong** tier only. |
| `SOLANA_BUNDLE_MIXER_STRICT=1` | `is_mixer_privacy_identity` requires **strong** tier only. |
| `SOLANA_BUNDLE_FUNDER_ROOT_IDENTITY_MAX` | Cap extra Helius identity calls on 2-hop root funders (default 24). |

---

## License

Project code is under the [MIT License](../LICENSE). Generated investigation artifacts (PDFs, JSON, client notes) are yours to manage; keep confidential material out of git.
