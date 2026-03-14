# Blockchain investigation — Launchpads like liquid.af

Diverg acts as an **investigation scanner** for potential crime on the blockchain, especially for **launchpad** and token-creation platforms (e.g. **liquid.af**). This runbook describes the platform, how Diverg adapts, what it detects, and the **four enhancement pillars**: sniper across launches, LP removal, fee vs on-chain, and multi-chain.

---

## Crypto site type detection (any scan)

On **any** website scan, Diverg infers whether the target is crypto-related and **what type** (crypto relation). This drives which skills run and how findings are interpreted.

| Relation       | How detected (URL + page/objective) | Skills / crime focus |
|----------------|--------------------------------------|----------------------|
| **launchpad**  | liquid.af, pump.fun, launchpad, token launch, bonding curve | blockchain_investigation, sniper/rug/LP/fees |
| **exchange**   | binance, coinbase, exchange, KYC, withdraw, orderbook | payment_financial, high_value_flaws, KYC/withdrawal/insider |
| **dex**        | raydium, uniswap, swap, liquidity, AMM | payment_financial, race_condition, front-run/slippage |
| **wallet**     | phantom, metamask, connect wallet, sign message | crypto_security, client_surface, key/seed exposure |
| **defi**       | aave, compound, lending, staking, yield, oracle | logic_abuse, payment_financial, oracle/rate abuse |
| **nft**        | opensea, blur, nft, marketplace, royalty | payment_financial, high_value_flaws, royalty/creator abuse |
| **bridge**     | bridge, wormhole, layerzero, cross-chain | payment_financial, crypto_security, withdrawal/flow |
| **crypto-general** | crypto, solana, ethereum, web3 (unspecified) | crypto_security, payment_financial, client_surface |

- **URL and objective** are used first; then **discovery text** (technologies, endpoints, findings) refines or adds the type.
- The **primary** relation is passed into `blockchain_investigation` when that skill runs, and is included in the **crime report** and **analysis context** so findings and potential crime are interpreted for that type (e.g. launchpad → sniper/rug; exchange → KYC/withdrawal).

---

## What is liquid.af (and similar platforms)

- **liquid.af** is a platform for viewing and creating coins/tokens, with a “Create” option and coin listings (prices, 24h change). It fits the **launchpad** pattern: users can launch new tokens; the platform may take fees, host liquidity, or run infrastructure that can be abused.
- **Similar platforms**: Pump.fun, Raydium launchpads (e.g. Bonk.fun, LetsBonk), Meteora, and other “fair launch” or bonding-curve launchpads. Diverg treats these as **launchpad** when the target URL or content matches.

---

## How Diverg adapts to the platform

1. **Profile detection**  
   When the target URL contains `liquid.af`, `pump.fun`, `launchpad`, `raydium`, `bonk.fun`, `meteora`, etc., or the objective contains “investigate”, “launchpad”, “sniper”, “rug”, “blockchain”, “crime”, Diverg infers **blockchain-investigation** and runs **blockchain_investigation** plus other crypto-relevant skills.

2. **Platform type**  
   The skill classifies the site as **launchpad** | **exchange** | **unknown** and tailors checks accordingly.

3. **Chain**  
   **Solana** (default): Solscan Pro API for transfers, token holders, defi activities.  
   **Ethereum**: Etherscan API for token transfers (ERC-20); same sniper/heuristic logic where applicable.

4. **Data sources**  
   - **Web:** Fee mentions, token-like addresses, program IDs, sniper/rug wording.  
   - **Solscan:** Account transfers, **token/transfer** (earliest-first for sniper), **account/defi/activities** (REMOVE_LIQ), token holders, **token/meta** (mint/freeze authority), **account/balance_change** (outflows).  
   - **Etherscan:** account tokentx for token contract (Ethereum).  
   - **Arkham:** Single-address label (legacy), **Intel API** (api.arkm.com): **batch address labels**, **counterparties** per address, optional **flow** (USD over time).

---

## Utilising Arkham and Solscan for crime investigation

We use both platforms to maximise **attribution**, **money flow**, and **on-chain risk signals**.

### Solscan (Solana)

| Use | Endpoint / data | Crime-investigation value |
|-----|------------------|---------------------------|
| **Sniper across launches** | `token/transfer` per token, sort asc | Same wallet buying early on 3+ tokens → sniper alert. |
| **LP removal** | `account/defi/activities` with `ACTIVITY_TOKEN_REMOVE_LIQ` | Deployer pulling liquidity → rug signal. |
| **Token authority risk** | `token/meta` → mint_authority, freeze_authority | Active mint = unlimited supply; active freeze = honeypot (can block sells). |
| **Deployer outflows** | `account/balance_change` with `flow=out` | Many outflows → possible dump/cash-out; correlate with token sells. |
| **Holder concentration** | `token/holders` | Top 10 ≥40% → rug/coordinated dump risk. |
| **Serial launcher** | `account/transfer` for deployer | Touches 5+ tokens → repeat launcher / rug history. |
| **Fee comparison** | Stated fee from scrape vs fee in token transfers | Mismatch → extractive or undisclosed fee. |

### Arkham

| Use | API | Crime-investigation value |
|-----|-----|---------------------------|
| **Single label** | Legacy `api.arkhamintelligence.com` (deployer) | Who is this wallet? |
| **Batch labels** | Intel API `POST /intelligence/address/batch` | Label **deployer + sniper wallets + top holders** in one call; fill `wallet_labels` for all. |
| **Counterparties** | Intel API `GET /counterparties/address/{address}` | **Who the deployer transacts with** (CEX, entities, OTC); reveals off-ramp and linked parties. |
| **Flow** | Intel API `GET /flow/address/{address}` | Historical USD in/out; optional for cash-out timeline. |

### How it ties together

1. **Solscan** finds the **what**: sniper pattern, LP pull, mint/freeze risk, outflows, concentration.  
2. **Arkham** adds the **who**: labels for deployer, sniper(s), top holders; counterparties show CEX or linked entities.  
3. Together: “This deployer has REMOVE_LIQ and many outflows (Solscan); they send to Binance and Entity X (Arkham counterparties).”

**Env:** `SOLSCAN_PRO_API_KEY` for Solscan. `ARKHAM_API_KEY` for both legacy label and Intel API (batch, counterparties); Intel uses `api.arkm.com` with header `API-Key`.

---

## Data accuracy: what is live vs skipped (100% truthful)

| Env var | When set | When missing |
|--------|----------|----------------|
| **SOLSCAN_PRO_API_KEY** (Solana) or **ETHERSCAN_API_KEY** (Ethereum) | On-chain transfers, sniper, LP, deployer, flow graph, and flow diagram are **live** (from API). | On-chain branch is **skipped**. No real addresses, no flow graph, no diagram. Report states "On-chain: skipped (no API key)". We never show placeholder addresses or dates as findings. |
| **ARKHAM_API_KEY** | Wallet labels and counterparties (CEX, mixer, OTC) are **live**. | Counterparties and labels are empty; nodes in flow show addresses only. |

- Flow diagram is **only** generated when `on_chain_used` is true (i.e. an API key was set and data returned). Tweet cards or boards that show an example flow must be labeled "Example (not live data)" and "Real addresses and dates require SOLSCAN_PRO_API_KEY + ARKHAM_API_KEY".
- Scan/attack summary includes a **Data** line: e.g. `Data: Blockchain: live | Entity: DDG | OSINT: live | Web: live` so the operator sees at a glance what is real.

---

## What we detect (four pillars)

### 1. Sniper across launches

- **Pattern:** Same wallet(s) buying in the **early window** (first blocks or first N transfers) across **multiple** tokens on the platform.
- **How:**  
  - **Solana:** For up to 5 discovered (or provided) token mints, we call Solscan **token/transfer** with `sort_order=asc` to get earliest transfers. We aggregate “buyer” (to_address / to) per token, then run the sniper heuristic: if one wallet appears in the early window for **3+ tokens**, we flag **sniper alert** and add a High finding.  
  - **Ethereum:** Same idea using Etherscan **tokentx** for each token contract (sort asc by block), aggregate by `to`, then same heuristic.
- **Why it matters:** Platform or insiders running a sniper that buys every launch before retail → unfair advantage, potential market manipulation.

### 2. LP removal (rug pull)

- **Pattern:** Liquidity removed or drained after launch (no lock/burn); deployer or pool wallet has **remove-liquidity** activity.
- **How:**  
  - **Solana:** For the **deployer address** we call Solscan **account/defi/activities** with `activity_type=ACTIVITY_TOKEN_REMOVE_LIQ`. If any activities are returned, we add a **liquidity alert** and a High finding: “Deployer has remove-liquidity (LP pull) activity [RUG RISK]”.  
  - We also keep **holder concentration** (top 10 ≥40% supply) as a rug-risk signal.  
- **Ethereum:** No single “defi activities” endpoint; we use normal tx list for deployer; LP detection on L2/AMM would require chain-specific endpoints (future).
- **Why it matters:** Classic rug: launch, attract buys, then pull LP so the token collapses.

### 3. Fee vs on-chain

- **Pattern:** Stated fee (from site) **vs** fee observed on-chain; mismatch or undisclosed fee.
- **How:**  
  - We **extract stated fee %** from scraped text (e.g. “5% fee”, “100 bps”) and store it in `fee_comparison.stated_pct`.  
  - We try to get **on-chain fee** from Solscan token transfers (fields `fee_pct`, `fee_percent`, or `fee`). If the API returns a fee, we set `fee_comparison.on_chain_pct`.  
  - If both are present and differ by more than 0.5%, we add a Medium finding: “Stated fee vs on-chain fee mismatch [REVIEW]”.  
- **Why it matters:** Users may be charged different than advertised; or fee not applied consistently.

### 4. Multi-chain

- **Pattern:** Same investigation logic on **Solana** and **Ethereum** (and extensible to more chains).
- **How:**  
  - **`chain` parameter:** `run(target_url, ..., chain="solana" | "ethereum")`. Default is `solana`.  
  - **Solana:** SOLSCAN_PRO_API_KEY → token/transfer, account/transfer, account/defi/activities, token/holders.  
  - **Ethereum:** ETHERSCAN_API_KEY → account tokentx (per token contract), txlist for deployer. Sniper aggregation uses ERC-20 transfer “to”; no defi-activities REMOVE_LIQ on vanilla Etherscan.  
- **Why it matters:** Launchpads and token platforms exist on multiple chains; one runbook and one skill cover both.

---

## Other detections (unchanged)

- **Deployer / serial launcher:** Deployer touches 5+ tokens (account transfers) → “possible serial launcher”.  
- **Arkham labels:** Deployer wallet labeled for entity attribution.  
- **Concentrated holders:** Top 10 holders ≥40% supply → rug/coordinated dump risk.  
- **Page mentions:** Sniper/first-block/insider, liquidity pull/rug, fee/tax wording.

---

## Risk score and crime report (crime-identifier output)

- **Risk score (0–100):** Aggregated from findings and alerts (High/Medium/Low severity, LP remove, sniper, concentration, counterparties). Use to rank targets or alert when above a threshold.
- **Crime report:** Structured object with `summary`, `risk_score`, `deployer_section`, `tokens_section`, `findings_with_evidence`, `flow_highlights`, `linked_wallets`. Export as JSON (in the skill output) or build Markdown for threads/compliance.
- **Linked wallets:** Deployer’s Arkham counterparties (address + label, source `counterparty`) plus labeled holders/snipers (source `holder`). Surfaces CEX off-ramp and related addresses in one list.

See `content/crime-identifier-strategy.md` for how this compares to manual investigators and the roadmap.

## Post-rug one-shot mode

When you have a deployer or token address but no URL, run with a placeholder URL and only on-chain data:

- `target_url`: `""` or `"post-rug"` (or any string starting with `post-rug`)
- `deployer_address`: the suspected deployer wallet
- `token_addresses`: optional list of token mints/contracts

The skill uses `https://post-rug.local` as target, skips web scrape, and runs full on-chain pipeline (transfers, LP remove, outflows, Arkham labels and counterparties, risk score, crime report). Use for “this token just rugged” — get a first-draft report in one run.

---

## How to run an investigation

### Prerequisites

- **Solana:** **SOLSCAN_PRO_API_KEY** (required for on-chain sniper, LP-remove, holder concentration, fee comparison).  
- **Ethereum:** **ETHERSCAN_API_KEY** (required for on-chain sniper and token transfers).  
- **ARKHAM_API_KEY** (optional): wallet/entity labels (Solana deployer).

### In Telegram

- Target: `https://liquid.af` (or any launchpad URL).  
- Objective examples:  
  - “Investigate liquid.af for potential crime”  
  - “Full investigation of this launchpad — sniper, rug, fees”  
  - “Blockchain investigation — sniper and liquidity pull”

For **Ethereum** launchpads, pass **chain=ethereum** in context or via the run_blockchain_investigation tool so the skill uses Etherscan.

### Optional parameters

- **deployer_address:** Enables serial-launcher check, **LP-remove check** (Solscan defi activities), and Arkham label.  
- **token_addresses:** Improves sniper (per-token early transfers) and holder-concentration checks.  
- **chain:** `solana` (default) or `ethereum`.

### Without API keys

- Web recon still runs: platform type, fee mentions, sniper/rug mentions, and a finding that on-chain investigation was skipped (set the appropriate API key for your chain).

---

## Investigation coverage: what we have vs full Diverg-style depth

After **two scans on liquid.af** (or any launchpad), Diverg currently provides:

| We have | Purpose |
|--------|--------|
| **Sniper, LP, fee, deployer, risk score, crime report** | Core crime signals and structured export. |
| **Linked wallets + counterparties** | Who deployer transacts with (CEX, entities). |
| **Flow graph (nodes + edges)** | Addresses and transfers with amount/date; feeds the diagram. |
| **Diverg flow diagram** | Auto-generated HTML: primary (red), counterparty (green), wallet (blue), edges with amount + date. |

To get **full coverage** comparable to a deep investigation, consider adding:

| Gap | How to close it |
|-----|------------------|
| **Deeper transfer history** | More pages of token/transfer and account/transfer (currently ~20–30 per token/deployer); optional “flow_trace” mode that pulls more hops. |
| **Mixer / off-ramp tagging** | Tag known mixer or casino/CEX addresses (e.g. Tornado, ChipMixer) in flow_graph so the diagram can show “Bitcoin mixer” / “Casino deposit” style annotations. |
| **Multi-hop tracing** | Follow counterparty addresses for their outflows (2–3 hops) so the diagram shows full path to mixer/off-ramp. |
| **Entity labels everywhere** | Rely on Arkham (and optional TRM/Chainalysis) so every node in the diagram has a human-readable label. |

Running **blockchain_investigation** plus **entity_reputation** and **osint** on liquid.af gives strong coverage for launchpad risk (sniper, rug, fees, deployer, labels). For a **full money-flow narrative** (theft → mixers → casinos), add the above extensions or run multiple passes with different deployer/counterparty seeds.

---

## Flow diagram (ZachXBT-style)

When **blockchain_investigation** runs with Solscan/Arkham (or Etherscan), it now builds a **flow graph** from token and account transfers:

- **Nodes:** Addresses with labels (from Arkham/counterparty) and type: **primary** (deployer), **counterparty**, **wallet**.
- **Edges:** Transfers with **amount**, **unit** (SOL/ETH/TOKEN), **date**, and **count** (number of transfers between same from/to).

After a **full scan** or **attack** that includes blockchain_investigation, Diverg:

1. Renders a **Diverg HTML diagram**: directed graph, primary node with red ring and “Primary / Deployer” annotation, counterparties with green ring, wallets with blue ring, edges labeled with amount and date.
2. Saves it under `results/` as `{timestamp}_{target}_flow_diagram.html` and sends it as a document in Telegram.

You can also generate the diagram from any saved crime report that contains `flow_graph` by calling `render_flow_diagram_html(flow_graph, title=..., output_path=...)` from `skills/blockchain_flow_diagram.py`.

---

## Summary table

| Area                | What we detect / do |
|---------------------|----------------------|
| **Sniper across launches** | Per-token early transfers (Solscan token/transfer or Etherscan tokentx); same wallet in 3+ tokens → sniper alert. |
| **LP removal**      | Solscan account/defi/activities ACTIVITY_TOKEN_REMOVE_LIQ for deployer; holder concentration ≥40%. |
| **Fee vs on-chain** | Stated % from scrape vs on-chain fee from transfers; mismatch → finding. |
| **Multi-chain**     | `chain=solana` (Solscan) or `chain=ethereum` (Etherscan); same sniper/heuristic pattern. |
| **Deployer**        | Many tokens per deployer; Arkham label. |
| **Intel**           | Solscan: transfers, holders, defi activities. Arkham: wallet labels. |
| **Flow diagram**    | Nodes (primary/counterparty/wallet) and edges (amount, unit, date); Diverg HTML auto-generated after scan/attack. |

Diverg **adapts to the platform** and **chain**, and focuses the investigation on **potential crime**: sniper across launches, LP pull, fee extraction vs on-chain, and deployer/wallet intel using Solscan, Etherscan, and (optionally) Arkham.
