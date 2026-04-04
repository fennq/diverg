# Integrations

Our blockchain investigation pipeline is powered by key data and intelligence providers. Each integration adds a layer of depth—from on-chain state and token metadata to wallet attribution, flow mapping, and social linkage. Here’s what we use and why.

---

## Arkham

**What it is:** Arkham provides address intelligence and entity labeling across chains.

**Value:** We use the Arkham Intel API to attach **labels and entities** to wallet addresses—exchange deposits, known protocols, high-value wallets, and risk tags. That turns raw addresses into named actors (e.g. “Binance 1”, “Raydium LP”) and supports **attribution and risk scoring**.

**What it lets us do deeper:**  
- Identify whether a wallet is tied to a CEX, protocol, or known entity.  
- Cross-reference our target wallets against Arkham’s entity graph.  
- Improve report narratives with human-readable labels instead of bare addresses.  
- Flag high-risk or sanctioned entities when present in Arkham’s dataset.

*Requires `ARKHAM_API_KEY` on the server for `POST /api/investigation/blockchain`, `POST /api/investigation/solana-bundle`, `POST /api/investigation/blockchain-full`, and for the `blockchain_investigation` skill whenever Solscan or Etherscan keys are used. Request access at [Arkham Intel API](https://intel.arkm.com/api).*

---

## Solscan

**What it is:** Solscan is a Solana block explorer and data API for tokens and holders.

**Value:** We use Solscan’s API for **token holder counts**, **token metadata** (name, symbol, supply), and explorer links. It gives us a quick, reliable view of who holds a token and how concentrated ownership is—essential for assessing distribution and potential manipulation.

**What it lets us do deeper:**  
- See total holder count and top holders for any SPL token.  
- Pull metadata (name, symbol, decimals) for the token of interest.  
- Generate direct Solscan links in reports for manual verification.  
- Support “who holds this token” and “how concentrated” questions in investigations.

*Uses public Solscan API; rate limits may apply.*

---

## Helius

**What it is:** Helius is a Solana RPC and data platform offering Wallet API, DAS (Digital Asset Standard), and Enhanced Transactions.

**Value:** We use Helius for **wallet identity**, **funded-by** (who first funded a wallet), **balances** (tokens + USD for top assets), **parsed history and transfers**, **Enhanced Transactions** (human-readable type/source: SWAP, TRANSFER, NFT_SALE, etc.), and **DAS** (portfolio and single-asset metadata). One provider gives us both “who is this wallet” and “what did it do.”

**What it lets us do deeper:**  
- Resolve wallets to known entities (exchange, protocol, KOL, scammer) via the Wallet API.  
- Trace **funding source** (first SOL in)—critical for sybil detection and attribution.  
- Build a full **portfolio view** (tokens + NFTs) and **parsed tx history** without raw RPC parsing.  
- Filter and analyze by transaction type and source (e.g. Jupiter swaps, NFT sales).  
- Enrich token data with DAS metadata when we have a mint.

*Requires `HELIUS_API_KEY`. Get keys at [Helius Dashboard](https://dashboard.helius.dev).*

---

## FrontrunPro

**What it is:** FrontrunPro is a Solana-focused intelligence and “smart money” platform, with a public Address Finder and an optional paid API.

**Value:** We integrate **Address Finder** (no API key) to go from a **Twitter @handle or wallet fragment to a full Solana address**. Optionally, with the paid API we can pull linked wallets, KOL follow lists, and CA history for deeper network mapping.

**What it lets us do deeper:**  
- **Social → chain:** Take a Twitter handle (or partial address) and resolve it to a Solana wallet for cross-referencing with our wallet list and reports.  
- **Attribution:** Link public identities (e.g. promoters, team) to on-chain addresses.  
- With the paid API: map **wallet clusters** and **KOL/smart money** connections for richer network analysis.

*No-cost: use [Address Finder](https://www.frontrun.pro/address-finder) or `address_finder_url("@handle")` in code. Paid API: set `FRONTRUNPRO_API_KEY` and `FRONTRUNPRO_BASE_URL` in `.env`.*

---

## Bubblemaps

**What it is:** Bubblemaps provides visual token flow and cluster analysis on Solana—who holds what, how tokens moved, and how wallets cluster.

**Value:** We use Bubblemaps **via links in our reports** (no API in-pipeline) to **visualize flows and clusters** around a token or set of wallets. It answers “how did this token move?” and “do these wallets cluster?” in a way that’s hard to get from raw tables.

**What it lets us do deeper:**  
- **Flow visualization:** See token movement and concentration over time.  
- **Cluster detection:** Identify wallet clusters (e.g. same funder, same behavior).  
- **Narrative support:** Give reviewers a clear visual to back written findings.  
- **Top holders and distribution:** Complement Solscan/Helius holder data with a spatial/cluster view.

*Used as a linked resource from investigation reports; open Bubblemaps for the token or address from our report links.*

---

## Bags (optional)

**What it is:** Bags.fm token launch and fee APIs on Solana.

**Value:** With `BAGS_API_KEY`, the pipeline enriches a token mint with creators, lifetime fees, claim events, 7d/30d claim trends, pool keys (Meteora DBC / DAMM v2), **per-fee-claimer claim totals (claim-stats)** with **concentration analytics** (Herfindahl index, top1/top3/top5, creator vs non-creator split, distribution label), **reconciliation** of claim-stats vs sampled claim-events (detects partial pagination), optional **fee-share admin list** check for creator wallets, optional **full Bags pool listing** for ecosystem scans, **Dexscreener token-info order availability** for the mint, optional **token launch feed** scan (whether the mint appears among recent/active Bags launches), optional **pool config lookup** from fee-claimer vault addresses, and (with Helius) CEX-linked signals for wallets that appear in claim activity.

**What it lets us do deeper:**  
- Who launched the token and royalty/admin context.  
- How much fee revenue accumulated and who claimed it (amounts, timestamps, signatures).  
- **Fee distribution:** total claimed per fee sharer (wallet + social fields), plus concentration metrics (creator share, top1/top3/top5, Herfindahl index, `highly_concentrated` / `moderate` / `dispersed`).  
- **Cross-check:** claim-stats totals vs first-page claim-events to flag truncated samples.  
- **Admin scope:** whether the mint appears in `/fee-share/admin/list` for creator wallet(s) (optional; `BAGS_SECTION3_ADMIN_CHECK`, `BAGS_SECTION3_ADMIN_MAX_WALLETS`).  
- Where Bags-associated liquidity lives (DBC config, DBC pool, optional DAMM v2 pool), with **liquidity stage** (`dbc_only` vs `migrated_to_damm_v2`), **Solscan explorer links**, and a **mint consistency** check vs the requested mint.  
- Whether recent claim activity is accelerating or cooling (7d vs 30d).  
- Whether claim wallets map to exchange-labeled identities or exchange-funded origins (via Helius).  
- Optional: `GET /solana/bags/pools` when `BAGS_FETCH_POOLS_LIST=true` (can be large; use for migration/ecosystem analysis). Set `BAGS_POOLS_ONLY_MIGRATED=true` to filter migrated-to-DAMM pools only.
- **Section 4:** `GET /solana/dexscreener/order-availability` (on by default; disable with `BAGS_DEXSCREENER_AVAILABILITY_CHECK=false`). Optional `GET /token-launch/feed` when `BAGS_FETCH_LAUNCH_FEED=true` (stores a mint match summary; set `BAGS_FETCH_LAUNCH_FEED_RAW=true` to retain the full feed payload in fetched JSON). Optional `POST /token-launch/state/pool-config` when `BAGS_FEE_CLAIMER_VAULTS` is set to a comma-separated list of vault pubkeys.

---

## Summary

| Integration   | Primary value                          | Lets us go deeper on                          |
|---------------|----------------------------------------|-----------------------------------------------|
| **Arkham**    | Labels, entities, risk tags            | CEX/protocol attribution, risk scoring       |
| **Solscan**   | Holder counts, token metadata, links   | Distribution, concentration, verification     |
| **Helius**    | Identity, funded-by, balances, DAS, tx | Who is this wallet, funding, full history     |
| **FrontrunPro** | @handle → wallet, optional clusters  | Social→chain attribution, network mapping      |
| **Bubblemaps**  | Flow and cluster visuals              | Movement, clusters, narrative and reporting   |
| **Bags**      | Creators, fees, claims, claim-stats, pools, Dexscreener, optional feed/vault state | Launch attribution, fee distribution, profit-taking, CEX links, listings context |

Together, these integrations let us move from raw addresses and tx lists to **attribution**, **funding trails**, **social linkage**, and **visual flow analysis**—so we can go deeper on any Solana-focused investigation.
