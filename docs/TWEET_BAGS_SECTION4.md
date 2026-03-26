# Tweet drafts — Bags API Section 4/4 (Launch feed, Dexscreener, pool-config state)

Same voice as **Section 2** and **Section 3** tweets. Tag **@BagsApp** (adjust if your canonical handle differs). Add repo or `docs/INTEGRATIONS.md` link when you ship.

---

## Single post (copy-paste)

**Option A — full (good for long-form / thread opener)**

New integration: **@BagsApp** API — **Sec 4/4** (Launch feed, Dexscreener, state)

Built for on-chain investigations.

Access to:
- **Dexscreener order availability** — `GET /solana/dexscreener/order-availability`: can a token-info order be placed for this mint? (on by default in the pipeline)
- **Token launch feed** (optional) — `GET /token-launch/feed`: scan whether your mint appears among recent/active Bags launches + status/keys summary when matched (`BAGS_FETCH_LAUNCH_FEED`)
- **Pool config from vaults** (optional) — `POST /token-launch/state/pool-config`: map fee-claimer vault pubkeys → Meteora DBC pool config keys (`BAGS_FEE_CLAIMER_VAULTS`)

Diverg: `parse_dexscreener_order_availability`, `find_mint_in_token_launch_feed`, `parse_pool_config_by_vaults_response` + `blockchain_fetch` when `BAGS_API_KEY` is set.

---

## Single post (shorter — ~280 friendly)

**@BagsApp** API in Diverg — **Sec 4/4: Listings & state**

Dexscreener order availability per mint; optional launch-feed mint match; optional vault→DBC pool-config resolution.

Built for on-chain investigations — not dashboard candy.

---

## Thread (3 posts)

**1/**  
New: **@BagsApp** integration — **Section 4/4: Launch feed, Dexscreener, pool-config** — closing out the read-side stack in Diverg investigations.

**2/**  
We surface **Dexscreener order availability** for the token mint on every fetch (skippable via env). Optionally pull the **launch feed** and report whether the mint shows up — with a tight summary, not dumping the whole list.

**3/**  
Power path: **fee-claimer vaults** → first **Meteora DBC pool config** per vault when you set `BAGS_FEE_CLAIMER_VAULTS`.  
Docs: `docs/INTEGRATIONS.md`

---

## Optional CTA

Code: `investigation/bags_client.py` · `investigation/blockchain_fetch.py` · env: `BAGS_DEXSCREENER_AVAILABILITY_CHECK`, `BAGS_FETCH_LAUNCH_FEED`, `BAGS_FETCH_LAUNCH_FEED_RAW`, `BAGS_FEE_CLAIMER_VAULTS`
