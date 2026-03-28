# Tweet drafts — Bags API Section 2/4 (Liquidity & pools)

Same voice as Section 3 tweets. Tag **@BagsApp** (adjust if your canonical handle differs). Add repo or `docs/INTEGRATIONS.md` link when you ship.

---

## Single post (copy-paste)

**Option A — full (good for long-form / thread opener)**  

New integration: **@BagsApp** API — **Sec 2/4** (Liquidity & pools)

Built for on-chain investigations.

Access to:
- **Pool-by-mint** — Meteora DBC config + pool keys, optional DAMM v2 after migration  
- **Liquidity stage** — `dbc_only` vs `migrated_to_damm_v2` at a glance  
- **One-click Solscan links** for every pool/config account  
- **Mint consistency check** — API mint vs the mint you asked for  

Diverg pipeline: `GET /solana/bags/pools/token-mint` → normalized `pool` object in `investigation/blockchain_fetch` when `BAGS_API_KEY` is set.

---

## Single post (shorter — ~280 friendly)

**@BagsApp** API in Diverg — **Sec 2/4: Liquidity & pools**

Pool-by-mint (Meteora DBC + DAMM v2 keys), liquidity stage (`dbc_only` / `migrated_to_damm_v2`), Solscan links on every account, mint consistency vs request.

Built for on-chain investigations — not dashboard candy.

---

## Thread (3 posts)

**1/**  
New: **@BagsApp** integration — **Section 2/4: Liquidity & pools** — in the Diverg investigation stack.

**2/**  
We resolve **pool-by-mint**: Meteora **DBC config + pool** keys, and **DAMM v2** when the token has migrated. You get a single **liquidity stage** flag so reports don’t hand-wave “where liquidity lives.”

**3/**  
Every relevant account gets a **Solscan** URL; we also run a **mint consistency** check (API `tokenMint` vs the mint you passed). Wire: `bags_client.parse_bags_pool` + `blockchain_fetch` token fetch with `BAGS_API_KEY`.

---

## Optional CTA line

Docs: `docs/INTEGRATIONS.md` · Code: `investigation/bags_client.py` (`parse_bags_pool`)
