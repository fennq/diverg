# Tweet drafts — Bags API Section 3/4 (Fee analytics & claim-stats)

Same layout as **Section 2** tweets. Tag **@BagsApp** if that’s your canonical handle. Add repo or `docs/INTEGRATIONS.md` when you ship.

---

## Single post (copy-paste)

**Option A — full**

New integration: **@BagsApp** API — **Sec 3/4** (Fee analytics & claim-stats)

Built for on-chain investigations.

Access to:
- **Per-claimer totals** — `GET /token-launch/claim-stats`: wallet + social fields, SOL claimed per fee sharer  
- **Concentration** — top1 / top3 / top5 share, Herfindahl-style fee index, creator vs non-creator split, `highly_concentrated` / `moderate` / `dispersed`  
- **Reconciliation** — claim-stats vs sampled claim-events so truncated “first page” data doesn’t fake a narrative  
- **Fee-share admin scope** (optional) — `/fee-share/admin/list` for creator wallets: is this mint in their admin set?  

Diverg: `parse_token_claim_stats` + `reconcile_claim_stats_with_events` + optional `section3_fee_share_admin` when `BAGS_API_KEY` is set.

---

## Single post (shorter — ~280 friendly)

**@BagsApp** API in Diverg — **Sec 3/4: Fee analytics**

Claim-stats per sharer, concentration (HHI + top-N + distribution label), reconcile vs claim-events, optional fee-share admin check for creators.

Built for on-chain investigations — not vanity metrics.

---

## Thread (3 posts)

**1/**  
New: **@BagsApp** integration — **Section 3/4: Fee analytics & claim-stats** — in the Diverg investigation stack.

**2/**  
We pull **claim-stats** into structured reports: per-wallet totals, **top claimer**, creator vs non-creator split, and a **distribution** label so “who captured the fees” is obvious in one glance.

**3/**  
We also **reconcile** claim-stats against the claim-events sample (pagination skew), and optionally hit **fee-share admin list** for creator wallets (`BAGS_SECTION3_ADMIN_CHECK`).  
Docs: `docs/INTEGRATIONS.md`

---

## Optional CTA

Code: `investigation/bags_client.py` · `investigation/blockchain_fetch.py` · env: `BAGS_SECTION3_ADMIN_CHECK`, `BAGS_SECTION3_ADMIN_MAX_WALLETS`
