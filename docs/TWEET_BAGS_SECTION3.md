# Tweet drafts — Bags API Section 3 (Diverg investigation pipeline)

Use one thread or a single post. Replace `[repo]` with your GitHub link if you publish.

---

## Single post (technical audience)

**Option A — short**  
We upgraded our **Bags.fm** integration (Section 3): per-fee-claimer totals now ship with **concentration analytics** (top1/top3/top5, Herfindahl index, creator vs non-creator split), **claim-stats ↔ claim-events reconciliation** (catch truncated samples), and optional **fee-share admin list** checks for creator wallets. Built for on-chain investigations, not vibes. `[repo]`

**Option B — bullets**  
Shipping a deeper **@bags_fm** Section 3 in Diverg:

- Claim-stats: distribution label + Herfindahl + top-N concentration  
- Reconcile against claim-events so “first page” doesn’t lie  
- Optional `/fee-share/admin/list` pass for creator wallets  

Solana token intel that actually holds up in a report.

---

## Thread (3 posts)

**1/**  
We just leveled up **Bags API Section 3** in the Diverg investigation pipeline.

**2/**  
New: **per-claimer fee distribution** with HHI-style concentration, top1/top3/top5, creator vs non-creator split, plus a plain-language **distribution** tag (`highly_concentrated` / `moderate` / `dispersed`).

**3/**  
Also: **cross-check claim-stats vs claim-events** so pagination skew is visible, and optional **fee-share admin scope** for creator wallets (env-tunable).  
Docs: `docs/INTEGRATIONS.md` — `BAGS_SECTION3_ADMIN_CHECK`, `BAGS_SECTION3_ADMIN_MAX_WALLETS`.
