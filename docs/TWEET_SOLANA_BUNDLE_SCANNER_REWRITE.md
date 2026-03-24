# Tweet drafts — Solana bundle scanner rewrite (Diverg extension)

Same voice as Bags tweets. Tag **@HeliusRPC** if relevant. Add extension link when public.

---

## Single post (copy-paste)

**Option A — Bags-style (recommended)**

New feature: **@HeliusRPC** — Solana token bundle scanner in Diverg

Built for on-chain investigations.

Access to:
- **Holder map** — `getTokenAccounts` (DAS, paginated): every real holder ranked by balance, not a 20-account stub
- **Funder identity** — `getSignaturesForAddress` + `/v0/transactions` batch parse: first native SOL inbound = true funder per wallet
- **Cluster analysis** — group holders by shared funder, filter out exchanges via `batch-identity`, surface coordinated wallets only
- **Verdict** — `CLEAN / WATCHLIST / SUSPICIOUS / BUNDLER` + risk score + % supply held by each suspicious cluster
- **Live progress** — status updates as each stage runs so you know it's actually scanning

Diverg: paste a mint → get a real bundle verdict in ~20s.

---

## Single post (shorter — ~280 friendly)

Rewrote Diverg's Solana bundle scanner.

Root cause of bad data: Helius DAS `getTokenAccounts` needs object params, not array — silent fail meant we were scanning 20 wallets max and calling it done.

Now mirrors Godmode exactly: paginated holders → oldest sig per wallet → batch-parsed first SOL funder → cluster → verdict.

Actually finds bundles now.

---

## Thread (3 posts)

**1/**  
Rebuilt the Solana token bundle scanner in Diverg.

Was giving clean verdicts on tokens Godmode flagged as bundled. Found the root cause. Fixed it.

**2/**  
The bug: `getTokenAccounts` (Helius DAS) requires **object params** in the JSON-RPC body — not the standard array params. We were wrapping it wrong, it silently fell back to `getTokenLargestAccounts`, which caps at **20 accounts**. We thought we were scanning 100 wallets. We weren't.

**3/**  
New flow: `getAsset` → `getTokenAccounts` paginated (up to 500 holders) → `getSignaturesForAddress` concurrent → `/v0/transactions` batch parse for first inbound SOL funder → `batch-identity` exchange filter → cluster → risk score.  
Same methodology as Godmode, same results.

---

## Optional CTA line

Code: `extension/solana_bundle.js` · Key fix: `dasRpc()` vs `rpc()` for DAS vs standard RPC methods
