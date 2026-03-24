# Tweet drafts — Solana bundle scanner rewrite (Diverg extension)

Same voice as Bags tweets. Tag **@HeliusRPC** if relevant. Add extension link when public.

---

## Single post (copy-paste)

**Option A — full**

Rewrote the Solana token bundle scanner in Diverg from scratch.

The old version was throwing garbage — turns out `getTokenAccounts` (Helius DAS) takes **object params**, not array params. Silent fail meant we were only ever scanning 20 wallets and calling it a full analysis.

Fixed flow now mirrors Godmode:

- **`getAsset`** → token name / symbol / supply / decimals  
- **`getTokenAccounts`** (DAS, paginated) → real top holders, not a 20-account stub  
- **`getSignaturesForAddress`** concurrent per holder → oldest tx per wallet  
- **`/v0/transactions`** batch parse → first native SOL inbound = true funder identity  
- **`batch-identity`** → exchange filter on funders  
- Cluster by funder → `CLEAN / WATCHLIST / SUSPICIOUS / BUNDLER` + risk score  

Live status updates in the popup so you can see it's actually working.

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
