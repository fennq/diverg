# Tweet — Cross-chain investigation (Solana + EVM hints)

**Diagram (SVG):** [`docs/diagrams/cross-chain-investigation.svg`](diagrams/cross-chain-investigation.svg)

---

## Post (medium, same structure as Phase 3 / 4 ship notes)

**Cross-chain investigation** is live in Diverg.

We surface **where the same asset may exist on other chains** and give you **direct explorer links** — without pretending a CSV row proves wrongdoing:

- **Wormhole-style token list** (cached registry) + optional **CoinGecko** contract metadata (with disk TTL cache)
- **Per-candidate** `foreign_explorer_url` (Solscan, Etherscan family, etc.) and **confidence tiers** (registry vs third-party metadata)
- **`summarize_cross_chain_payload`** so dashboards get one stable shape whether the payload came from the **Solana bundle** or the **blockchain investigation** skill
- **Solana bundle:** **bridge / mixer–adjacent** funding-cluster hints (focus-scoped where it matters) merged into coordination signals + API `risk_signals`
- **Multi-chain EVM** token context in **blockchain_investigation** alongside Solana mints

Investigative hints only — **verify on official bridges and destination-chain explorers.** Authorized use.

---

## Short (~260 chars)

Cross-chain hints in Diverg: **Wormhole list + optional CoinGecko**, **explorer links per candidate**, stable **`cross_chain.summary`**, **bridge/mixer bundle signals** on Solana, **EVM + Sol** in blockchain investigation. Hints only — verify on-chain. @DivergSec

---

## Alt text (SVG)

Dark flowchart: Solana mint and EVM contract feed Wormhole registry and optional CoinGecko into cross_chain_hints; outputs branch to blockchain_investigation and Solana bundle API with bridge/mixer notes; footer states hints are not proof of misconduct.

---

## Thread (3 posts) — optional

**1/** Tokens don’t stop at one chain. Diverg now pulls **cross-chain mapping hints** from a **cached Wormhole-style list** and optional **CoinGecko** metadata — with **explorer URLs** on every candidate so you can verify fast.

**2/** **Solana bundle** responses include **`cross_chain` + `summary`**. We also bump coordination context when **bridge program IDs** and **mixer-tagged funding** show up in the sample — scoped to the **holder cluster** where possible.

**3/** **Blockchain investigation** attaches the same style of **`cross_chain`** payload (and **summary**) to the structured report, including **multi-chain EVM** when you’re not on Solana. Still **hints**: corroborate with primary bridge docs and explorers.
