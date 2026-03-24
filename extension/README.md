# Extension tech

Background worker and API auto-detect logic. Same code is kept in sync with the separate extension repo (popup, side panel, results UI live there). Backend runs from this repo; extension calls API at 127.0.0.1:5000 by default.

**Side panel tabs**

- **Site** — Auto-scan header/inline risks for the active tab (unchanged).
- **Solana** — Token mint + optional wallet; runs **in the extension** via `solana_bundle.js` (Helius RPC + Wallet API). Set your **Helius API key** under **Options** (stored in `chrome.storage.local`, sent only to Helius — no Python server). Heuristic: top holders + wallets sharing the same direct funder (Helius funded-by).
