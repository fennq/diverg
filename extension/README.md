# Extension tech

Background worker and API auto-detect logic. **Canonical Chrome UX** (side panel tabs, Solana bundle, options) is maintained in **[github.com/fennq/diverg-extension](https://github.com/fennq/diverg-extension)** — copy `sidepanel.*`, `solana_bundle.js`, `options.*`, `icons/` from there when syncing. This folder mirrors that for the Sectester monorepo. Optional API: `127.0.0.1:5000` for full scans when `api_server.py` runs.

**Side panel tabs**

- **Site** — Auto-scan header/inline risks for the active tab (unchanged).
- **Solana** — Token mint + optional wallet; runs **in the extension** via `solana_bundle.js` (Helius RPC + Wallet API). Set your **Helius API key** under **Options** (stored in `chrome.storage.local`, sent only to Helius — no Python server). Heuristic: top holders + wallets sharing the same direct funder (Helius funded-by).
