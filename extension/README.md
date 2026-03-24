# Extension tech

Background worker and API auto-detect logic. **Canonical Chrome UX** (side panel tabs, Solana bundle, options) is maintained in **[github.com/fennq/diverg-extension](https://github.com/fennq/diverg-extension)** — copy `sidepanel.*`, `solana_bundle.js`, `options.*`, `icons/` from there when syncing. This folder mirrors that for the Sectester monorepo. Optional API: `127.0.0.1:5000` for full scans when `api_server.py` runs.

**Popup (click extension icon)**

- **Security** — URL + Run Security Scan (same as [diverg-extension](https://github.com/fennq/diverg-extension)).
- **Solana** — Token mint + optional wallet; `solana_bundle.js` + Helius key in **Options** (browser-only).

**Side panel** — Site scan summary for the active tab only; Solana lives in the **popup → Solana** tab.
