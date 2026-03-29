# Diverg — Chrome extension (monorepo mirror)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Canonical repo](https://img.shields.io/badge/canonical-diverg--extension-4285F4?logo=googlechrome&logoColor=white)](https://github.com/fennq/diverg-extension)

This directory is a **mirror** of extension logic kept in sync with the main **[diverg-extension](https://github.com/fennq/diverg-extension)** repository. **Shippable Chrome UX** (side panel, popup, **Solana bundle**, options, icons) is maintained there—copy updates **from** diverg-extension **into** this folder when syncing the monorepo.

---

## What the extension does

| Mode | Behavior |
|------|----------|
| **Quick scan** | In-browser checks (headers, page signals) without a backend |
| **Full scan** | Calls **`api_server.py`** on `http://127.0.0.1:5000` (or your configured base URL) for the full Diverg pipeline |
| **Solana — token bundle** | **Popup**: enter SPL **token mint**, optional **wallet**, run **Analyze bundle** — holder map, same-funder **cluster** analysis, **coordination / risk score** (methodology aligned with **`POST /api/investigation/solana-bundle`**). Requires a **[Helius](https://www.helius.dev/)** API key in **Options** |
| **Simulate** | **`POST /api/poc/simulate`** for IDOR / unauthenticated PoCs when the API is available |

**Side panel** — Auto-scan / site findings for the **active tab** only.

**Popup (toolbar icon)** — Security scan flow **and** the **Solana** bundle entry point (mint + optional wallet + **Analyze bundle**); Helius key lives in **Options**.

---

## Sync from canonical extension

When updating this mirror:

1. Open **[github.com/fennq/diverg-extension](https://github.com/fennq/diverg-extension)**  
2. Copy into `extension/` here: `sidepanel.*`, **`solana_bundle.js`**, `options.*`, **`icons/`**, and related background/popup assets as listed in the canonical repo’s README  
3. Keep API auto-detect / background behavior consistent with **`api_server.py`** expectations  

---

## Solana & Helius

- Bundle analysis uses **Helius** JSON-RPC / DAS-style calls (see `solana_bundle.js` and `investigation/solana_bundle.py` in the main repo).  
- Set **`HELIUS_API_KEY`** in extension Options and/or on the server for **`/api/investigation/solana-bundle`** and Solana paths on **`/api/investigation/blockchain`**.  

Use only for **authorized** research and tokens you are permitted to analyze.

---

## License

MIT — see [`LICENSE`](../LICENSE) in the repository root.
