# Diverg — Chrome extension (monorepo mirror)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Canonical repo](https://img.shields.io/badge/extension-diverg--extension-4285F4?logo=googlechrome&logoColor=white)](https://github.com/fennq/diverg-extension)

This directory mirrors extension **background worker** and **API auto-detect** logic for the [Sectester / Diverg](https://github.com/fennq/diverg) monorepo.

**Production extension UX** (side panel, popup, **Solana bundle scanner**, options, icons) is maintained in the canonical repository:

### [**github.com/fennq/diverg-extension**](https://github.com/fennq/diverg-extension)

When updating the Chrome product, edit **diverg-extension** first, then copy the following into this repo if you need parity:

- `sidepanel.*`
- `solana_bundle.js`
- `options.*`
- `icons/`

---

## Solana bundle analysis

The extension’s **Solana** flow is built for fast, serious token due diligence:

- Enter a **token mint** and optional **wallet**
- **Analyze bundle** runs holder clustering, same-funder analysis, and coordination scoring
- Outputs align with the console’s **`POST /api/investigation/solana-bundle`** (same methodology as `investigation/solana_bundle.py` + Helius)

Configure a **[Helius](https://www.helius.dev/)** API key in **Extension options**. Without a key, Solana RPC-heavy features are limited; EVM-style checks in other surfaces may still use public endpoints.

---

## Web scan integration

- **Quick checks** can run in-browser without a backend  
- **Full scans** call the Diverg API when `api_server.py` is running (default discovery: `http://127.0.0.1:5000`, configurable)

---

## License

MIT — see the [LICENSE](../LICENSE) file in the repository root.
