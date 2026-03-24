# Extension tech

Background worker and API auto-detect logic. Same code is kept in sync with the separate extension repo (popup, side panel, results UI live there). Backend runs from this repo; extension calls API at 127.0.0.1:5000 by default.

**Side panel tabs**

- **Site** — Auto-scan header/inline risks for the active tab (unchanged).
- **Solana** — Token mint + optional wallet; calls `POST /api/solana/bundle-snapshot` on the local API (`python api_server.py`). Requires `HELIUS_API_KEY` in the server environment. Heuristic: top holders + wallets sharing the same direct funder (Helius funded-by).
