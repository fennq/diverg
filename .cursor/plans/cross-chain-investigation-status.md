# Cross-chain investigation — implementation status

Last reviewed: 2026-03-29. Items below are implemented on `main` unless noted.

## Core

- [x] Wormhole CSV (and JSON fallbacks) with disk cache under `data/`
- [x] Optional CoinGecko contract lookups with disk TTL cache (`DIVERG_COINGECKO_CACHE_SEC`)
- [x] `foreign_explorer_url` + `confidence_tier` on each candidate (`investigation/cross_chain_hints.py`)
- [x] `summarize_cross_chain_payload()` for bundle vs investigation-report shapes
- [x] Solana bundle: `cross_chain` + `summary` (`investigation/solana_bundle.py`)
- [x] `blockchain_investigation` skill: `cross_chain` + `summary`, finding text includes explorer URLs
- [x] Bridge/mixer funding-cluster signals with focus-cluster–scoped bridge counts (`bridge_count_eligible_wallets`)
- [x] `bridge_mixer_confidence_tier` + `bridge_signal_scope` on bundle signal block
- [x] Unit tests + CSV fixture; optional Helius smoke test (`tests/test_helius_solana_bundle_smoke.py`)

## Optional

- [x] Run smoke test locally: `HELIUS_API_KEY=... python3 -m unittest tests.test_helius_solana_bundle_smoke`

## Hygiene

- [x] Root `package.json` / `package-lock.json` for `@railway/cli` (deploy tooling)
