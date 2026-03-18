# Manual trial runs — vulnerability discovery

Summary of manual scan trials to find vulnerable exploits. Reports are saved under `reports/`. **Do not record specific company names or third-party targets** in this repo; use generic descriptions (e.g. "example SPA", "test target") or reference only authorized targets from AUTHORIZED_TEST_TARGETS if applicable.

## Trial run log

| # | Target (generic) | Scope | Date | Findings (C/H/M/L/I) | Notes |
|---|------------------|-------|------|----------------------|------|
| *(add rows as needed; do not name specific companies)* | full/quick/web | YYYY-MM-DD | — | Notes only. |

## How to run more trials

```bash
cd /path/to/Sectester
./venv/bin/python orchestrator.py --target "https://example.com" --scope web --report detailed
# Scopes: full | quick | web | api | recon | passive
```

Then append High/Critical to the discovered log:

```bash
./venv/bin/python scripts/append_discovered_exploit.py reports/sectester_<domain>_<timestamp>.json --append
```
