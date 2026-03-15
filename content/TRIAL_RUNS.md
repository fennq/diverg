# Manual trial runs — vulnerability discovery

Summary of manual scan trials to find vulnerable exploits. Reports are saved under `reports/`.

## Trial run log

| # | Target | Scope | Date | Findings (C/H/M/L/I) | Notes |
|---|--------|-------|------|----------------------|------|
| 1 | https://testphp.vulnweb.com | full | 2026-03-15 | 0/1/0/2/3 | Target unreachable (SSL/connection timeout); no injection vulns confirmed. |
| 2 | https://www.perplexity.ai/computer/new | quick | 2026-03-15 | 0/0/1/3/13 | CSP missing (Medium); HSTS max-age &lt; 1y; Server header. 403s from WAF. |
| 3 | https://x.com/home | quick | 2026-03-15 | 12/31/11/12 | Path probe 200s on /admin, /backoffice, /export.* — verify (SPA often returns 200 for all routes). |
| 4 | https://www.perplexity.ai/computer/new | api | 2026-03-15 | (running) | api_test + headers_ssl + company_exposure; may timeout due to 403s. |

Earlier runs (same session): Perplexity web (19 findings), X.com web (69 findings) — see DISCOVERED_EXPLOITS.md.

## Exploitable findings from trials

- **Perplexity:** Missing CSP (Medium) — multi-site applicable. HSTS 180 days; Server: cloudflare.
- **X.com:** Path-based “admin/backup/export” High — require verification (SPA 200 vs real backend). HSTS fixed (includeSubdomains accepted).
- **testphp.vulnweb.com:** Not reachable from scan environment; run from network where target is available to get SQLi/XSS findings.

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
