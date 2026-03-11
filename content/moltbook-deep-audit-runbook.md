# Full In-Depth Review — Moltbook (or Any Target)

Use this runbook when you want a **full, advanced** security review: maximum coverage, client-side intel fed into dependency/CVE and logic abuse, breach checks, exfil and crypto-trust signals, and follow-up from recommended next tests.

## When to use

- **Target:** Moltbook or any product where you want a deep audit.
- **Trigger:** In Telegram, use an objective that includes **in-depth**, **deep review**, **full review**, **moltbook**, **thorough**, or **comprehensive**.  
  Example:  
  `Run a full in-depth security review of moltbook`  
  or  
  `Full deep review of https://moltbook.com including user leakage and crypto trust`

The bot infers the **deep-audit** preset and runs the expanded plan below.

---

## What the deep-audit preset does

### Phase 1 (discovery)
- **OSINT (full)** — WHOIS, DNS, crt.sh, breach checks (HIBP, IntelX), tech fingerprinting.
- **Recon** — Subdomains, techstack, sensitive path discovery.

### Phase 2 & 3 (expanded)
- **Headers & TLS** — HSTS, CSP, TLS versions, cert.
- **Crypto** — JWT, weak TLS, weak frontend crypto, **crypto-trust** (client-side key/seed/signing).
- **Data leak risks** — Verbose errors, cache/PII, client-side exposure.
- **Client surface** — JS fetch/axios, source maps, dangerous sinks, **third-party exfil** (sensitive data to other domains), **crypto-trust** patterns.
- **Dependency audit** — Uses **client_surface** and **recon** output: versions from headers + JS, CVE watchlist.
- **Logic abuse** — Uses **client_surface** extracted endpoints: amount/limit/offset probes (0, -1, MAX_INT, NaN).
- **API** — Discovery, GraphQL, info disclosure, auth bypass, CORS.
- **Auth** — Forms, session, enumeration, JWT.
- **Company exposure** — Operational, business, debug.
- **High-value flaws** — IDOR, secrets in assets.
- **Race condition** — Concurrency on financial/trade endpoints.
- **Payment/financial** — Amount tampering, refund, wallet/order IDOR.
- **Web vulns** — Full (files, XSS, SQLi, etc.).

So: **client_surface runs first**, then **dependency_audit** and **logic_abuse** receive its output for versions and endpoints. Breach exposure (from osint) is surfaced in the report with the dark-web disclaimer.

---

## How to run

### 1. Full attack (recommended for in-depth)
In Telegram:

```
Run a full in-depth security review of moltbook
```
or with URL:

```
Full deep review of https://moltbook.com including user leakage and crypto trust
```

The bot will:
1. Run phase1 (osint full, recon x3).
2. Infer profiles and run phase2+phase3 (all skills above), **passing client_surface result into dependency_audit and logic_abuse**.
3. Correlate findings, attack paths, **recommended_next_tests**.
4. Send results to the LLM for the final report (with breach/dark-web note if applicable).

### 2. With authenticated (post-login) checks
- Set auth once: `/setauth cookies=...` or `/setauth bearer_token=...`
- Then send: `Full in-depth review of moltbook` (or the URL).  
  Payment, wallet, and other auth-dependent checks will use the stored session.

### 3. Direct /scan with deep preset
If the **target** contains **moltbook** (e.g. `moltbook.com`), the bot infers **deep-audit** even without an objective. So:

- `/scan moltbook.com`  
  uses the deep-audit plan (same expanded steps, with context passing for dependency_audit and logic_abuse).

---

## What “next level” means here

| Area | Standard run | Deep in-depth run |
|------|----------------|-------------------|
| **OSINT** | DNS / light | Full: breach (HIBP, IntelX), tech, subdomains |
| **Recon** | Subdomains + techstack | + sensitive path discovery |
| **Client intel** | client_surface | Same + **exfil** (third-party + sensitive params) and **crypto-trust** (key/seed/signing) |
| **Dependency/CVE** | Headers only | **+ client_surface + recon** → versions from JS and techstack, then CVE watchlist |
| **Logic abuse** | Built-in paths | **+ client_surface** → probes **extracted_endpoints** with numeric/bounds |
| **API / auth** | Discovery + one or two variants | Discovery + GraphQL + info disclosure + auth bypass + CORS + JWT + enumeration |
| **Report** | Findings + attack paths | + **recommended_next_tests** + **breach_exposure** + dark-web disclaimer when relevant |

---

## After the run

- Use **RECOMMENDED NEXT TESTS** in the report (e.g. SSRF if verbose errors, API discovery on client endpoints, XSS if dangerous sinks).
- If **breach_exposure** is present: treat as “domain/emails in known breaches”; we cannot confirm dark-web sale — use threat intel or breach monitoring.
- For Moltbook (or any crypto/trading app): focus the read on **crypto-trust**, **third-party exfil**, **IDOR on wallet/position/trade**, and **logic abuse** on amount/limit.

---

## Optional: even deeper

- **Manual follow-up:** WebSockets, parameter pollution, logout/revoke token reuse, pagination/sort abuse (see axiom-trade runbook “Underplayed risks”).
- **Add Moltbook-specific paths:** If Moltbook exposes known API paths, add them to payment_financial or api_test wordlists and re-run.
- **Second pass:** Run the first 1–2 **recommended_next_tests** (e.g. `run_web_vulns` for SSRF, `run_api_test` for discovery on client endpoints) and merge into your report.

This runbook plus the deep-audit preset and context passing give you a **full in-depth review** suitable for Moltbook or any high-value target.
