# Daily Changelog

Professional, end-of-day shipping log for Diverg.

Use this page as the source of truth for what was completed each day, why it matters, and how it was validated.

---

## Update Workflow

At the end of each day:

1. Summarize all shipped changes for the day (product, docs, infra, testing).
2. Add a new entry under this file with newest date first.
3. Keep language crisp, outcome-focused, and professional.
4. Include validation notes (tests/smoke checks) when available.

---

## Entry Template

Copy this template for each new day:

```md
## YYYY-MM-DD

### Highlights
- Key outcome 1
- Key outcome 2

### Product & UX
- What changed in user-facing flows

### Platform & API
- Backend/data/reliability changes

### Validation
- Tests run and outcomes

### Notes
- Risks, known limitations, or follow-ups
```

---

## 2026-04-13

### Highlights
- Hardened HTTP security for the console and API: HTTPS-aware HSTS, stricter CSP on dashboard pages, trust-aware client IP handling, and reduced server fingerprinting.
- Shipped professional changelog entry documenting security work alongside recent platform features (scan verification UX and site watchlist).

### Product & UX
- Dashboard `index.html` and `login.html` now send `noindex, nofollow` and an explicit referrer policy meta tag so the operator console is less likely to be indexed or leak full URLs via referrers.

### Platform & API
- `Strict-Transport-Security` is emitted only when the request is effectively HTTPS (`request.is_secure` or `X-Forwarded-Proto` when proxy trust is enabled), avoiding misleading HSTS on plain HTTP dev servers while keeping strong posture behind TLS terminators.
- `DIVERG_TRUST_PROXY` (documented in `.env.example`) controls whether `X-Forwarded-For` / `X-Forwarded-Proto` are honored; default follows production vs dev (production defaults to trusting, matching Railway-style deployments).
- `_get_client_ip()` no longer trusts `X-Forwarded-For` when proxy trust is disabled, reducing client IP spoofing risk on directly exposed instances.
- Dashboard CSP extended with `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`, and `upgrade-insecure-requests` in production; `Permissions-Policy` tightened with `payment`, `usb`, and ad-topic related directives.
- `Server` response header is stripped on outbound responses where present.
- Startup warning when `IS_PRODUCTION` and `DIVERG_JWT_SECRET` is unset (ephemeral signing key per process).

### Validation
- `python3 -m pytest tests/ -q` — full suite green after changes.

### Notes
- If you terminate TLS on a custom proxy, set `DIVERG_TRUST_PROXY=1` explicitly when needed and ensure the proxy sets `X-Forwarded-Proto: https` so HSTS and HTTPS detection stay correct.
- Marketing site (`diverg-landing` / divergsec.com) is separate from this repo; console hardening applies to the Flask-served dashboard and API.

## 2026-04-10

### Highlights
- Shipped Solana protocol-depth analysis with Token-2022 extension risk extraction and authority misuse heuristics in bundle investigations.
- Added correlated wallet-drainer signal scoring to reduce single-pattern noise while preserving explicit allowlist blind-spot visibility.
- Extended strict evidence gates and proof contracts for new Solana and wallet-abuse categories, then validated via full regression tests.

### Product & UX
- Token bundle results now include concise Solana depth panels for token program standard, extension indicators, and authority misuse score/signals.
- Dashboard token investigation view now surfaces protocol-depth rationale without overwhelming the existing holder/funder workflow.
- Extension popup now displays Token-2022/program risk context and authority misuse summary alongside coordination output.

### Platform & API
- `investigation/solana_bundle.py` now parses DAS token program/extension authority indicators and emits normalized `token_program_analysis`.
- `investigation/solana_bundle_signals.py` now computes authority misuse findings (`risk_reason`, `confidence`, remediation, holder context) and exposes them in `bundle_signals`.
- `skills/wallet_drainer_signals.py` now applies multi-signal correlation (approval + signing + hijack + obfuscation + origin context) and emits correlated cluster diagnostics.
- `skills/client_surface.py` now attaches wallet-drainer correlation context fields (`matched_signals`, `score`, `reason`) into finding evidence.
- `orchestrator.py` strict proof contracts now include Solana authority/Token-2022 and wallet-abuse correlation classes to keep evidence requirements explicit.
- `api_server.py` Solana bundle enrichment now exposes top-level depth signals (`token_program_analysis`, `authority_misuse_score`, `solana_depth_signals`) for dashboard/extension parity.

### Validation
- Targeted suites passed for Solana depth and strict-gate changes (`44 passed`).
- Full regression suite passed: `python3 -m pytest tests/ -q` (`166 passed`, `6 skipped`).
- Lint diagnostics check reported no new issues on edited files.

### Notes
- Wallet-drainer detection remains heuristic; medium/high correlated severity now requires multi-signal corroboration for third-party scripts.
- Allowlisted third-party wallet hosts still suppress direct drainer alerts by design, but now emit explicit blind-spot diagnostics for analyst awareness.
- This entry excludes social/article publication assets and focuses on product/platform/tested shipping work.

## 2026-04-09

### Highlights
- Integrated Privy wallet authentication (SIWS) as a primary sign-in/signup path alongside existing email/password flow.
- Shipped daily scan credit system with token-holder bonus grants, wallet-verified DIVERG balance lookup, and live countdown timer.
- Wallet connection now persists across sessions and auto-links on Privy signup.

### Product & UX
- Added "Create account with Privy (Wallet)" button on login/signup page with hybrid mode (wallet + email fallback).
- New Privy users are prompted to choose a username before entering the dashboard (no more "Privy User" defaults).
- Credits page redesigned: connected/disconnected wallet state with green status dot, live token balance display, and a ticking HH:MM:SS countdown until daily credit reset.
- "Connect Phantom" button toggles to "Change Wallet" when a wallet is already linked; "Refresh Balance" only appears when connected.
- Email/password users can connect a wallet from the Credits page via Phantom challenge-sign flow.
- Frontend now surfaces specific Privy error codes and hints in the login UI for faster self-diagnosis.

### Platform & API
- Added `PATCH /api/auth/profile` endpoint for authenticated users to update their display name.
- `/api/auth/privy` now accepts `wallet_address` and auto-links it to the user's credit account on signup.
- Privy access token verification uses a two-path strategy: `privy-client` SDK first, then a PyJWT + JWKS fallback that fetches the ES256 verification key from `auth.privy.io`. No hard dependency on `privy-client` for token verification.
- Wallet signature verification now has a `cryptography` Ed25519 fallback and pure-Python base58 decoder, so it works even if `PyNaCl`/`base58` packages are missing.
- Added `PyNaCl>=1.5.0`, `base58>=2.1.0`, and `privy-client>=0.2.0` to `requirements.txt`.
- CSP headers updated to allow Privy SDK domains (auth, API, CDN, WSS).
- Privy verification error responses now return structured `code` and `hint` fields (503 for server misconfiguration, 401 for invalid tokens).
- Solana bundle holder clustering fixed: wallets are now grouped by direct first funder instead of multi-hop terminal address.

### Validation
- All existing test suites pass: `test_privy_auth_bridge`, `test_wallet_signature_verify`, `test_credits_system`, `test_solana_bundle_holder_cluster`.
- Manual verification of PyNaCl, cryptography-fallback, and base58-fallback signature paths.
- Flake8 lint clean on `api_server.py` and `orchestrator.py`.

### Notes
- Privy SIWS flow requires Phantom wallet extension; Google OAuth via Privy is disabled in the Privy dashboard and not used.
- `HELIUS_API_KEY` must be set on the server for automatic DIVERG token balance lookup during wallet auto-link; without it, balance defaults to 0 and users can refresh manually.
- Server env vars required for Privy: `DIVERG_ENABLE_PRIVY=1`, `PRIVY_APP_ID`, `PRIVY_APP_SECRET`.

---

## 2026-04-08

### Highlights
- Shipped Solana Phase 2 mint watchlist: per-user server persistence, dashboard Tokens UI, automatic snapshot refresh after bundle scans, and a follow-up accuracy pass (mint validation, watchlist TVL merged into bundle requests, clearer snapshot copy).

### Product & UX
- Added Mint watchlist card on the Tokens page with add-from-field, optional self-reported TVL (USD) for tier context, load/run-scan/remove actions, and inline last verdict and score display.
- Added “Add to watchlist” on successful token bundle results for one-click save.
- Bundle scans send `tvl_usd` from the watchlist row when the mint is saved with TVL; results show a short banner when that value was applied.
- Watchlist rows show **last scan** time (`last_checked_at`), self-reported TVL line, and explicit copy that verdict/score are bundle heuristics—not a protocol audit.
- Token scanner rejects invalid mint strings client-side before calling the API.
- Follow-up polish: watchlist cache prefetched on dashboard load; bundle scans refresh cache first so TVL merge is reliable; silent list refresh when switching to Tokens (no loading flicker); inline flash messages instead of alert on save; Load/Run scan prefill optional TVL field; Enter runs bundle scan from mint input; watchlist upsert preserves existing **label** when POST sends an empty label.

### Platform & API
- Added `solana_watchlist` SQLite table with unique `(user_id, mint)` and capped list size per user.
- Added authenticated endpoints: `GET/POST/PATCH /api/solana/watchlist`, `DELETE /api/solana/watchlist/<id>` for list, upsert, snapshot patch, and delete.
- Shared base58 mint checks (`32–44` charset) for `POST/PATCH /api/solana/watchlist` and `POST /api/investigation/solana-bundle`.
- Watchlist `POST` upsert keeps the prior `label` when the client omits or sends a blank label (empty re-add no longer wipes notes).
- Added `tests/test_solana_mint_format.py` for mint validation rules.

### Validation
- `python3 -m py_compile api_server.py` and `node --check dashboard/js/app.js` completed successfully.
- `pytest tests/test_solana_mint_format.py -q` passed.

### Notes
- Public integrations docs updated to describe live mint watchlist behavior, automatic TVL on re-scan, and dashboard entry path.

## 2026-04-07

### Highlights
- Rolled out Solana ecosystem security framework integration across API, dashboard investigation, scanner analytics, and public docs.
- Added a shared `solana_security_profile` model so Solana guidance is consistent between investigation and scan workflows.
- Published same-day release notes in internal and public changelogs.
- Added dashboard-first initiative push pass with role-based CTAs, activation hooks, and KPI review tracking for Solana Security Program adoption.
- Added a product-direction scanner focus pass that keeps scan experiences centered on core findings and diff interpretation.

### Product & UX
- Added Solana Security Program rendering in token bundle investigation results with:
  - tier status
  - monitoring/formal-verification eligibility context
  - incident response priority
  - pillar and action summaries
- Added Solana Security Program card in scanner analytics for crypto-relevant scans.
- Kept scanner presentation aligned with existing dashboard cards and analytics list patterns.
- Added a scanner-side “What this means” block, trust row (`Framework-aligned`, profile logic date), role mode switch, and CTA hierarchy.
- Added token investigation-side initiative actions: deeper recheck trigger, framework reference, baseline reminder, and incident summary export.
- Added generated Solana incident runbook blocks (severity, owner role, first-15-minute steps, escalation contacts, top actions) in scanner and token program surfaces.
- Added weekly KPI review panel in Analytics for Solana initiative usage (views, CTR, rechecks, investigations) with copy-adjustment guidance.
- Added a streamlined scanner presentation pass to reduce non-core overlays and keep triage paths concise.
- Added a streamlined token investigation presentation pass to keep the holder/funding analysis flow clear and direct.
- Added analytics surface cleanup so dashboard telemetry panels stay aligned with core scan workflows.

### Platform & API
- Added deterministic Solana profile model generation with:
  - framework references (program, STRIDE, SIRN)
  - TVL-based tier mapping (`$10M` monitoring, `$100M` formal verification)
  - pillar status logic
  - incident readiness checklist
  - tooling coverage map
  - prioritized next actions
- Extended `POST /api/investigation/solana-bundle` with profile attachment and optional `tvl_usd` context.
- Extended `POST /api/scan` and `POST /api/scan/stream` done payloads with `solana_security_profile` for eligible scan contexts.
- Added client-side Solana event instrumentation for dashboard interactions:
  - card views
  - role mode changes
  - primary/secondary CTA clicks
  - recheck starts
  - investigation completions
  - baseline reminder saves
  - incident summary exports
  - incident workflow starts with runbook severity context

### Validation
- `python3 -m pytest tests/test_scan_diff.py -q` passed (`5 passed`).
- `node --check dashboard/js/app.js` passed.
- Lint diagnostics check reported no issues on edited dashboard/backend files.
- Post-update syntax check passed for `dashboard/js/app.js` and no linter issues were reported on edited dashboard files.

### Notes
- Existing unrelated local changes and untracked files were intentionally left untouched.
- Public docs rollout was completed in `diverg-landing` and linked from Resources.
- Public docs wording was further aligned to a dashboard-first initiative narrative.
- Update scope was limited to dashboard surfaces (`index.html`, `app.js`, `dashboard.css`) and did not touch unrelated local work.

## 2026-04-06

### Solana Security Integration Update
- Added a shared `solana_security_profile` schema to API outputs so Solana framework guidance is deterministic across products.
- Integrated profile generation into:
  - `POST /api/investigation/solana-bundle` (with optional `tvl_usd` support for tiering context)
  - `POST /api/scan`
  - `POST /api/scan/stream` (`done` report payload)
- Added a scanner-side Solana Security Program card that appears when crypto context is detected and renders:
  - tier label
  - monitoring/formal-verification eligibility flags
  - incident priority
  - pillar and immediate action lists
- Added investigation rendering in token bundle results for Solana Security Program details, including references to framework sources.
- Introduced deterministic profile sections:
  - framework references (program, STRIDE, SIRN)
  - TVL tiering model (`10M` monitoring / `100M` formal verification)
  - pillar status model
  - incident readiness checklist
  - tooling coverage map (Hypernative, Range, Riverguard, Sec3 X-Ray, AuditWare Radar)
  - actionable recommendations with priority
- Updated public docs/resources in `diverg-landing`:
  - expanded `resources/docs/blockchain.html` with Solana Security Program section
  - expanded `resources/docs/integrations.html` with framework integration model
  - added a Solana Security Program card on `resources/index.html`

### Validation (Solana Security Integration)
- Backend and frontend files updated and sanity-checked for profile propagation and rendering paths.
- Final validation sweep includes targeted tests/lints after this entry.

### Highlights
- Completed major scanner improvements across onboarding, trust UX, and reliability transparency.
- Shipped a full recheck + scan diff flow (`new`, `fixed`, `regressed`, `improved`) wired end-to-end.
- Updated and pushed `diverg-auto` alignment release (`v0.3.1`) in the companion repository.
- Launched a public-facing daily changelog page format on the website.
- Improved scan diff discoverability by showing it directly on scanner page before first run.
- Removed GitHub issue integration path after product decision to keep scanner workflow focused.

### Product & UX
- Added guided first-run scanner onboarding with scope helper context.
- Expanded findings trust presentation with structured detail blocks and a "Fix First (Top 3)" panel.
- Added false-positive feedback action flow from scanner findings.
- Removed the Scanner Readiness panel from the scanner UI per product direction.
- Added a new scanner "Scan Diff" panel with:
  - counts for New / Fixed / Regressed / Improved
  - detail lists for each bucket
  - one-click "Recheck target" action.
- Refined scan diff UX with:
  - always-visible card on scanner page (not only after scan completion)
  - one-line explainer for baseline comparison behavior
  - first-run CTA to trigger recheck flow
  - inline help tooltips for New/Fixed/Regressed/Improved definitions
  - stronger visual emphasis for Fixed, Regressed, and Improved values
  - human-readable baseline timestamp formatting
- Removed GitHub issue integration controls from settings and finding rows to reduce workflow noise.

### Platform & API
- Extended scan responses with `scan_diff` metadata generated against the most recent prior scan for the same target and user.
- Enabled diff attachment for both:
  - `POST /api/scan`
  - `POST /api/scan/stream` (`done` event report payload).
- Diff model now tracks baseline status and includes scoped finding samples for each diff bucket.

### Validation
- Scanner test sweep completed via automated tests and endpoint smoke checks.
- Scan diff validation:
  - `tests/test_scan_diff.py` passing
  - live smoke run confirms baseline behavior on first scan and populated diff schema on subsequent same-target scan
- Post-change syntax and lint validation completed for updated scanner UI files (`dashboard/index.html`, `dashboard/js/app.js`, `dashboard/css/dashboard.css`).

### Notes
- Local environment has multiple active API ports; testing used known-good local instances to validate behavior.
- Some unrelated workspace files remain modified/untracked and were intentionally left untouched.

### Detailed Release Notes
- **Scanner Discoverability**
  - `Scan Diff` is now visible before a scan starts so users can understand comparison behavior earlier.
  - First-run empty-state copy now explains baseline setup directly instead of showing a generic empty panel.
  - First-run CTA now points users to immediate recheck behavior once baseline exists.
- **Diff Interpretation Quality**
  - Added micro-help hints (`?`) on each bucket to explain how `new`, `fixed`, `regressed`, and `improved` are computed.
  - Changed baseline timestamp rendering from raw API string to human-readable local time for faster triage.
  - Highlighted outcome buckets visually (positive for fixed/improved, warning for regressed) for better scan-read speed.
- **Workflow Decisions**
  - Removed GitHub integration actions from scanner findings after product review; current remediation flow remains in-console by design.
  - Preserved all diff API and data-layer behavior; change was strictly workflow/UI simplification, not model rollback.
- **Operational Impact**
  - No auth or permissions model changes introduced with this pass.
  - No scan-engine skill selection changes were made; improvements are focused on result interpretation and usability.
