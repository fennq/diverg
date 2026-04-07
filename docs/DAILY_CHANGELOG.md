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

## 2026-04-07

### Highlights
- Rolled out Solana ecosystem security framework integration across API, dashboard investigation, scanner analytics, and public docs.
- Added a shared `solana_security_profile` model so Solana guidance is consistent between investigation and scan workflows.
- Published same-day release notes in internal and public changelogs.
- Added dashboard-first initiative push pass with role-based CTAs, activation hooks, and KPI review tracking for Solana Security Program adoption.

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

### Notes
- Existing unrelated local changes and untracked files were intentionally left untouched.
- Public docs rollout was completed in `diverg-landing` and linked from Resources.
- Public docs wording was further aligned to a dashboard-first initiative narrative.

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
