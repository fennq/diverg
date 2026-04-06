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

## 2026-04-06

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
