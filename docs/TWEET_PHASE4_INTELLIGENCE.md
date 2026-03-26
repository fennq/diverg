# Tweet — Phase 4 intelligence synthesis

**Diagram (SVG):** [`docs/diagrams/phase4-intelligence-synthesis.svg`](diagrams/phase4-intelligence-synthesis.svg)

---

## Post (same structure as Phase 3)

Phase 4 is live: Intelligence synthesis upgraded.

We leveled up what happens after the scan with:

- ranked attack paths across skills (exploit chains, not isolated checklist items)
- finding-type-aware risk score (0-100, Safe / Caution / Risky; hardening weighted lower than real vulns)
- tiered remediation plan (fix now, fix soon, harden when possible)
- gap analysis plus suggested next tests so you know which probes complete the story
- same structured payload on the orchestrator, POST /api/scan (and streaming), plus the extension full report

Authorized testing only.

---

## Short (~260 chars)

Phase 4: post-scan intelligence — **attack path correlation**, **risk score + verdict**, **remediation tiers**, **gaps + next tests**. API + extension. @DivergSec

---

## Alt text (SVG)

Dark flowchart: Phases 1-3 and aggregate feed Phase 4 intelligence synthesis; four output columns for attack paths, risk score, remediation plan, and gaps/next tests; references orchestrator run_web_scan.
