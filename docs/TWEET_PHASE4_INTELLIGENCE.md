# Tweet — Phase 4 intelligence synthesis

**Diagram (SVG):** [`docs/diagrams/phase4-intelligence-synthesis.svg`](diagrams/phase4-intelligence-synthesis.svg)

---

## Single post (Phase 1 style)

**Phase 4 is live:** Intelligence synthesis on top of Phases 1–3.

We turn the full skill graph into **ranked attack paths** (cross-skill chains, not isolated alerts), a **finding-type-aware risk score** (hardening vs real vulns weighted differently), a **tiered remediation plan** (fix now / soon / harden), plus **gap analysis** and **suggested next tests** so operators know what to run next.

Same payload on **CLI orchestrator**, **POST /api/scan**, and the **extension** full report. Authorized assessments only.

@DivergSec

---

## Short (~280 chars)

Phase 4: after surface + context + attack passes we **synthesize** — correlated **attack paths**, **0–100 risk** (hardening vs vulns), **remediation tiers**, **gaps + next tests**. API + extension. Checklist tools don’t chain findings; we do. @DivergSec

---

## Alt text (SVG)

Dark technical flowchart: Phase 1 Surface, Phase 2 Context, Phase 3 Attack, Aggregate, then a highlighted Phase 4 Intelligence synthesis box feeding four outputs — Attack paths, Risk score, Remediation plan, Gaps and next tests — with Diverg/GitHub-style colors.
