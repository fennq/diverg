# Tweet + asset — Phase 2 context skills (Dependency · Logic · Reputation)

Ship note: full web scans now run these **after** phase-1 surface skills, using **client_surface**, **recon**, **api_test**, and **osint** context. Recent upgrades: richer stack detection (incl. `Sec-CH-UA`), baseline-aware logic probes + form POST, canonical reputation findings + domain fallback when WHOIS is empty.

**Visual:** use `docs/assets/phase2-context-skills-card.png` (generated) for the image post.

---

## Single post (medium)

**Phase 2 context skills** — one pipeline, three focused passes:

1️⃣ **Dependency audit** — headers + JS/recon versions vs curated **CVE watchlist** (more signal from `Sec-CH-UA`, `Via`, common stacks).

2️⃣ **Logic / numeric abuse** — probes amount/limit-style params with **GET + JSON + form**; **baseline fingerprint** cuts “success” noise on static pages.

3️⃣ **Entity reputation** — org/registrant/mail domains from **OSINT** (WHOIS fallback); outputs **canonical findings** + manual **recommended_queries**.

Built for **authorized** assessments — evidence-backed, not dashboard candy.

$DivergSec — multimodal security & investigation.

---

## Short (~260 chars)

Phase 2 of our web scan: **dependency/CVE watchlist** (incl. Sec-CH-UA), **logic/numeric abuse** (baseline + form POST), **entity reputation** (canonical findings). Context from phase 1 — one coherent report. Authorized testing only. @DivergSec

---

## Thread (3 posts)

**1/** Full Diverg web scans aren’t a flat checklist. **Phase 2** runs three context-aware modules *after* recon, client JS, API, and OSINT.

**2/** **Dependencies:** version signals from headers + surface + recon, matched to a curated CVE list. **Logic abuse:** tamper probes with baseline diffing so static “success” pages don’t drown signal. **Reputation:** entity-level DDG research normalized into standard findings.

**3/** Goal: same **title / severity / evidence / impact / remediation** shape end-to-end — CLI, API, extension — so operators can triage fast and corroborate anything that touches legal or regulatory claims.

---

## Alt text (for the image)

Diverg branded diagram: three columns labeled Dependency audit, Logic abuse, Entity reputation, on a dark grid with teal accents and subtitle “Phase 2 — context-aware scanning.”
