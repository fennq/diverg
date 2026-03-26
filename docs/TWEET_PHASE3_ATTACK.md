# Tweet — Phase 3 attack probing

**Diagram (SVG):** [`docs/diagrams/phase3-attack-probing.svg`](diagrams/phase3-attack-probing.svg)

---

## Post (template)

Phase 3 is live: Attack Probing upgraded.

We leveled up vulnerability coverage with:

- deeper web vuln probing (full crawl + file exposure)
- expanded API probing (auth bypass, CORS, host header, rate limits, param fuzz, mass assignment, contract drift)
- stronger company surface checks (docs, staging, support, admin, identity, observability)
- attack-mode runs Phase 1 + Phase 2 + Phase 3 in one coherent report

Authorized testing only.

---

## Alt text (SVG)

Dark diagram: Phase 1 and Phase 2 boxes feed into a purple-outlined Phase 3 block; three columns list web_vulns variants, api_test passes, and auth_test / company_exposure buckets; footer notes API scope=attack and orchestrator phase list.
