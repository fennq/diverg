# Next Evolution: Where Diverg Can Really Change the Game

## Current Problems with Web Applications (That Most Tools Don’t Solve Well)

1. **Findings in isolation** — Scanners report a list. Real risk is *chains*: "verbose error reveals internal host" + "SSRF" = pivot. "IDOR on user id" + "user id in JWT" = no guessing. Nobody tells the client "combine A + B and an attacker can do X."

2. **Schema vs reality** — OpenAPI says "PATCH not allowed"; server accepts it. Schema says "read-only"; server mutates. Docs say "401 when unauthenticated"; server returns 200 with empty data. **Contract drift** and **shadow behavior** are everywhere; few tools compare declared API contract to actual behavior.

3. **“Possible” vs “proven”** — "Possible SQLi" vs "we extracted a row." "Possible XSS" vs "we got cookie in our callback." Reducing noise by **proving** exploitability (actual exfil, actual state change) would change how much teams trust and act on reports.

4. **Client-side boundary** — Most scanning is server-side. Real issues: sensitive data in localStorage/__NEXT_DATA__, postMessage to untrusted origins, prototype pollution, dangerous sinks (eval, innerHTML). The **client is untrusted** boundary is where many modern apps leak.

5. **Logic, not injection** — "Apply discount twice," "change quantity after price lock," "reuse one-time link," "vote/rate multiple times." These need workflow understanding and state, not just parameter fuzzing.

6. **Time and race** — TOCTOU, coupon/credit expiry bypass, rate-limit timing, session fixation with quick reuse. Time as a dimension is under-tested (we have race_condition; we could go deeper).

---

## What Diverg Already Does Well

- Adaptive tool selection (discover → run what matches).
- Multiple high-value skills (payment, crypto, data leak risks, IDOR, race condition).
- CONFIRMED vs VERIFY labeling and remediation on every finding.
- Correlation and attack-path narrative in the report (LIKELY ATTACK PATHS, correlation_engine).
- Evidence normalization and dedupe across skills.

---

## Three Evolution Directions That Would Really Make a Change

### A. **Contract vs reality (API schema drift)** — IMPLEMENTED

**Idea:** When we find OpenAPI/Swagger/GraphQL schema (we already discover these), *compare* declared contract to actual server behavior.

- **Methods:** Schema says only GET; we send POST, PUT, PATCH, DELETE. Report "Schema says GET only; server accepts POST (shadow API / contract drift)."
- **Status codes:** Schema says 401 for unauthenticated; we GET without auth and get 200. Report "Contract says 401; server returns 200 when unauthenticated."
- **Fields:** Schema marks `role` as read-only; we send PATCH with `role: admin`. Report "Declared read-only field accepted in request (privilege escalation risk)."

**Why it matters:** Contract drift is a top real-world cause of access control and logic bugs. Almost no scanners do this. It’s a clear differentiator and directly addresses "current problems with web applications."

**Scope:** Implemented in api_test: `_fetch_openapi_spec`, `_parse_openapi_paths`, `test_contract_drift`. Runs on full scan and when scan_type is `contract_drift`. Reports: (1) server accepts method not in schema, (2) 200 when auth required per schema, (3) read-only field accepted in PATCH/PUT.

---

### B. **Explicit attack path correlation** — IMPLEMENTED

**Idea:** Don’t just list findings; **infer and report chains** that lead to a concrete impact.

- **Input:** Normalized findings (we already have this).
- **Logic:** Simple rules + optional LLM pass: e.g. "Finding: verbose error discloses internal hostname" + "Finding: SSRF in web_vulns" → "Attack path: Use SSRF to reach disclosed host; likely internal pivot."
- **Output:** A short "Correlated attack paths" section: "Path 1: [entry] → [step] → [impact]. Evidence: finding A + B."

**Why it matters:** Clients get "what an attacker could actually do" instead of a pile of issues. We already have correlation_engine and LIKELY ATTACK PATHS; making the *chain* explicit and evidence-based would be the evolution.

**Scope:** Implemented in bot: `_infer_attack_paths` now assigns 1-based finding IDs, matches paths by keywords, and attaches `evidence_finding_ids` to each path. New path: "Info disclosure to SSRF pivot" when both verbose/internal disclosure and SSRF are present. Report instruction: cite "Evidence: findings #N, #M" when present.

---

### C. **Prove it (exploitability checks)** — IMPLEMENTED (SQLi, IDOR, XSS callback)

**Idea:** For high-value findings, add a **proof step** where we try to turn "possible" into "confirmed."

- **SQLi:** If we see error-based or time-based signals, send one payload that extracts a known value (e.g. version()) or triggers a measurable delay; if we get it, label CONFIRMED and add one-line proof to evidence.
- **XSS:** If we see reflection in a dangerous context, try a minimal callback (e.g. img onerror or fetch to our endpoint); if we get a hit, CONFIRMED.
- **IDOR:** We already probe alternate IDs; if we get a different user’s data structure (same schema, different content), add "Proof: response for id=N contained distinct user data."

**Why it matters:** Fewer false positives, more trust, and clearer prioritization. We already use CONFIRMED/VERIFY; this is "one more step" to actually prove the exploit where feasible.

**Scope:** Done: SQLi version extraction in web_vulns; IDOR distinct-data proof in high_value_flaws; XSS optional `DIVERG_XSS_CALLBACK_URL` proof payload in web_vulns.

---

## Recommendation

- **Fastest high impact:** **A (Contract vs reality)**. We already discover docs and hit APIs; adding a small "deviation from schema" layer would directly target a widespread, under-tested problem and differentiate Diverg.
- **Highest strategic value:** **B (Attack path correlation)**. It makes the whole report answer "so what can an attacker do?" and leverages the findings we already have.
- **Best for trust and noise:** **C (Prove it)**. Improves every report by upgrading "possible" to "confirmed" where we can.

Doing **A** first, then **B**, then **C** would be a strong evolution path: first "find what others miss (contract drift)," then "explain what it means (paths)," then "prove what we say (exploitability)."
