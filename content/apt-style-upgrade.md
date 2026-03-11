# Think Like Them, Find Before Them — APT-Style Upgrade

Sophisticated actors (e.g. Lazarus, other APT) find bugs that scanners miss by focusing on **code**, **supply chain**, **logic**, and **chaining**. They move fast on new CVEs and reason about how to combine small issues into full compromise. This doc outlines how to upgrade Diverg so we surface those same classes of issues earlier.

---

## How They Find Exploits (What We’re Matching)

| What they do | What it means for us |
|--------------|----------------------|
| **Code-level analysis** | Don’t just probe HTTP; read client-side JS, source maps, and build artifacts. Find dangerous sinks (eval, innerHTML), API shapes, and secrets before an attacker does. |
| **Supply chain** | Hit dependencies and frameworks: known CVEs (e.g. React2Shell), dependency confusion, outdated libs. Know versions and match to public exploits. |
| **Logic and state** | Abuse *order of operations* and *numeric edge cases*: integer overflow in amounts, rounding errors, TOCTOU, “pay then cancel then refund” flows, state machine bypass. |
| **Chaining** | Treat findings as steps: “We have A and B; the next test should be C.” Use correlation to suggest the *next* probe, not just the final path. |
| **Speed to new CVEs** | When a critical CVE drops (e.g. Next.js, React, a popular API framework), quickly check targets for that version and pre-built exploit. |

---

## Upgrade 1: Client-Side Code Intelligence

**Goal:** Turn the frontend into a first-class source of attack surface and evidence.

- **Source map discovery and use**  
  - Look for `*.js.map`, `sourceMappingURL` in JS.  
  - Fetch and parse; reconstruct readable paths and symbols.  
  - Use them to find: hidden endpoints, debug-only params, dangerous sinks (eval, innerHTML, document.write, postMessage), and strings that look like keys/URLs.

- **API shape extraction from JS**  
  - Parse fetched JS (regex or lightweight AST) for: `fetch(...)`, `axios.(get|post)(...)`, `api.`, `/api/...`, `.get(`, `.post(`.  
  - Build a list of *client-used* endpoints, methods, and body shapes.  
  - Compare to server discovery: endpoints the app calls but we didn’t probe, or params we didn’t fuzz.

- **Dangerous sinks and data flow**  
  - Flag: `eval(`, `new Function(`, `innerHTML`, `document.write`, `insertAdjacentHTML`, `postMessage` handlers, `localStorage`/`sessionStorage` with sensitive keys.  
  - Report: “Dangerous sink with user-influenced input” or “Sensitive key in storage” so the client can prioritize code review.

- **Dependency and version from frontend**  
  - From script `src` (e.g. `react.production.min.js`, `chunk-abc123.js`) or from source maps / `__webpack_require__`, infer framework and ideally version.  
  - Feed into Upgrade 2 (dependency/CVE).

**Deliverable:** A skill (e.g. `client_surface` or extend `high_value_flaws` / `data_leak_risks`) that: discovers and fetches main JS, follows source maps, extracts API shapes and sinks, and outputs structured findings (endpoints to test, sinks to review, possible secrets).

---

## Upgrade 2: Dependency and CVE Awareness

**Goal:** Know what versions the app uses and whether they’re in the “exploit soon” window.

- **Version detection**  
  - From headers (`X-Powered-By`, `Server`), HTML comments, JS filenames, source maps, or known paths (e.g. `/wp-includes/version`, Next.js build id).  
  - Normalize to (product, version) and store in recon output.

- **CVE lookup (offline or API)**  
  - Maintain a small table or use an API (e.g. NVD, OSV) for high-profile stacks: Next.js, React, Node, Django, Laravel, WordPress, etc.  
  - When we detect version X, check if X is in a known-vulnerable range (e.g. React2Shell, recent RCE).  
  - Report: “Detected Next.js X.Y; CVE-XXXX affects this version — verify patch status.”

- **Dependency confusion / private package names**  
  - If we ever see references to internal package names (e.g. in build output or errors), flag the risk of dependency confusion and suggest checking registry scope.

**Deliverable:** Recon or a small “dependency_audit” step that: (1) collects versions from existing recon + JS/source maps, (2) checks them against a curated CVE list or API, (3) adds findings like “Detected [stack] [version]; [CVE] may apply.”

---

## Upgrade 3: Logic and Numeric Bug Hunting

**Goal:** Find “think like an attacker” bugs that aren’t injection or classic IDOR.

- **Numeric edge cases**  
  - For any parameter that looks like amount, quantity, balance, or limit: send `0`, `-1`, `MAX_INT`, `MAX_INT+1`, very large decimal, `NaN`, `Infinity`.  
  - For prices/ratios: try values that could cause rounding to zero or overflow (e.g. 0.1 * 0.2 in different orders).  
  - Report when the server returns success or a different code path (e.g. “Amount accepted as -1” or “Overflow to zero”).

- **State and order of operations**  
  - Model critical flows (e.g. signup → login → create order → pay → cancel).  
  - Send requests out of order: pay before order confirmed; cancel after pay but with a modified refund amount; reuse a one-time token twice.  
  - Already partially there (race_condition); extend to “sequence abuse” and “reuse after invalidate.”

- **Bounds and limits**  
  - For `limit`, `offset`, `per_page`: try `-1`, `0`, `1`, `999999`, and one above stated max.  
  - For “max N items”: send N+1, or N+1 in a batch request.  
  - Report when the server returns more than intended or errors in an exploitable way.

**Deliverable:** Extend `payment_financial` and/or add a “logic_abuse” skill that: (1) identifies amount/quantity/limit params from API discovery and JS, (2) runs numeric and sequence tests, (3) outputs CONFIRMED/POSSIBLE findings with evidence.

---

## Upgrade 4: Chain-Driven Next Tests

**Goal:** Use what we already found to decide what to test next (like an attacker would).

- **Rule-based “if A then try B”**  
  - If we have “verbose error with internal hostname” → ensure we have SSRF probes to that host (or report “SSRF to disclosed host recommended”).  
  - If we have “IDOR on user id” and “JWT in cookie” → suggest “Try substituting user_id in JWT or in request body.”  
  - If we have “GraphQL introspection” → suggest “Run batch/mutation abuse and depth limit tests.”

- **Feed new probes back into the run**  
  - Optional: a second phase that takes “suggested next tests” (endpoints from JS, params from API shape, CVE checks) and runs a limited number of targeted checks.  
  - Report: “Based on findings, we also ran …”

**Deliverable:** Post-processing step (or correlation_engine extension) that: (1) takes normalized findings, (2) runs rules like above to produce “Recommended next tests” and “Potential chain: A + B → C”, (3) optionally runs a small number of those tests and appends results.

---

## Upgrade 5: CVE Speed (React2Shell-Style)

**Goal:** When a critical CVE drops, we can quickly say “your stack may be affected.”

- **Curated watchlist**  
  - Maintain a short list of high-impact products (Next.js, React, Express, Django, Laravel, etc.) and a way to ingest “new CVE for product X, version range Y.”  
  - Could be manual (we add CVE-XXX to a JSON file) or an API (OSV, NVD) filtered by product.

- **In-scan check**  
  - After recon + client_surface, we have (product, version) for the target.  
  - For each, check watchlist: “Next.js 14.0.0–14.0.2 → CVE-2025-XXXX (RCE). Recommend immediate patch check.”

**Deliverable:** Small “CVE watchlist” file or API integration plus a step in the report: “Detected versions” + “Known issues for these versions” with CVE IDs and severity.

---

## Suggested Order of Implementation

1. **Client-side code intelligence (Upgrade 1)** — Biggest gap today; unlocks API shape, sinks, and better dependency detection.  
2. **Dependency and CVE awareness (Upgrade 2 + 5)** — Version detection plus a small CVE/watchlist so we can say “this version may be exploitable.”  
3. **Logic and numeric hunting (Upgrade 3)** — Extend payment_financial and add sequence/bounds tests.  
4. **Chain-driven next tests (Upgrade 4)** — Use existing correlation; add “recommended next tests” and optional second-phase runs.

---

## Summary

To **think like them and find before them** we need to:

- **Read the client:** source maps, JS, API shapes, dangerous sinks, and secrets.  
- **Know the stack:** versions and CVEs so we can flag “exploit soon” targets.  
- **Hunt logic:** numeric edge cases, order-of-operations, and bounds.  
- **Chain and iterate:** use findings to suggest and run the next most valuable tests.

Implementing Upgrades 1 and 2 gives the largest step up: we stop treating the frontend as a black box and we start surfacing dependency risk the same way sophisticated attackers do.
