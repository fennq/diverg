# Next Set of Features for the Diverg Extension

---

## What’s real vs what’s proposed

- **Already in the extension (today):** Scan current tab (Quick / Full / Option scan), “Scan for” goal, options, in-browser fallback if API is down. Results show findings, summary, etc.
- **Already in the API/backend:** Full scan, goal-based scan, streaming, scope (full/quick/crypto), site_classification, exploit_ref (exploitation + remediation), **Live PoC / Simulate** (POST /api/poc/simulate — see content/API_POC_SIMULATE.md).
- **Everything else in this doc is proposed.** Live PoC backend is implemented; the extension still needs to add the “Simulate” button and call the API. The “THE BAR” features below are **not built yet** — they’re ideas for what to build next. The “Incremental features” section is also a list of possible next steps, not things that already exist.

So: **you did NOT include these in the extension yet.** This file is a roadmap / feature list, not a changelog.

---

# THE BAR: Features that actually define the product (PROPOSED)

These aren’t “add a button” — they’re ideas for things that would make people choose this extension over everything else. **None of these are implemented yet.** Some need backend; some could be extension-only.

---

## 1. **Passive live scanning (always-on observatory)**

- **What:** As you browse, the extension watches in the background: every request, every script, every cookie, every form. No “Scan” click. It builds a live map: “This page called 12 origins, 3 have no CORS, 2 scripts have known CVEs, 1 request sent auth cookie to a third party.” Dashboard: “Sites visited today: 8, issues observed: 4” with one-click drill-down. Alerts in real time: “Request to cloud metadata IP detected — possible SSRF.”
- **Why:** Scans are a snapshot. Real risk is “what happens while we use the app.” This turns the extension into a **continuous** sensor, not a one-shot tool.
- **Build:** Content script + optional service worker; capture fetch/XHR (and/or use devtools protocol if possible). Send telemetry to your API or process locally; store “observed issues” per origin. Heavy but product-defining.

---

## 2. **Request capture, modify, replay (Burp in the browser)**

- **What:** Capture every request the page makes. List view: method, URL, status, size. Click one: see headers, body, response. **Edit** (change `user_id`, add header, change body) and **Replay**. “Replay with different ID” becomes one click — instant IDOR check. Optional: “Replay all with user_id=victim” to batch-test. Export to Burp/curl.
- **Why:** Findings are hypotheses. **Proof** is “we changed the ID and got someone else’s data.” This turns the extension into a real testing tool, not just a report generator.
- **Build:** Intercept fetch/XHR (e.g. service worker or proxy in extension). Store last N requests per tab. Replay via fetch from extension. No backend required for core; optional “send to API for analysis.”

---

## 3. **Scan as the logged-in user (session-aware scan)**

- **What:** “Scan this tab” uses the **current tab’s cookies and session**. The backend (or in-page runner) runs the scan in a context that’s already logged in. So you’re testing the **authenticated** surface: private APIs, user-specific IDOR, payment flows, admin actions. Option: “Scan as guest” vs “Scan as me.”
- **Why:** 90% of scanners only see the public surface. The real bugs are behind login. This is the only way to find “change user_id in /api/me/orders and get another user’s orders.”
- **Build:** Extension passes cookies (or a session cookie) to the API; backend runs requests with that session. Or: run a lightweight scan **in the page** (same-origin) using the existing session and send results to API for merge. Backend must support “scan with this cookie.”

---

## 4. **Live PoC / simulate (proof, not “might be”)**

- **What:** For each finding, a **“Simulate”** or **“Run PoC”** button. For IDOR: send the same request with a different ID and show “Got 200 with other user’s data” or “403 Forbidden.” For XSS: render payload in a sandboxed iframe and show “Executed” or “Blocked by CSP.” For open redirect: show “Redirected to evil.com.” One-click proof that the finding is real (or a false positive).
- **Why:** Reports get ignored because “we’re not sure it’s exploitable.” Proof gets fixed. This closes the gap between “we found something” and “we showed it.”
- **Build:** Extension or API generates minimal PoC (modified request, or iframe with payload). Run from extension (same-origin or CORS) or from backend; show result in UI. Needs PoC templates per finding type.

---

## 5. **AI attack plan (what to exploit first)**

- **What:** After a scan, one click: **“Generate attack plan.”** Input: the full report (and optionally “this app has payment flow” or “this is an admin panel”). Output: ordered list: “1. Exploit the IDOR on /api/orders to dump orders. 2. Use the leaked token in the next request to hit /admin. 3. …” With reasoning: “IDOR first because it’s unauthenticated and leads to data.” Optional: “Is this finding a false positive?” with short reasoning.
- **Why:** 40 findings → “where do I start?” AI turns the report into an **action plan** that a human would follow. That’s differentiation no other scanner gives.
- **Build:** Backend endpoint: POST report + optional context; LLM returns structured plan (or “false positive?”). Extension displays it. Needs good prompting and maybe structured output (JSON).

---

## 6. **Attack surface map (visual graph, not a list)**

- **What:** One view: **graph** of the attack surface. Nodes: domains, subdomains, API endpoints, scripts, cookies, storage keys. Edges: “calls,” “sets cookie,” “reads storage.” Click a node: “Scan this,” “Replay requests,” “Findings here.” Color by risk (e.g. red = has Critical). Zoom and filter. Export as image or graph JSON.
- **Why:** A list of findings doesn’t show **where** things connect. A map shows “this script runs on every page and has access to the auth cookie” and “this API is called from 5 pages.” That’s how attackers think.
- **Build:** Feed: recon data (subdomains), client_surface (endpoints, scripts), scan results (findings per URL). Extension (or backend) builds graph; render with D3/Cytoscape/vis.js. Optional: live-update from passive scanning.

---

## 7. **Compliance / framework mapping**

- **What:** Map every finding to **PCI-DSS**, **SOC 2**, **ISO 27001**, **GDPR** (e.g. “PII exposure”). View: “PCI-relevant: 4 findings,” “SOC 2: 12,” “GDPR: 2.” Export: “Compliance checklist” for auditors (finding + control + status). Optional: “You’re missing these controls for SOC 2.”
- **Why:** Sec teams don’t buy “we found 30 issues.” They buy “we’re ready for the audit” or “we’re not, and here’s the gap.” This turns the scanner into an **audit** product.
- **Build:** Backend or static mapping: category/severity/CWE → framework control IDs. Extension shows filters and export. Requires a small compliance taxonomy.

---

## 8. **Supply chain / dependency risk**

- **What:** For every script on the page (CDN, npm bundle): show **name, version, known CVEs** (from CVE DB or OSV), **license**, and **permissions**: “This script can read cookies,” “This script can read localStorage.” Graph: “Page loads A → A loads B → B has CVE-2024-xxx.” One click: “Scan this script’s origin.”
- **Why:** Most risk is in the stack, not your code. “jQuery 1.8 on this page has 3 known CVEs and can access your auth cookie” is a single, actionable sentence.
- **Build:** Content script: enumerate scripts, get src/origin; optional source map or package name inference. Backend or extension: CVE lookup by name/version; permission model from browser (cookie/store access per origin). Extension UI: list or graph per page.

---

## 9. **Block deploy until clean (CI integration)**

- **What:** Integration with **Vercel**, **Netlify**, **GitHub Actions**, or generic webhook: “If the last scan for this URL has Critical or High, **fail the deploy** (or block merge).” Dashboard: “Last scan: 2 Critical — deploy blocked.” Optional: “Allow list” (e.g. these 2 findings are accepted).
- **Why:** The only way to enforce “don’t ship with Critical” is to make the pipeline **block**. Everything else is advisory.
- **Build:** Backend: store last scan result per “project” (e.g. URL or repo id). CI calls “GET /api/scan/status?url=…” or webhook receives “deploy started”; respond with pass/fail. Extension can show “Deploy status: blocked (2 Critical).”

---

## 10. **Team workspace (shared project, shared findings)**

- **What:** “Workspace” = base URL + scope. Team joins (invite link or code). Every member’s scans **merge** into one view: “Findings” (deduped), “Who found it,” “Status: Open / Fixed / Accepted,” “Assigned to.” Activity: “Alice ran a scan; 2 new. Bob marked #12 Fixed.” Comments on findings. Export: “Audit log for this project.”
- **Why:** Security is a team sport. One person’s scan is a snapshot; a shared workspace is **continuous** and **accountable**. That’s how consultancies and internal teams actually work.
- **Build:** Backend: projects, members, scan ingestion, finding merge, status, comments. Extension: “Current workspace,” “Upload scan to project,” “View project findings.” Significant backend.

---

## 11. **Time-travel: replay session with security checks**

- **What:** **Record** a session: every click, form submit, navigation, request (optionally response). “Replay” that session with security instrumentation: at each request, also run IDOR probe, param tampering, etc. Report: “During this flow we found 2 additional issues.” So you’re testing the **exact** flow the user did, not a generic crawl.
- **Why:** Crawlers miss flows that require specific steps (e.g. “add to cart, apply coupon, checkout”). Replay uses real usage as the test plan.
- **Build:** Extension records events (and optionally requests) in a buffer. “Replay” = send recording to backend; backend simulates or replays with probes. Or: extension replays in page and sends new requests to API for analysis. Complex but unique.

---

## 12. **Benchmark / “how you compare”**

- **What:** Anonymous benchmark: “We’ve scanned 10k sites. Your site is in the **top 15%** for security (fewer Critical/High per domain).” Or: “Sites with your tech stack (React, Stripe) average 6 findings; you have 9.” Optional: “Industry: e-commerce — you’re better than 60%.” Gamification + FOMO.
- **Why:** Execs and product people care about “are we good?” A number and a percentile answer that. Also drives adoption (“I want to get to top 10%”).
- **Build:** Backend: store anonymized stats (domain hash, severity counts, stack). Aggregate by segment (optional). Extension: “Your rank” and “Similar sites” from API. Needs privacy-safe design.

---

## Summary: the bar

| # | Feature | One-line | Backend? |
|---|---------|----------|----------|
| 1 | Passive live scanning | Always-on observatory as you browse | Yes (or heavy extension) |
| 2 | Request capture/replay | Burp in the browser — modify & replay for proof | No (extension-led) |
| 3 | Session-aware scan | Scan with your cookies = test behind login | Yes |
| 4 | Live PoC / simulate | One-click proof per finding | **Done (API); extension needs button** |
| 5 | AI attack plan | “What to exploit first” from the report | Yes (LLM) |
| 6 | Attack surface map | Visual graph of domains/APIs/scripts/risk | Yes or extension |
| 7 | Compliance mapping | PCI/SOC2/ISO/GDPR per finding + export | Taxonomy + export |
| 8 | Supply chain / deps | CVEs + permissions per script on page | CVE API + extension |
| 9 | Block deploy | CI fails if Critical/High | Yes |
| 10 | Team workspace | Shared project, merged findings, status, comments | Yes (big) |
| 11 | Time-travel replay | Replay recorded session with security probes | Yes |
| 12 | Benchmark | “You’re in top 15%” / “vs similar sites” | Yes (anon stats) |

**Highest leverage with least backend:** 2 (capture/replay), 4 (PoC), 8 (supply chain in extension). **Biggest product shift:** 1 (passive), 3 (session scan), 5 (AI plan), 10 (team).

---

## Plain-English summary (what each feature actually is)

| # | In one sentence |
|---|------------------|
| **1. Passive live scanning** | The extension watches what the page does in the background (requests, scripts, cookies) and builds a live “risk map” and can alert you — no need to click “Scan.” |
| **2. Request capture / replay** | Like Burp Suite in the browser: see every request the page makes, change something (e.g. user ID), send it again, and see if you get someone else’s data (instant IDOR check). |
| **3. Scan as logged-in user** | When you click “Scan,” it uses the cookies from your current tab so the scan runs *while logged in* and finds bugs on private/authenticated pages, not just the login page. |
| **4. Live PoC / simulate** | For each finding, a “Prove it” button: the tool actually runs a tiny attack (e.g. request with another user’s ID) and shows “Yes, we got other user’s data” or “No, it was blocked.” **Backend done:** POST /api/poc/simulate (see API_POC_SIMULATE.md). Extension: add button + call API. |
| **5. AI attack plan** | You get a list of 40 findings; you click “Give me an attack plan” and the AI says: “Do this IDOR first, then use that to hit the admin API,” in order, with short reasons. |
| **6. Attack surface map** | A diagram: boxes for domains, APIs, scripts, cookies; lines for “calls” or “has access to”; red/green by risk. Click a box to scan it or see findings. |
| **7. Compliance mapping** | Each finding is tagged with “PCI-DSS 6.x” or “SOC 2 CC6.1” etc., and you can export a list for auditors (“here’s what we have for PCI”). |
| **8. Supply chain / deps** | For every script on the page (e.g. jQuery, React from CDN): show version, known CVEs, and “this script can read your cookies” — so you see third-party risk. |
| **9. Block deploy** | Connect to your host (e.g. Vercel) or CI: if the last scan found Critical or High, the deploy fails. So you can’t ship until those are fixed. |
| **10. Team workspace** | You and your team share one “project” (e.g. example.com). Everyone’s scans go into one list; you can mark “Fixed,” “Accepted,” assign to someone, add comments. |
| **11. Time-travel replay** | Extension records what you did (clicks, form submits). You click “Replay with security checks” and it runs that same flow again but probes for IDOR etc. at each step. |
| **12. Benchmark** | After a scan it says something like “Your site is in the top 15% of sites we’ve seen” or “Sites like yours usually have 6 issues; you have 9” — anonymous comparison. |

---

# Incremental features (existing list)

*Below: smaller improvements that still matter but don’t redefine the product.*

---

## 1. **Results: show exploitation + patch (use existing API)**

- **What:** In the results view, for each finding show:
  - **How someone could use it** — from `finding.exploit_ref.exploitation` (or impact if no ref).
  - **How to patch it** — from `finding.remediation` or `finding.exploit_ref.prevention`.
- **Why:** Users asked for both “how could an attacker use the loophole” and “how can the company patch it”; the API already returns this.
- **Implementation:** Expandable section per finding: “Impact / exploitation” and “Remediation / patch”. Optional: OWASP/CWE badges from `exploit_ref`.

---

## 2. **Site classification badge (crypto vs non-crypto)**

- **What:** After a scan, show a clear badge or line: “Site classified as **crypto/DeFi**” or “Site not classified as crypto,” with optional tooltip: “Chain validation checks ran because …” using `site_classification.chain_validation_abuse_reason`.
- **Why:** Users want to see whether we treated the site as crypto and why the extra (Injective-style) checks ran or didn’t.
- **API:** `report.site_classification`: `is_crypto`, `confidence`, `chain_validation_abuse_ran`, `chain_validation_abuse_reason`.

---

## 3. **Streaming progress in the popup (use /api/scan/stream)**

- **What:** During a scan, show live progress: “Running headers_ssl…”, “headers_ssl: 5 findings”, then “Running api_test…”, etc., and finally the full results.
- **Why:** Better UX than a long silent wait; matches the streaming API we already have.
- **API:** `POST /api/scan/stream` with NDJSON: `skill_start`, `skill_done`, `done` (see `content/API_STREAM_AND_GOAL.md`).
- **Implementation:** Use `fetch` + `ReadableStream` and parse line-by-line; update popup or results page on each event.

---

## 4. **Scope selector: Full vs Quick vs Crypto**

- **What:** Let the user pick scan scope in the popup (e.g. dropdown or chips): **Full**, **Quick**, **Crypto** (and optionally **Option scan** with “Scan for” goal as today).
- **Why:** Full is heavy; Quick is fast triage; Crypto adds chain/batch validation when the user knows the site is DeFi/crypto.
- **API:** Optional `scope` in request body is supported: `{"url": "...", "goal": "...", "scope": "full"|"quick"|"crypto"|"recon"|"web"|"api"|"passive"}`. Default is `full`.

---

## 5. **Export report (JSON / PDF or markdown)**

- **What:** Button in results: “Export report” → download JSON (full API response) and/or a readable format (e.g. markdown or PDF) with summary, findings, exploitation, and remediation.
- **Why:** Users need to share or archive reports; JSON is already there; a simple text/md export is easy to add in the extension.

---

## 6. **Scan history (last N scans)**

- **What:** Store the last 5–10 scan results in `chrome.storage.local` (or similar): target URL, timestamp, summary (e.g. total/critical/high counts), and link to “View” (or re-open the same report).
- **Why:** Quick access to recent scans without re-running.
- **Implementation:** On `done` event, save a compact record; options page or popup can list “Recent scans” with a “View” action.

---

## 7. **RAG citations in the UI**

- **What:** If a finding has `citations[]`, show a “Sources” or “Learn more” expandable section with the cited chunks (exploit catalog, prevention docs).
- **Why:** API already attaches citations when RAG is enabled; the extension can surface them for deeper context.
- **API:** `finding.citations` (array of text or refs).

---

## 8. **Configurable API base URL**

- **What:** Options page: “API URL” (default `http://127.0.0.1:5000`) so the extension can talk to a different host/port (e.g. staging or a deployed Diverg API).
- **Why:** Flexibility for different setups without repackaging the extension.

---

## 9. **“Scan for” presets for Option scan**

- **What:** In addition to a free-text “Scan for” goal, offer preset chips or a dropdown: e.g. “Payment bypass”, “Headers & SSL”, “Auth & API”, “Crypto audit”, “Full audit”. Selecting one sets the goal sent to the API.
- **Why:** Faster and more consistent than typing; aligns with `intent_skills` phrases (payment bypass, headers, auth, crypto audit, etc.).

---

## 10. **Severity filter and sort in results**

- **What:** In the findings list: filter by severity (Critical, High, Medium, Low, Info) and sort by severity or by title/URL.
- **Why:** Long reports are easier to triage; focus on Critical/High first.

---

## Summary table

| # | Feature | Depends on API change? | Effort (extension-side) |
|---|--------|------------------------|--------------------------|
| 1 | Exploitation + patch in results | No | Low |
| 2 | Site classification badge | No | Low |
| 3 | Streaming progress | No | Medium |
| 4 | Scope selector (Full/Quick/Crypto) | No (API supports `scope`) | Low |
| 5 | Export report (JSON / md) | No | Low–Medium |
| 6 | Scan history (last N) | No | Medium |
| 7 | RAG citations in UI | No | Low |
| 8 | Configurable API URL | No | Low |
| 9 | “Scan for” presets | No | Low |
| 10 | Severity filter/sort | No | Low |

**Recommended first batch:** 1 (exploitation + patch), 2 (site classification), 3 (streaming progress), 4 (scope selector). Then 5 and 6 for export and history.

---

# Next-level features (differentiate, don’t just polish)

These turn the extension into a real workflow tool and make it clearly better than “generic scanner UI.”

---

## A. **Scan diff — compare two runs**

- **What:** “Compare with previous scan” (or “Compare with …” and pick from history). Side-by-side or unified diff: **New findings**, **Fixed** (in previous but not this run), **Unchanged**. Summary: “+3 new, −2 fixed, 8 unchanged.”
- **Why:** Answers “what changed since last week?” and “did they fix the IDOR?” without re-reading the whole report.
- **Implementation:** Store last N full reports (or at least finding keys per URL). Diff by (title, url, category) or by a stable finding id if we add one. Extension-only; no API change.

---

## B. **Attack path view**

- **What:** Dedicated tab or section: “Attack paths” — show chains like “Unauthenticated endpoint → IDOR → Sensitive data” or “Missing HSTS → Session hijack → Admin.” Each step links to the finding(s). If the API ever returns `attack_paths` (from correlation), render them; otherwise infer simple chains from finding categories (e.g. “Access Control” → “Injection” → “Data”).
- **Why:** One picture of “how an attacker would chain these” beats a flat list of 40 findings.
- **API:** Optional: backend could add `attack_paths` to the report (or use existing attack_paths skill output if we merge it into run_web_scan).

---

## C. **Create ticket from finding**

- **What:** On each finding: “Create Jira” / “Create Linear” / “Create GitHub issue” (or “Copy as ticket”). Opens a pre-filled form or template: **Title** = finding title, **Description** = evidence + impact + exploitation (if any), **Remediation** = remediation/prevention, **Labels** = severity, category. Optional: deep link to Jira/Linear/GH with body pre-filled (URL params or their API).
- **Why:** Removes the copy-paste gap between “we found it” and “dev has a ticket.”
- **Implementation:** Template in extension; optional OAuth or API key in options for one-click create. At minimum: “Copy as markdown” that pastes straight into GH/Jira.

---

## D. **Scheduled / recurring scans**

- **What:** Options: “Scan this URL every [day|week].” Extension (or a small companion script) runs the scan at that cadence and notifies (e.g. badge count, or “New findings” notification). Store results with timestamp; “Scan history” becomes a timeline.
- **Why:** Continuous assurance instead of one-off; catch regressions and new issues.
- **Implementation:** Chrome alarms API or a background script; respect rate limits and “don’t run when browser closed” (or document “keep browser open” / use external cron hitting API).

---

## E. **Right-click: “Scan this link” / “Scan this domain”**

- **What:** Context menu on any link or page: “Diverg: Scan this URL” and “Diverg: Scan this domain” (root origin). Starts scan with current scope/goal; opens or focuses results when done.
- **Why:** Scan without copying URL into the popup; natural for power users.
- **Implementation:** `chrome.contextMenus`; pass URL to same scan flow.

---

## F. **Full results page (not just popup)**

- **What:** “Open full report” opens a dedicated tab or extension page: **Summary** (grade, counts, site classification), **Findings** (filter, sort, search, expand all), **Attack paths**, **Export**, **Compare**, **History**. Popup stays minimal: “Scan” + “Last result” + “Open full report.”
- **Why:** Popup is too small for 30+ findings; a full page makes export, diff, and triage actually usable.
- **Implementation:** `chrome.tabs.create` or `chrome.extension.getURL('results.html')` with report passed via `chrome.storage` or URL state.

---

## G. **Security grade / risk score**

- **What:** Single headline: “Grade: B” or “Risk: Medium” (or 0–100 score) from severity mix (e.g. Critical = −25, High = −15, Medium = −5; cap at 100). Optional: “Critical issues must be fixed before we consider this safe.”
- **Why:** Execs and non-sec people want one number; helps compare before/after (e.g. “was C, now B”).
- **Implementation:** Extension-only formula; optional: backend could return `grade` or `risk_score` for consistency.

---

## H. **Export to SARIF**

- **What:** “Export as SARIF” → download a SARIF 2.1 file so the report can be ingested by GitHub Code Scanning, Azure DevOps, or any SARIF viewer. Map findings to `result` with `ruleId`, `message`, `level`, `locations`, and optional `fixes`.
- **Why:** Fits into existing DevOps pipelines and gives a second life to the report in the tooling teams already use.
- **Implementation:** Extension builds SARIF from report; optional backend endpoint that returns SARIF if we want one source of truth.

---

## I. **“Explain this finding” / plain-English summary**

- **What:** Per finding: “Explain like I’m not a security person” — short paragraph: what it is, why it matters, one sentence on how to fix. Could be client-side (template by category) or a small LLM call (extension sends title + evidence to your API that returns 2–3 sentences).
- **Why:** Devs and PMs often ignore findings because they don’t understand them; plain English increases fix rate.
- **API:** Optional: `POST /api/explain` with `finding` body, return `summary`; or extension-only templates.

---

## J. **Batch scan: all links on this page**

- **What:** “Scan all links on this page” (with cap, e.g. 10 or 20). Queue same-origin or user-selected links; run Quick scan on each; show table: URL, grade, critical count, “View” link. Optional: “Only links to same domain.”
- **Why:** Quick map of “which of our pages are worst?” without manually scanning each.
- **Implementation:** Content script or popup parses links; loop over `/api/scan` with `scope=quick`; show progress and aggregate table. Rate limit to avoid hammering API.

---

## K. **Baseline / “mark as accepted”**

- **What:** “Set as baseline” on current report. Future scans for same URL compare against baseline: only show **New** and **Fixed**; optionally hide “Unchanged” or show count. “Accepted risks” list: user can mark findings as “Accepted” (e.g. known false positive or accepted risk); they’re filtered or greyed out next time.
- **Why:** Stops the “we already know about that” noise and focuses on what actually changed or is new.
- **Implementation:** Extension stores baseline and accepted IDs per URL; diff logic same as scan diff.

---

## L. **Webhook / notification on scan done**

- **What:** Options: “Webhook URL” (and optional secret). When a scan finishes, extension (or backend) POSTs a minimal payload: `url`, `summary`, `critical_count`, `report_url` (if we have one). Use for Slack/Discord/Teams or internal dashboards.
- **Why:** Automate “tell the channel when the nightly scan is done” or “alert when critical &gt; 0.”
- **API:** Optional: backend sends webhook; or extension sends from client (CORS may require backend proxy).

---

## M. **Keyboard shortcut**

- **What:** “Scan current tab” on e.g. `Ctrl+Shift+S` (or `Cmd+Shift+S`). No popup needed; start scan, show badge, open full report when done (or on second press).
- **Why:** Power users live on keyboards.
- **Implementation:** `chrome.commands` in manifest.

---

## N. **Subdomain “Scan this” from recon**

- **What:** If the backend ever returns a list of discovered subdomains (from recon/OSINT), show them in the report with “Scan this” next to each. One click = new scan for that subdomain. Optional: “Scan all” (queue Quick scans).
- **Why:** Recon is useless if you can’t act on it; this closes the loop.
- **API:** Requires report to include `subdomains` or similar from recon skill.

---

## O. **Dark / light theme + density**

- **What:** Options: Theme (dark / light / system) and list density (compact / comfortable). Apply to popup and full results page.
- **Why:** Comfort for long triage sessions; matches IDE/dashboard expectations.

---

## P. **Search across findings**

- **What:** Search box in findings list: full-text search over title, evidence, category, remediation. Highlight matches; filter list to matching findings.
- **Why:** “Do we have anything about CORS?” → instant filter.
- **Implementation:** Client-side; no API change.

---

## Q. **Copy finding as formatted text**

- **What:** “Copy” on a finding → clipboard gets markdown or plain text: title, severity, URL, evidence, impact, exploitation (if any), remediation. So you can paste into Slack, email, or ticket in one go.
- **Why:** Faster than “expand all, select, copy.”
- **Implementation:** Extension-only; template from finding object.

---

## R. **Crypto-specific: “Injective-style checks” summary**

- **What:** When `site_classification.is_crypto` and chain_validation_abuse ran, show a small card: “Injective-style batch/validation checks ran (100+ routes).” Link to a short doc or in-app blurb: “We looked for batch-vs-single path gaps and account_id substitution.”
- **Why:** Makes the crypto/chain value prop visible instead of buried in “skills_run.”
- **Implementation:** Extension-only; link to `content/injective-style-exploit-routes.md` or hosted copy.

---

## Summary: next-level

| Feature | Impact | Effort |
|--------|--------|--------|
| A. Scan diff | High | Medium |
| B. Attack path view | High | Medium |
| C. Create ticket from finding | High | Medium |
| D. Scheduled scans | High | High |
| E. Right-click scan | Medium | Low |
| F. Full results page | High | Medium |
| G. Security grade | Medium | Low |
| H. SARIF export | High (for DevOps) | Medium |
| I. Explain finding | Medium | Low–Medium |
| J. Batch scan links | High | Medium |
| K. Baseline / accepted | High | Medium |
| L. Webhook on done | Medium | Low–Medium |
| M. Keyboard shortcut | Low | Low |
| N. Subdomain “Scan this” | Medium | Low (+ API) |
| O. Theme + density | Low | Low |
| P. Search findings | Medium | Low |
| Q. Copy finding formatted | Medium | Low |
| R. Crypto Injective card | Medium | Low |

**Strong first picks from this list:** A (diff), B (attack paths), C (create ticket), F (full results page), J (batch scan links), K (baseline). Then H (SARIF), D (scheduled), L (webhook) when you want pipeline and automation.
