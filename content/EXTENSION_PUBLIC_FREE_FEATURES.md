# Diverg Extension — Public Free Version: Feature Brainstorm

**Positioning:** The extension is the **free, public-facing** version of Diverg. These are **features for the public extension** — what users see and do in the browser. **Backend can and should support them where it makes sense** (e.g. scan, Simulate, CVE lookup, streaming, session-aware scan). The list below is the extension product roadmap, not “extension-only at all costs.”

**Focus:** Browser-main security — what we can see, measure, and improve from the page and its requests. Market angles: privacy/consent, supply-chain risk, headers & hardening, “am I exposed?” checks, shareable reports.

---

## Tier 1: Extension-led (backend optional)

Extension does the work in-browser; backend can add value later (e.g. CVE API, deeper analysis).

### 1. **Page security snapshot (one-click report)**

- **What:** One click from popup: “Page report.” Extension inspects the **current tab only**: response headers (from last load or a quick HEAD/fetch), scripts (src, integrity, crossorigin), cookies (SameSite, Secure, HttpOnly), forms (action, method), links (external vs same-origin), and obvious client-side leaks (e.g. keys in JS, `data-` attributes with secrets).
- **Output:** Single-page summary: “Headers: Missing X-Frame-Options, Strict-Transport-Security.” “Scripts: 4 from CDN, 0 with SRI.” “Cookies: 2 without Secure.” “Possible leak: `apiKey` in window.” Export as text or copy-friendly markdown.
- **Why:** Instant value. No server, no sign-up. Fits “browser main security process” — we only use what the browser gives us. Great for devs doing a quick self-check.

### 2. **Request/response inspector (last N requests)**

- **What:** Content script or optional service worker captures **requests made by the page** (fetch/XHR). Popup or side panel: list of last 20–50 requests (method, URL, status, size). Click one: view request/response headers and body snippet. Optional: “Copy as cURL” / “Copy as fetch.”
- **Why:** “Who is this page talking to?” and “What did it send?” — core browser security visibility. No backend. Differentiator: built into the same tool as the scan, not a separate proxy.

### 3. **Third-party and cookie map**

- **What:** For the current page: list every **third-party origin** that received cookies or storage (or that the page called). Simple table: Origin | Cookies (names) | Storage keys (if detectable). Flag: “Sent to 3rd party,” “No SameSite,” “Cross-site in iframe.”
- **Why:** Privacy and compliance (GDPR, consent). “Browser main” = we observe what the page does. Market: privacy auditors, front-end leads, compliance checks.

### 4. **Script inventory + CVE hint (client-side)**

- **What:** List every `<script src="...">` (and optionally inline script hashes). For each: origin, filename, optional version from URL or comment. Extension-only CVE hint: open **OSV** or **Snyk** in a new tab with pre-filled query (e.g. “jquery 3.1.1”) or show a “Check CVEs” link that goes to a public CVE/OSV search. No backend — we don’t store or run vuln DB; we just make lookup one click.
- **Why:** Supply-chain risk is hot. We don’t need to run the CVE DB ourselves; we surface “what’s on the page” and link out to authoritative sources.

### 5. **Security headers scorecard**

- **What:** Fetch the current page (or main document) and score **security headers**: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy, etc. Simple grade (A–F) or traffic lights + short recommendation per header. Stored in extension storage per origin; optional “Compare to last time.”
- **Why:** Headers are quick to check and easy to fix. Fits “browser main” (we only need the response). Very shareable: “Our grade is B; here’s the list.”

### 6. **Sensitive string detector (in-page)**

- **What:** Content script scans **visible DOM + inline scripts** for patterns: API keys (e.g. `sk_`, `api_key=`, `apikey`), tokens, passwords in `data-*`, hardcoded secrets in JS. Report: “Possible secret in script at line X” or “Attribute `data-token` on element Y.” No server — regex + allowlist (e.g. Stripe `pk_`, Google Maps key in map context).
- **Why:** Client-side secret exposure is a top finding. Pure browser, no backend; can reuse logic similar to your existing client_surface/public-key allowlist.

---

## Tier 2: Extension + backend

Extension calls Diverg backend (or a free/public endpoint). Backend is part of the public extension story.

### 7. **Quick public scan (no install)**

- **What:** “Scan this site” from the extension sends the URL to a **free, rate-limited** public endpoint (e.g. 1 scan per domain per day). Backend runs a **quick** scope only (headers, basic API test, maybe client_surface). Result shown in extension: findings list + Simulate where applicable. Optional: “Run full scan locally” if user has Diverg API.
- **Why:** Users who don’t run the backend still get a real scan. Converts to “run locally for full power.”

### 8. **Session-aware scan (cookies to backend)**

- **What:** “Scan as logged-in user.” Extension sends **current tab cookies** (or selected ones) with the scan request. Backend runs the same scan but with that session (e.g. for IDOR, private endpoints). Extension UI: “Include cookies from this tab” checkbox; optional “Scan as guest” vs “Scan as me.”
- **Why:** Most value is behind login. This is the “browser main” idea: the browser has the session; we just pass it once for the scan.

### 9. **Streaming scan progress in UI**

- **What:** Extension already has `POST /api/scan/stream`. Use it: show live “Running: Headers → API test → …” and append findings as they arrive. Feels responsive and “pro.”
- **Why:** You have the endpoint; the free extension should use it when the user points to their own API.

---

## Tier 3: Differentiators (extension + backend)

Strong differentiators that need more product/backend work. Good next phase after Tier 1–2.

### 10. **Passive observatory (background watch)**

- **What:** As the user browses, extension records (locally): origins loaded, scripts, cookies set, requests to metadata/internal IPs. No “Scan” click. Dashboard: “Sites today: 12, issues: 2” (e.g. “Request to 169.254.x.x,” “Script with no SRI”). Optional: export “today’s map” as JSON.
- **Why:** Continuous visibility instead of one-shot. Fits “browser main” — we only observe what the browser does. Market: “See what your browser is really doing.”

### 11. **Replay / IDOR from request list**

- **What:** From the “last N requests” list, user selects a request. “Replay with change”: e.g. change `user_id` to another value, send, show response. Essentially “Simulate” but driven from **captured** traffic instead of scan findings. Can call existing `POST /api/poc/simulate` with the modified URL/params.
- **Why:** Proof in the browser: “I changed the ID and got different data.” Fits request capture + existing PoC API.

### 12. **Export and share (report link)**

- **What:** “Share this report” generates a **read-only link** (or a static HTML/JSON export). Link could be time-limited, no-auth view of findings + summary (no cookies, no secrets). Devs share with teammates or auditors; “run this scan and share the link.”
- **Why:** Collaboration and compliance without building a full workspace. Sticks to “we ran a scan in the browser; here’s the result.”

### 13. **Compliance tags (mapping)**

- **What:** For each finding, show a tag: “PCI-DSS”, “SOC 2”, “GDPR”, etc. (from a static mapping category/severity → framework). Filter view: “Show only GDPR-relevant.” Export: “Compliance checklist” for this scan. Backend can hold the mapping; extension just displays and filters.
- **Why:** “Browser main” = we present the scan result in a way that fits how compliance is talked about. Market: teams preparing for audits.

---

## Suggested order (ship fast, stay browser-first)

| Priority | Feature | Tier | Rationale |
|----------|---------|------|------------|
| 1 | Page security snapshot | 1 | No backend, instant value, defines “free” |
| 2 | Security headers scorecard | 1 | Easy, shareable, clear grade |
| 3 | Script inventory + CVE link | 1 | Supply-chain angle, extension-only |
| 4 | Request inspector (last N) | 1 | Foundation for replay; no backend |
| 5 | Streaming scan in UI | 2 | You have the API; better UX |
| 6 | Session-aware scan | 2 | Unlocks “behind login” value |
| 7 | Third-party / cookie map | 1 | Privacy/compliance, browser-only |
| 8 | Sensitive string detector | 1 | High-impact, client-side only |
| 9 | Replay from request list | 3 | Uses request capture + PoC API |
| 10 | Export / share report | 3 | Growth and teamwork |

---

## One-line pitch for the free extension

**“See your page’s security in one click — headers, scripts, cookies, and leaks — then run a real scan and prove findings with Simulate. All from the browser.”**

Sticking to **browser main security process** means: we prioritize what the extension can do with the current tab and its requests. Backend supports scan, Simulate, streaming, session-aware scan, and any future APIs (CVE, compliance, share). The public extension is the product; the backend is there to make it powerful.
