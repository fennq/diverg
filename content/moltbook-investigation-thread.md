# Moltbook investigation board — 7-tweet thread copy

Use each block with the matching panel from `moltbook-investigation-board.html` (screenshot board 1–7 in order).  
Image size: 1200×628px per panel. Colors match the blue logo palette (#58a6ff, #0f1419, #1c2128).

---

## Thread 1 — Case file (board 1)

**Tweet 1 (attach board 1):**

We ran a deep-audit security assessment on Moltbook. Here’s the investigation board — 7 threads on what we found and how it puts their users at risk. Subject: moltbook.com (Proxy Protection LLC, DreamHost). Subdomains: www + cdrcb.com.moltbook.com. Stack: Cloudflare, AWS CloudFront, Next.js, React. DNSSEC unsigned. 🧵

---

## Thread 2 — Exposed surfaces (board 2)

**Tweet 2 (attach board 2):**

2/ Exposed surfaces. /admin and /dashboard return 200 with full HTML to the internet — no auth enforced at the HTTP layer. /phpMyAdmin/ path exists (308). /health returns {"status":"OK"} publicly. /app.config and /log/production.log exist (403); one misconfig away from config or log leak. Impact: unauthorized access, credential attacks, sensitive workflow exposure.

---

## Thread 3 — Weak crypto (board 3)

**Tweet 3 (attach board 3):**

3/ Weak crypto. Frontend uses Math.random() in two JS chunks (785528a67640bd6e.js, b236f1f448afb5e0.js). It’s predictable, not cryptographically secure. If that touches tokens, session IDs, or nonces → predictable values → session hijack, token forgery, account takeover. Remediation: use crypto.getRandomValues() for any security-sensitive randomness.

---

## Thread 4 — Secret in bundle (board 4)

**Tweet 4 (attach board 4):**

4/ Possible secret in the bundle. We flagged a SECRET-like pattern in shipped JavaScript (785528a67640bd6e.js). If it’s a real credential or token, anyone who loads the page can extract it — API abuse, impersonation, or backdoor-style access to user data. Impact: account takeover, data breach, financial loss. Needs manual verification. Remove secrets from client-side code.

---

## Thread 5 — Client-side vectors (board 5)

**Tweet 5 (attach board 5):**

5/ Client-side vectors. innerHTML sinks in 694aaced0024becc.js and 785528a67640bd6e.js → XSS if user/3rd-party data reaches sink. postMessage listeners in multiple chunks — origin validation not confirmed → cross-origin data theft or injection. CSP allows googletagmanager.com → supply-chain/exfil risk. Session theft, form exfil, phishing. Validate event.origin; sanitize innerHTML.

---

## Thread 6 — Data leak & APIs (board 6)

**Tweet 6 (attach board 6):**

6/ Info leak + user APIs. Request to /api/user/../../../etc/passwd returned 404 but response matched internal/stack/path pattern — attackers learn stack. Client exposes /api/v1/auth/me, activity/recent, homepage, observers, posts. Any IDOR or auth flaw here = one user’s data or account exposed. Server/X-Powered-By leak CloudFront and Next.js. Return generic errors; test auth on all these endpoints.

---

## Thread 7 — Verdict (board 7)

**Tweet 7 (attach board 7):**

7/ Verdict: the setup creates user exploitation risk. Weak crypto → session/token prediction. Possible secret in frontend → backdoor/API abuse. Exposed admin/dashboard → unauthorized access. phpMyAdmin/config/log paths → one misconfig from full exposure. innerHTML + postMessage + GTM → XSS, cross-origin theft, supply-chain exfil. Verbose errors + API surface → faster targeting. Not proof of intent — conditions are there. Lock it down.

---

## Shorter variant (under 280 chars per tweet)

Use if you need to stay within Twitter’s single-tweet limit.

1. Deep-audit on Moltbook — investigation board in 7 threads. moltbook.com, Proxy Protection LLC. Subdomains: www + cdrcb.com.moltbook.com. Cloudflare, AWS, Next.js, React. 🧵

2. /admin + /dashboard → 200 public. /phpMyAdmin/ path exists. /health public. /app.config + /log/production.log exist (403). One misconfig from full exposure. Unauthorized access + credential attack risk.

3. Math.random() in 2 frontend JS chunks. Predictable → session/token prediction → hijack, account takeover. Use crypto.getRandomValues() for anything security-sensitive.

4. SECRET-like pattern in shipped JS (785528a67640bd6e.js). If real credential → anyone can extract → backdoor-style abuse, data breach. Verify manually; remove secrets from frontend.

5. innerHTML sinks (XSS). postMessage without confirmed origin check (cross-origin theft). GTM in CSP (supply-chain risk). Session theft, form exfil, phishing. Validate origin; sanitize.

6. Verbose error on path traversal → stack/path leak. APIs: auth/me, activity/recent, observers, posts. IDOR/auth flaw = user data exposed. Generic errors; test auth on all endpoints.

7. Verdict: user exploitation risk — weak crypto, possible secret, exposed admin, dangerous client patterns, verbose errors. Lock down admin, remove secrets, fix crypto + origin checks.
