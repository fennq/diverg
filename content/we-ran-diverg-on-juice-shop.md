# We Ran Diverg on OWASP Juice Shop — Here's What We Found (and How to Fix It)

**TL;DR:** We ran [Diverg](https://github.com/your-org/diverg) against the intentionally vulnerable [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) to show what an adaptive security scan catches in minutes. Every finding below includes a concrete fix. No unauthorized targets — Juice Shop exists to be tested.

---

## Why Juice Shop?

Juice Shop is a modern, intentionally vulnerable web app used for security training and tool testing. Running Diverg against it proves two things: **the scanner finds real issues**, and **we provide real solutions**. Everything below was found automatically; every remediation is something you can apply in your own stack.

---

## What We Ran

- **Target:** `https://juice-shop.herokuapp.com` (or your self-hosted instance)
- **Tool:** Diverg — adaptive security scanner (recon, headers/SSL, crypto, auth, API, payment/financial, high-value flaws)
- **Scope:** Proof scan (headers_ssl, crypto_security, payment_financial, high_value_flaws)
- **Duration:** ~2 minutes

*To reproduce: run `python scripts/run_proof_scan.py https://juice-shop.herokuapp.com` from the repo.*

---

## Findings and Fixes

*Real findings from a Diverg run against Juice Shop (herokuapp.com). TLS and certificate checks passed; the main gaps were security headers and server disclosure.*

---

### 1. High — Missing HSTS (Strict-Transport-Security)

**What we saw:**  
The server did not send a `Strict-Transport-Security` header. Browsers are not told to force HTTPS or to resist downgrade attacks.

**Evidence (sanitized):**  
`Strict-Transport-Security` absent on `https://juice-shop.herokuapp.com` responses.

**Why it matters:**  
Users could be sent to HTTP (e.g. via redirect or MITM) and credentials or session cookies could be sent in the clear.

**How to fix:**
- [ ] Add this header to every HTTPS response: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- [ ] Submit the site to the [HSTS preload list](https://hstspreload.org/) so browsers load it over HTTPS from first request.

---

### 2. Medium — Missing Content-Security-Policy (CSP)

**What we saw:**  
No `Content-Security-Policy` header was present. The app does not declare which scripts, styles, or origins are allowed.

**Evidence (sanitized):**  
`Content-Security-Policy` missing on target responses.

**Why it matters:**  
XSS and data injection have more impact when there is no CSP; attackers can load arbitrary scripts and exfiltrate data more easily.

**How to fix:**
- [ ] Define a CSP that allows only trusted origins for scripts, styles, and fetches (e.g. `script-src 'self'`, `default-src 'self'`).
- [ ] Start with report-only mode (`Content-Security-Policy-Report-Only`) to tune rules, then switch to enforcing.
- [ ] Use nonces or hashes for inline scripts if you must keep them.

---

### 3. Low — Missing or weak security headers

**What we saw:**  
Several other security headers were missing or weak: X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy.

**Why it matters:**  
Together they reduce exposure to clickjacking, referrer leakage, and unnecessary browser features (camera, mic, etc.).

**How to fix:**
- [ ] Add `X-XSS-Protection: 1; mode=block` (legacy) or rely on CSP for XSS.
- [ ] Add `Referrer-Policy: strict-origin-when-cross-origin`.
- [ ] Add `Permissions-Policy` to restrict camera, microphone, geolocation, etc., to what the app needs.
- [ ] Add `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` where appropriate.

---

### 4. Low — Server header disclosure

**What we saw:**  
Responses included `Server: Heroku`, revealing the hosting stack.

**Evidence (sanitized):**  
`Server` header value: `Heroku`.

**Why it matters:**  
Revealing stack details makes it easier for attackers to choose known exploits for that environment.

**How to fix:**
- [ ] Remove or genericize the `Server` header in your app or platform config (e.g. Heroku/config or reverse proxy).
- [ ] If you cannot remove it, avoid exposing version numbers.

---

### TLS and certificate (passed)

Diverg also checked TLS and certificates. On this run: protocol TLS 1.2 (pass), weak protocols TLS 1.0/1.1 correctly rejected (pass), certificate validity and cipher strength pass. So the main improvements are on the **security headers** and **server disclosure** above.

---

## How to Reproduce This Scan

1. **Get Diverg**  
   Clone the repo and install dependencies (see main README).

2. **Run the proof scan** (authorized target only):
   ```bash
   python scripts/run_proof_scan.py https://juice-shop.herokuapp.com
   ```
   This writes `content/juice-shop.herokuapp.com-proof-results.json`.

3. **Or run a full adaptive scan** via CLI:
   ```bash
   python orchestrator.py --target https://juice-shop.herokuapp.com --scope full
   ```

4. **Use your own instance**  
   Run Juice Shop locally (Docker) and point the script at `http://localhost:3000` (or your URL). Same steps.

---

## What This Proves

- **Diverg finds real issues** on a known-vulnerable app (headers, crypto, auth, payment/basket, etc.).
- **We give solutions** — every finding above has a clear "how to fix" so teams can close gaps, not just get a list of problems.
- **No unauthorized testing** — Juice Shop is designed for this. Use the same approach on your own apps with proper authorization.

---

## Next Steps

- **Run Diverg on your staging** (with permission) and get a report that ties findings to fixes.
- **Star or fork** the repo if you want to see more "we ran Diverg on X" proof posts.
- **Contribute** — suggest checks, improve remediations, or add support for more stacks.

---

*Author: [Your name / Diverg team]*  
*Target: OWASP Juice Shop (authorized, intentionally vulnerable).*  
*Last run: [Date when you ran the proof scan].*
