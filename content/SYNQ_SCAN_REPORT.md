# Diverg Scan Report: app.synq.xyz/discover — Positives & Negatives

**Target:** https://app.synq.xyz/discover (Synq — Trade Anything, Miss Nothing)  
**Scan type:** Headers + HTML (no live JS execution).  
**Date:** 2026-03.

---

## Positives

1. **HTTPS and HSTS**
   - Site is served over HTTPS. TLS is in use.
   - **Strict-Transport-Security** is present: `max-age=31536000` (1 year). Browser will enforce HTTPS and reduce downgrade risk.

2. **No mixed content (from initial HTML)**
   - All observed script and link URLs in the initial document are HTTPS. No HTTP resources on an HTTPS page in the fetched snapshot.

3. **Cache control**
   - `Cache-Control: public, max-age=0, must-revalidate` is set. Responses can be revalidated and are not blindly cached long-term.

4. **Hosting**
   - Hosted on Netlify with visible HSTS. Edge and TLS handling are typically well maintained.

5. **Sensitive path probes (from our checks)**
   - No evidence in the header/HTML scan of classic “company exposure” paths (e.g. admin, backup, export) returning 200 in a way we could confirm as real backend endpoints from this snapshot. (SPAs often return 200 for all routes; would need live verification.)

---

## Negatives

1. **No Content-Security-Policy (CSP)**
   - **Impact:** No browser-level control over script sources. Third-party scripts (e.g. MoonPay, Google Tag Manager) and any future inline script are not constrained. Increases XSS and script-injection risk.
   - **Recommendation:** Add a strict CSP with `default-src 'self'` and allowlisted `script-src` for required third parties; avoid `unsafe-inline` / `unsafe-eval` where possible.

2. **No X-Frame-Options**
   - **Impact:** Page can be embedded in iframes. Clickjacking (e.g. on login or wallet-connect flows) is possible.
   - **Recommendation:** Set `X-Frame-Options: DENY` or `SAMEORIGIN`.

3. **No X-Content-Type-Options**
   - **Impact:** Browsers may MIME-sniff responses. Increases risk of content-type confusion and related attacks.
   - **Recommendation:** Set `X-Content-Type-Options: nosniff` on all responses.

4. **No Referrer-Policy**
   - **Impact:** Full URL may be sent in the Referer header to third parties (e.g. MoonPay, analytics). Can leak query params and path information.
   - **Recommendation:** Set e.g. `Referrer-Policy: strict-origin-when-cross-origin`.

5. **No Permissions-Policy**
   - **Impact:** No explicit restriction of browser features (camera, mic, geolocation, etc.). If the app or a third-party script uses them later, policy is implicit only.
   - **Recommendation:** Add Permissions-Policy to restrict unneeded features.

6. **No Cross-Origin-Opener-Policy (COOP)**
   - **Impact:** For an app that may use wallet connect or cross-origin windows, isolation is weaker. Cross-origin window access is less constrained.
   - **Recommendation:** Consider `Cross-Origin-Opener-Policy: same-origin` (or a tailored value) after testing.

7. **Server header exposed**
   - **Impact:** Minor information disclosure: `Server: Netlify` reveals the platform.
   - **Recommendation:** Remove or genericize the Server header if possible via Netlify config.

8. **External scripts without SRI**
   - **Impact:** At least two third-party scripts (MoonPay SDK, Google Tag Manager) load without Subresource Integrity. If the CDN or script is compromised, the app could load tampered code.
   - **Recommendation:** Add `integrity` (and `crossorigin="anonymous"`) for third-party scripts, or self-host / reduce reliance on them.

9. **Third-party script supply chain**
   - **Impact:** Payment/crypto (MoonPay) and analytics (GTM) run in the same origin as the app. A compromise of either provider could affect the page. No CSP to limit or report on script behavior.
   - **Recommendation:** Treat third-party scripts as part of the trust boundary; add CSP and consider minimal, sandboxed integration (e.g. iframes where appropriate).

10. **Manifest with credentials**
    - **Impact:** `manifest.json` is loaded with `crossorigin="use-credentials"`. Credentials are sent to the manifest URL. Ensures correct origin and auth if needed, but increases sensitivity of that request.
    - **Recommendation:** Confirm manifest endpoint does not expose user-specific data and is required for PWA behavior; otherwise consider `crossorigin="anonymous"` if appropriate.

11. **Large main bundle**
    - **Impact:** Main JS bundle is very large (~13MB reported). Large attack surface (XSS, dependency issues) and slower load; wallet/trading logic likely in this bundle.
    - **Recommendation:** Code-split, tree-shake, and audit dependencies; treat wallet/signing code as critical path.

12. **Inline script**
    - **Impact:** Google Analytics inline snippet runs in the page. Without CSP, any future inline script is allowed; increases XSS and policy bypass risk.
    - **Recommendation:** Move to non-inline loading where possible; lock down with CSP.

---

## Summary

| Category        | Positives | Negatives |
|----------------|-----------|-----------|
| Transport       | HSTS, HTTPS, no mixed content | — |
| Headers         | Cache-Control | No CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP; Server exposed |
| Scripts / DOM   | — | No SRI on third-party scripts; third-party supply chain; inline script; large bundle |
| Config          | — | Manifest with use-credentials; no CSP to constrain scripts |

**Overall:** Strong on transport (HTTPS + HSTS). Weak on defensive headers (CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP) and on script integrity and supply-chain control. For a site involving wallet connect and trading, adding CSP and the missing security headers should be a priority.
