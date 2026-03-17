# Four Pillars — Zero False Positives

Design principles for the four high-impact areas. We only report when we have **strong evidence**; every finding is **reproducible** and **verifiable**.

---

## 1. Business logic / workflow abuse

**Goal:** Expose true flow bypass (e.g. confirm without pay, zero amount) with no guesswork.

**Evidence bar:**
- **Path:** URL must clearly indicate order/checkout/confirm (path segment or common endpoint list).
- **Response:** We require **two** success signals: (1) HTTP 2xx, and (2) response body matching **order/checkout semantics** (e.g. `order_id`, `confirmation`, `placed`, `thank you`), not generic "success" alone.
- **Replay:** Every finding includes **verification_steps**: exact method, URL, and body so an assessor can replay and confirm.

**We do NOT report when:**
- Only generic "success" or "completed" in body (could be a non-order page).
- Path is generic (e.g. `/api/success`) with no checkout/order hint.
- We have no prior context that this is a checkout flow.

**Output:** Finding only when confidence = **confirmed**; evidence includes request/response snippet and replay steps.

---

## 2. Client-side sensitive data exposure

**Goal:** Report only **confirmed** sensitive data in client (keys, tokens, storage) that is both present and **used in a sensitive way**.

**Evidence bar:**
- **Context:** Match must be in **executable** code (we strip comments and string-only usage like `console.log("api_key")`).
- **Correlation:** For keys/tokens we prefer to correlate: same script sends this in a request (fetch/axios URL or header). Without correlation we report as **suspected** with lower severity.
- **Exclusions:** Known public patterns (e.g. Stripe `pk_`, Google Maps key in map context) are allowlisted or downgraded to Info.
- **Crypto/keys:** Private key, seed phrase, signing in client = report only when we see the pattern in code that could be executed (not in a comment or dead branch).

**We do NOT report when:**
- Pattern appears only in comments or inside a string passed only to logging.
- Key is known public (e.g. publishable key with documented public use).
- We cannot show the value is used in a network request or storage.

**Output:** Severity and a **confidence** field (confirmed / suspected). Evidence includes file URL, snippet, and if available the request/usage context.

---

## 3. Attack path / chaining

**Goal:** Output **concrete attack stories** (Step 1 → Step 2 → Impact) that an assessor can verify. No vague chains.

**Evidence bar:**
- **Steps:** Each step must have a **real** finding with non-empty `url` and `evidence`. We drop findings that are too generic.
- **Plausibility:** Chain order must be valid (entry before privilege, etc.); we use role classification only when the finding title/category/impact clearly support that role.
- **Narrative:** Every path is rendered as: **Step 1:** [title] at [url]. **Step 2:** ... **Impact:** [one line]. **Evidence refs:** [skill/finding].

**We do NOT report when:**
- A step has no URL or no evidence.
- Role was inferred only from a single keyword that could be coincidental (e.g. "admin" in a non-auth finding).
- Chain is purely theoretical with no concrete finding refs.

**Output:** Attack paths with **attack_story** (narrative) and **steps** with finding title, url, and source_skill. No paths without at least one High/Critical for high-impact chain types (financial, data).

---

## 4. Third-party script trust

**Goal:** Report only when we can show a **third-party** script has **actual** access to something sensitive (cookies, storage, postMessage) or lacks origin checks.

**Evidence bar:**
- **Third-party:** Script URL origin ≠ main page origin (we tag by origin).
- **Access:** We must see in the script content: e.g. `document.cookie`, `localStorage`, `sessionStorage`, or `addEventListener('message')` (and optionally check for origin validation). We do not report "script is third-party" alone.
- **Sensitivity:** Report only when the access could be sensitive (e.g. cookie without HttpOnly in same page, or postMessage without origin check). We allowlist common benign CDNs (stripe, gstatic, etc.) and do not report them unless we see dangerous usage.

**We do NOT report when:**
- Script is first-party (same origin).
- We cannot show the script reads cookies/storage or listens to postMessage.
- Script is on a known allowlist and we see no dangerous pattern.

**Output:** Finding only when we have: script URL, origin (third-party), and **evidence** (snippet showing cookie/storage/postMessage access). Remediation: restrict cookie scope or load in iframe with reduced access.

---

## Implementation checklist

- [x] Design doc (this file)
- [x] Pillar 1: Workflow — two-signal order semantics, verification_steps, reject generic-only JSON
- [x] Pillar 2: Client-surface — comment stripping, confidence (confirmed/suspected), public-key allowlist
- [x] Pillar 3: Attack paths — attack_story narrative, evidence-only steps, min High/Critical for financial/data chains
- [x] Pillar 4: Third-party — origin tagging, cookie/storage/postMessage access only, allowlist, evidence-only
