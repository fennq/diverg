# Crypto Trust & Data Risk — What Diverg Can and Cannot Do

## Can we find if a company is doing shady crypto or selling user data on the dark web?

**Short answer:** We can find **technical conditions** that make shady behavior possible or likely (backdoor-friendly code, data exfil paths, weak crypto, breach exposure). We **cannot** prove that a company is intentionally backdooring or selling data on the dark web — that requires human intel, law enforcement, or insider information.

---

## What we CAN detect (technical signals)

### 1. Shady or high-risk crypto patterns
- **Weak crypto:** Math.random for tokens, MD5/DES/RC4/ECB, hardcoded IVs (crypto_security).
- **Client-side key handling:** Private keys, seed phrases, or mnemonics in frontend JS (crypto_security + client_surface). If the app handles keys in the browser, it can be abused or leak; we flag it.
- **Opaque or unsigned flows:** Withdrawal/transfer to arbitrary address, unsigned or unverified signing in client. We flag patterns that could enable theft or a hidden “drain” path.

### 2. Backdoor-friendly or hidden behavior
- **Hidden endpoints:** Paths like `/shell`, `/exec`, `/debug`, `/backdoor`, admin panels without auth (recon + company_exposure). We don’t know intent, but we flag “this looks like a backdoor or debug hook.”
- **Credentials or secrets in frontend:** API keys, tokens, or internal URLs in JS (high_value_flaws, client_surface). Could be accidental or intentional; we report so you can verify.
- **Obfuscated code loading remote scripts:** Dynamic script loading from unknown or third-party domains. Could be analytics or something worse; we flag for review.
- **postMessage without origin check:** Cross-origin message handling that doesn’t validate `event.origin` can be used to exfiltrate data or inject commands.

### 3. Data exfiltration risk (where does PII go?)
- **Third-party requests with sensitive-looking data:** We scan JS for `fetch`/`axios` to **non–same-origin** URLs. If the same code sends params/body that look like email, token, user_id, wallet, phone, we flag: “Sensitive-looking data may be sent to third-party domain X; verify compliance and intent.”
- **Bulk export without rate limit or audit:** APIs that return large lists of users/data with no obvious cap (logic_abuse, api_test). We flag so you can check if this could be used to dump data for resale.
- **IDOR on user/wallet data:** Access to other users’ data (high_value_flaws, payment_financial). A malicious insider or compromised backend could use the same bugs to export data; we surface the technical flaw.

We do **not** decide “this company is selling data.” We say: “Data flows to these domains; these endpoints allow bulk or cross-user access — verify who has access and how it’s logged.”

### 4. Breach and “already leaked” exposure
- **Breach databases (HIBP, IntelX):** We check if the **domain** (or related emails) appears in known breaches (osint). That tells you: “Your brand/domain has shown up in breach data” — i.e. data has already been exposed somewhere. We **cannot** tell whether that data was then sold on the dark web or by whom.

---

## What we CANNOT do

- **Prove a company is backdooring:** We can find hidden endpoints, weak crypto, or client-side key handling. We cannot attribute intent (bug vs backdoor). You still need code review, threat intel, or legal/forensic work.
- **Prove data is being sold on the dark web:** No automated scan can see inside dark web markets or prove that a specific company is selling data. We can only:
  - Flag that **data has been exposed** (breaches, IDOR, bulk export, token leakage).
  - Say: “If someone wanted to resell data, these are the technical paths that would allow it.”
- **Distinguish “shady” from “incompetent”:** Same misconfiguration can be malice or negligence. We report the finding; you decide how to interpret it.

---

## How we use this in reports

- **Crypto / trust:** Findings like “Client-side private key handling,” “Weak TLS,” “Request to third-party with token-like param” are called out so you can assess trust and custody risk.
- **Exfil and access:** “Sensitive-looking data sent to third-party domain X” and “IDOR on user/wallet” are in the report with a note: “Verify compliance and access controls; these conditions could enable data theft or misuse.”
- **Breach:** If osint finds the domain in HIBP/IntelX, the report states that clearly and adds: “We cannot determine whether data was sold on the dark web; consider threat intel or breach monitoring for your domain/emails.”
- **Backdoor-like:** “Hidden or privileged endpoint X” is reported as “Verify this is intended and properly restricted; pattern is consistent with backdoor or debug hook.”

---

## Summary

| Question | Answer |
|----------|--------|
| Can Diverg find shady crypto? | Yes — weak crypto, client-side keys, opaque withdrawal/signing. We flag high-risk patterns; you judge intent. |
| Can Diverg find a backdoor? | We can find **backdoor-like** code paths (hidden endpoints, credentials in frontend, exec/shell-style routes). We cannot prove intent. |
| Can Diverg find if a company is selling user data on the dark web? | No. We find **exposure** (breaches, IDOR, bulk export, third-party data flows) and say “these conditions could enable theft or resale.” Proving actual sale is outside automated scanning. |

Use Diverg to **surface the technical conditions** that would let a bad actor (or a malicious insider) steal data, abuse keys, or hide a backdoor. Combine that with threat intel, breach monitoring, and human review to form a full picture.
