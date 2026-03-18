# AI guidance: crypto/DeFi site detection and scan selection

## How new routes/skills behave: crypto vs non-crypto

| Scenario | chain_validation_abuse runs? | How you can tell |
|----------|-----------------------------|-------------------|
| **Non-crypto site, full scan, no goal** | **No** | `site_classification.is_crypto` is false, `chain_validation_abuse_ran` is false, `chain_validation_abuse_reason` is null. |
| **Crypto site, full scan, no goal** | **Yes** (auto) | `site_classification.is_crypto` true, `confidence` ≥ 0.2, `chain_validation_abuse_ran` true, `chain_validation_abuse_reason` is `"auto_crypto"`. |
| **Any site, scope=crypto** | **Yes** | `chain_validation_abuse_ran` true, `chain_validation_abuse_reason` is `"scope_crypto"`. |
| **Any site, goal e.g. "batch validation" or "crypto audit"** | **Yes** | `chain_validation_abuse_ran` true, `chain_validation_abuse_reason` is `"goal"`. |

**Identifying the difference:** Every scan result (API and streaming) includes **`site_classification`** with:
- **`is_crypto`** — boolean from detector
- **`confidence`** — 0.0–1.0
- **`signals`** — sample keywords/signals that triggered (if any)
- **`chain_validation_abuse_ran`** — whether the Diverg batch validation skill ran
- **`chain_validation_abuse_reason`** — `"auto_crypto"` | `"scope_crypto"` | `"goal"` | null

So you can always see (1) whether we classified the site as crypto, and (2) why the extra skill ran (or didn’t). On a **non-crypto** site when the skill **does** run (goal or scope), the skill adds an Info finding: *"Site not classified as crypto/DeFi — generic batch/IDOR checks still applied"* so the report is explicit.

---

When assessing a target (e.g. for Diverg/Sectester), the AI should:

## 1. Quick analysis first

- Run **crypto/DeFi site detection** before or at the start of the scan:
  - Use `crypto_site_detector.detect_from_url(target_url)` (or `detect_from_content` if you already have HTML/JS).
  - If `result.is_crypto` is true and `result.confidence >= 0.2`, treat the site as **crypto-related**.

## 2. What “crypto-related” means

- The detector looks for: wallet/connect, web3, swap, defi, token, bridge, stake, subaccount, chain, signing, etc., in the page and URL.
- Crypto-related sites get **additional** checks on top of the main scan (see below).

## 3. Which scans to run

- **Always run (main scans):** recon, headers_ssl, crypto_security, data_leak_risks, company_exposure, web_vulns, auth_test, api_test, high_value_flaws, workflow_probe, race_condition, payment_financial, client_surface, and (with context) dependency_audit, logic_abuse, entity_reputation.

- **When crypto-related:** Also run **chain_validation_abuse**. The orchestrator does this automatically when `_is_crypto_site(target_url)` is true for a full scan, or when scope is `crypto`, or when the user’s goal matches phrases like “crypto”, “defi audit”, “batch validation”, “chain validation”.

- **Goal-based:** If the user says “crypto audit”, “batch validation”, “chain validation”, “defi”, “exchange security”, resolve the goal via `intent_skills.resolve_goal(goal)` so that `chain_validation_abuse` is included.

## 4. What chain_validation_abuse does

- Classifies the site as crypto or not (if not already known).
- Probes for **batch-like endpoints** (e.g. `/batch`, `/orders/batch`) and suggests comparing validation to the single-operation path.
- Looks for **account/subaccount-style parameters** in the page/JS (e.g. `subaccount_id`, `account_id`, `beneficiary`) and recommends ensuring they are not trusted without signer/session check.
- References **content/diverg-batch-validation-routes.md** (100+ routes) for manual or follow-up checks.

## 5. Using the 100+ exploit routes

- For crypto and high-value targets, use **content/diverg-batch-validation-routes.md** as a checklist:
  - Batch vs single path (routes 1–10), parameter substitution (11–20), alternate endpoints (21–30), type confusion (31–38), etc.
  - The AI can prioritize routes that match the surface (e.g. if batch API exists, emphasize batch-vs-single; if account_id appears, emphasize IDOR/ownership).
- Findings from `chain_validation_abuse` and related skills can be enriched with the **exploit_catalog** entry `batch_validation_gap` (prevention text and CWE/OWASP).

## 6. Summary

- **Filter:** Use `crypto_site_detector` to decide if the site is crypto-related.
- **Scans:** Main scans always; add **chain_validation_abuse** (and optionally the **crypto** profile) when crypto is detected or requested.
- **Routes:** Use **diverg-batch-validation-routes.md** for 100+ ways to find or replicate batch validation issues on other sites.
