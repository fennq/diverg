# Diverg — Efficiency and Performance

Ways to improve scan speed, reduce cost, and avoid rate limits.

---

## 1. Parallel execution (attack flow)

**Phase 1 recon runs in parallel.** In `/attack`, all Phase 1 steps (e.g. `osint`, `recon:subdomains`, `recon:techstack`, `recon:sensitive`) are executed in parallel in batches of up to **4** concurrent skills. This cuts Phase 1 wall-clock time roughly by the number of steps (e.g. 4 steps in ~1x skill duration instead of 4x).

- **Where:** `run_attack()` in `bot.py` — Phase 1 uses `asyncio.gather()` in batches of `PHASE1_PARALLEL_CAP` (4).
- **Why cap at 4:** Limits concurrent load on the target and on outbound APIs (DNS, Solscan, etc.) to avoid rate limits and connection spikes.
- **Phase 2/3:** Remain sequential because steps like `dependency_audit` and `logic_abuse` depend on prior results (e.g. `client_surface`).

---

## 2. Inter-step / inter-skill delay

A short **0.3s** delay is applied:

- After each **Phase 2** and **Phase 3** skill in `/attack`.
- After each step in **full scan** (`/scan`).

This reduces the chance of triggering rate limits or WAF throttling on the target when many requests are sent in quick succession.

- **Tuning:** To change the delay, search for `asyncio.sleep(0.3)` in `bot.py` and adjust (e.g. 0.5s for stricter targets).

---

## 3. Skill time and budget

| Setting | Where | Purpose |
|--------|--------|--------|
| `SKILL_TIMEOUT` | `bot.py` (~120s) | Hard cap for each skill run; prevents a single skill from hanging the flow. |
| `RUN_BUDGET_SEC` | Per skill (e.g. 50–55s in `client_surface`, `blockchain_investigation`) | Soft budget; skills check `_over_budget()` and exit early to leave time for other work. |
| `TIMEOUT` | Per skill (e.g. 6–12s per HTTP request) | Request-level timeout so a single URL does not block the whole skill. |

**Improving efficiency:**

- For **quick audits**, use the **quick-audit** preset (fewer steps, lighter recon).
- For **deep audits**, skills already trim work (e.g. max JS files, capped tokens) to stay within budget; increasing `RUN_BUDGET_SEC` per skill can allow more coverage at the cost of longer runs.

---

## 4. API and external service usage

- **Solscan / Etherscan / Arkham:** Blockchain investigation uses fixed caps (e.g. 5 tokens for sniper checks, 2 for token meta, 3 for holder checks). Lower these in `blockchain_investigation.py` (e.g. `[:3]`, `[:2]`) to reduce API calls and run time.
- **Arkham:** Batch labeling (`_arkham_intel_batch`) is used so one request labels many addresses instead of one request per address.
- **Stealth:** Uses a single `requests.Session` per skill (connection reuse) and adaptive backoff on 429/403.

---

## 5. LLM and token usage

- **Truncation:** Raw results sent to the model are trimmed (e.g. `MAX_RAW_RESULTS_CHARS`, `MAX_PER_RESULT_CHARS` in `bot.py`) to stay under token limits and reduce cost.
- **Context:** Analysis context (e.g. `ranked_findings`, `attack_paths`) is capped (e.g. top 5, top 4) before being passed to the LLM.

Reducing these caps further will lower token usage and cost at the cost of less context for the model.

---

## 6. Result cache (recon / headers / osint)

A short-lived **in-memory cache** is used for repeat runs of the same skill against the same host:

- **Cached skills:** `recon`, `headers_ssl`, `osint`.
- **Key:** `(skill, normalized_host, scan_type)`. Host is normalized from URL (e.g. `https://example.com/path` → `example.com`).
- **TTL:** 5 minutes (`SKILL_RESULT_CACHE_TTL_SEC`). Only successful results (no top-level `error` in JSON) are cached.
- **Size:** Up to 50 entries; expired entries are evicted first, then oldest by expiry.

When you run the same recon/headers/osint step again within the TTL (e.g. same domain in a second `/attack` or parallel phase1 steps that overlap), the bot returns the cached result and skips the skill run. Auth and context are not cached (cache is skipped when auth or context is passed).

---

## 7. Presets and scope

| Preset | Use case | Relative speed |
|--------|----------|-----------------|
| **quick-audit** | Fast check (recon, headers, files, auth, discovery, business exposure) | Fastest |
| **api-heavy** | API-focused (subdomains, headers, API discovery/GraphQL/CORS/auth, company, sqli) | Medium |
| **waf-protected** | WAF-aware (waf/subdomains/tech, headers, xss/sqli, discovery, CORS, auth, company) | Medium |
| **deep-audit** | Full recon + crypto + data leak + client surface + dependency + logic + many steps | Slowest |

Use **quick-audit** when you need efficiency over maximum coverage.

---

## 8. Checklist for operators

- Use **quick-audit** when speed is more important than depth.
- Rely on **Phase 1 parallel** in `/attack`; no extra config needed.
- If the target rate-limits, consider increasing the inter-step delay (e.g. to 0.5s).
- For blockchain investigations, ensure `SOLSCAN_PRO_API_KEY` (and optionally `ARKHAM_API_KEY`) are set; missing keys add errors and can make the skill exit earlier.
- Monitor skill timeouts; if skills often hit `SKILL_TIMEOUT`, consider a higher cap or reducing scope (e.g. smaller wordlist, fewer tokens in blockchain checks).
