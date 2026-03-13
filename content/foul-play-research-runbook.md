# Foul-play and owner history research

Diverg is both a **security scanner** (to help improve company security) and an **investigator** to figure out whether companies or their owners have been part of **crime, foul play, or backdooring**. External research on known owners and entity history is part of that.

---

## What we do

1. **Identify entities**  
   From WHOIS (registrant name, org) and optional OSINT result we get one or more entity names (company, owner, registrant).

2. **External reputation search**  
   For each entity we run a public search for signals of:
   - Fraud, lawsuit, convicted, fined  
   - Data breach, scandal, backdoor  
   - FTC, SEC, or other regulatory action  

3. **Structured output**  
   Findings are tagged by relevance: `lawsuit`, `breach`, `criminal`, `regulatory`, `foul_play`, or `reputation`. Snippets and URLs are kept so the operator or report can follow up. We also output **recommended_queries** for manual or deeper search (including years-back research).

4. **Integration with reports**  
   Entity reputation is merged into the assessment context. The final analysis prompt tells the model to:
   - Use owner/entity history when assessing potential foul play or backdooring  
   - Report links to lawsuits, regulatory action, convictions, breaches, or fraud  
   - Treat these as public-record/reputation signals, not legal conclusions  
   - Add an **OWNER / ENTITY HISTORY** or **FOUL-PLAY RESEARCH** section when there are findings  

---

## When it runs

- **Attack flow (default and deep-audit):** `entity_reputation` is in phase 2. It receives the OSINT result from phase 1 so WHOIS org/registrant are used.
- **Full scan (`/scan`):** `entity_reputation` is in the skill list. It receives OSINT result from the same run when available.
- **Single tool:** Use `run_entity_reputation` with `target` (domain or URL). Optionally pass `osint_result` (raw JSON from `run_osint`) for better entity names.

---

## OSINT changes for owner research

- **WHOIS:** The OSINT skill now exposes **registrant_name** (and still **org**) from WHOIS so entity reputation can target the right person/company.
- **Breach / HIBP:** Unchanged; breach exposure is still extracted and passed to the report as before.

---

## How to run manually

- **Telegram:** After running OSINT on a domain, you can run entity reputation with the same target; if the bot has the OSINT result in context (e.g. from a previous step in the same flow), it will be used.
- **Tool (LLM):** `run_entity_reputation(target="example.com", osint_result="<paste osint JSON>")` for best results.
- **CLI / script:** Call `entity_reputation.run(domain, scan_type="full", osint_json=osint_raw)`.

---

## Upgrades (current)

- **Two query types per entity:** (1) fraud/lawsuit/convicted/breach/FTC/SEC/regulatory; (2) CEO/founder/arrested/indicted/sanction/DOJ so executive and sanctions-style hits are included.
- **Severity:** Findings are tagged High (criminal, regulatory, foul_play), Medium (lawsuit, breach), or Low (reputation). The report and scan summary show high-severity counts.
- **Date hints:** Years (e.g. 2019, 2020–2022) are extracted from snippets/titles so the report can reference timeline (“linked to incident in 2020”).
- **Email-domain check:** WHOIS emails from OSINT are used to derive email domains; we run a separate “data breach OR leak OR pwned” search per domain (up to 2) to tie the organisation to past breaches.
- **Discover integration:** When the surface is classified as **admin-surface** or **identity-surface**, `run_entity_reputation` is recommended so owner/entity research is suggested right after discover.
- **Summary field:** The skill returns a short `summary` (e.g. “X entities researched, Y findings (Z high-severity)”) used in scan output and context.

---

## Limits and ethics

- Research is based on **public** search (e.g. DuckDuckGo). No access to private or paywalled court/regulatory databases unless you add them.
- Findings are **reputation signals**, not legal conclusions. The report text should say so.
- Rate limits and time budget apply; we cap entities and results per entity to avoid abuse.
- Authorized use only; ensure you have permission to run this against the target.
