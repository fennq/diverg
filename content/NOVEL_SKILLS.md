# Diverg-proprietary skills — beyond checklist scanning

These skills are designed to be **more effective at finding exploitable issues** than generic scanners. They don’t just “run a list of checks”; they correlate, reason about flow, and prioritize what an attacker would actually chain to get impact.

---

## 1. Attack paths (`run_attack_paths`)

**What it does:** Takes the **output of a prior scan** (e.g. `run_full_attack`) and turns raw findings into **ranked exploit chains**.

- **Classifies** each finding into roles: **entry** (unauthenticated access, XSS, info leak), **privilege** (auth bypass, IDOR, JWT), **pivot** (SSRF, internal disclosure), **data** (credentials, PII), **financial** (payment bypass, refund).
- **Builds chains** such as: entry → privilege → data, entry → pivot, privilege → financial.
- **Scores** each chain by exploitability (severity + length) and **impact** (data / financial / pivot).
- **Output:** Ranked attack paths with steps, evidence refs, and impact summary so you see *how* an attacker would go from “in” to “data/money/internal.”

**Why it’s different:** Most tools list findings. We answer: “Which of these can be *chained* to real impact, and in what order?”

**When to use:** After `run_full_attack` (or after running several tools). In the Telegram bot, full attack runs attack paths automatically and includes them in the result. You can also call `run_attack_paths` with `prior_results_json` = the JSON of a previous run.

---

## 2. Workflow probe (`run_workflow_probe`)

**What it does:** Probes **business-flow and order-of-operations** bugs that checklist tools miss.

- **Targets** flows like: cart → checkout → pay → confirm.
- **Probes:**  
  - **Skip step:** Call confirm/complete without a prior pay or cart step; if the server returns success, that’s a flow bypass.  
  - **Zero amount:** Send `amount=0` or `total=0` to order/checkout endpoints; if accepted, that’s a free-order bug.
- **Output:** Findings such as “Flow bypass: terminal step accepted without prior steps” or “Zero-amount order/checkout accepted.”

**Why it’s different:** Many scanners test single endpoints (e.g. “is this URL open?”). We test *sequences* and *state*: “Can I confirm an order without paying? Can I get a free order?”

**When to use:** On any target with checkout, orders, payments, or multi-step flows. Included in `run_full_attack` when relevant; you can also run it alone with `run_workflow_probe(target_url)`.

---

## How to run

- **Bot:** Use `run_full_attack(target)` — attack paths are run automatically at the end. Use `run_workflow_probe(target_url)` for flow-only. Use `run_attack_paths(target_url, prior_results_json=<paste prior run JSON>)` to re-correlate a past run.
- **Orchestrator:** `python orchestrator.py --target https://example.com --scope full` — `workflow_probe` is in the full profile; attack paths can be added as a post-step on aggregated findings.
- **Standalone:**  
  - `python -m skills.workflow_probe.workflow_probe https://example.com`  
  - Attack paths: pass prior results as second arg (path to JSON file) or from your own script.

---

## Roadmap (more “our own” capabilities)

- **Credential surface:** One score combining JWT in URL/localStorage, cookie flags, API keys in JS, session in Referer → “session takeover feasibility.”
- **Data lineage:** From client_surface + api_test, build “who can see what” and flag paths where data leaks or escalates.
- **State-machine probe:** Infer order of operations from API discovery and systematically test invalid orderings (e.g. confirm before pay, replay steps).

These stay focused on **exploitability** and **chaining** so we find what people can actually abuse, not just what a checklist says is “present.”
