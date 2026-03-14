# Diverg as #1 Crime Identifier — Strategy

How we beat manual investigators (TRM, Arkham users, independent researchers) on **speed**, **scale**, and **actionable output**.

---

## How manual investigators work today

- **Manual toolchain:** Arkham, Etherscan/Solscan, Dune, Cielo, TRM, bridge explorers (Range, Socketscan, Pulsy), OSINT (LeakPeek, IntelX, Spur, Cavalier, TelegramDB, Discord.id), archives (Wayback, Mugetsu).
- **Process:** Follow wallets by hand → trace flows → label entities → build narrative → publish thread.
- **Strengths:** Pattern recognition, persistence, public threads that get shared.
- **Limitations:** One investigation = hours/days; reactive (after the rug); output = tweet thread (hard to query or reuse); no single risk score; no automation at scale.

---

## Where we win

| Dimension | Manual investigators | Diverg |
|-----------|-------------------|--------|
| **Speed** | Hours–days per case | One run = full pipeline in minutes (deployer → tokens → LPs → counterparties → risk score → report). |
| **Scale** | One target at a time | Batch: run on every new launch or top N tokens; rank by risk score; alert on threshold. |
| **Output** | Thread + screenshots | **Structured crime report**: summary, risk score, evidence (tx hashes, addresses), counterparties, linked wallets — exportable JSON/MD for lawyers, exchanges, or threads. |
| **Proactive** | Mostly after rug | **Pre-rug:** mint/freeze authority, LP remove history, holder concentration, sniper pattern, deployer CEX counterparties → risk score **before** dump. |
| **Attribution** | Manual cross-check | **Automated:** Arkham batch labels + counterparties; deployer + sniper + top holders labeled in one run; linked-wallet cluster from counterparties + co-holders. |
| **Verifiability** | “Trust the thread” | **Evidence-first:** every claim ties to tx hash, address, or API source; report is auditable. |

---

## Roadmap: better results than manual

### 1. **Risk score (0–100)**  
Single number from all signals: mint/freeze authority, LP remove history, holder concentration, sniper pattern, serial launcher, deployer outflows, CEX counterparties. Enables: sort by risk, alert when score &gt; threshold, “worst 10 launches this week.”

### 2. **Structured crime report**  
One artifact per investigation: **Summary** (1–2 sentences), **Risk score**, **Deployer** (address, label, counterparties), **Tokens** (mint, authority risks), **Findings** (with evidence hashes), **Flow** (outflows, CEX), **Linked wallets** (cluster). Export: JSON (API) + Markdown (human/shareable).

### 3. **Wallet clustering / linked wallets**  
From deployer (or any seed): Arkham counterparties + same-token top holders + optional 1-hop transfers → “network” of related addresses. Surfaces: OTC, CEX, same-team wallets. Feeds narrative: “Deployer sends to Binance and Wallet X; Wallet X holds 3 other tokens from same deployer.”

### 4. **Post-rug one-shot mode**  
Input: “This token/wallet just rugged.” One command runs full pipeline (no URL needed): deployer + all tokens + LP removal + outflows + counterparties + labels + risk score + report. First-draft report in minutes instead of hours.

### 5. **Proactive monitoring (future)**  
Watch new launches (e.g. pump.fun, liquid.af); run risk checks on each; store scores; alert when score &gt; 80 or when deployer matches a known-bad cluster. Be first to flag, not first to post-mortem.

### 6. **Cross-surface (future)**  
Token metadata → website/social links → WHOIS, same IP, same server. Optional: Telegram/Discord scrape for “dev” wallet mentions. Complements on-chain with off-chain (OSINT, Telegram/Discord) the way manual investigators do.

### 7. **Contract / bytecode similarity (future)**  
Compare contract bytecode to known scam contracts; same or near-same = instant red flag. Requires: verified contract storage or third-party API.

---

## Immediate implementation (this repo)

- **Risk score:** Compute from existing findings (authority, LP remove, concentration, sniper, serial, counterparties); add to `BlockchainInvestigationReport` and to crime report.
- **Crime report:** New output format: `crime_report` dict with summary, risk_score, deployer_section, tokens_section, findings_with_evidence, flow_highlights, linked_wallets; export as JSON and optional Markdown.
- **Linked wallets:** From deployer: Arkham counterparties + top holders of same token(s); optional 1-hop from deployer transfers; list in report as “linked_wallets” with labels where available.
- **Post-rug mode:** Bot/CLI accepts `deployer_address` or `token_address` only (no URL); skill runs with placeholder URL and max depth (all tokens for deployer, full counterparties, full report).

---

## Messaging

- **“Faster than a human thread”** — Same intel top investigators assemble by hand, in one run, with evidence hashes.
- **“Risk score before the rug”** — Don’t just post-mortem; flag high-risk launches so users and platforms can act.
- **“Structured, not just screenshots”** — Report is machine-readable (JSON) and human-readable (MD); ready for compliance, exchanges, or your own thread.
