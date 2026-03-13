# Accuracy & Research — Gaps and Improvements

Where data and research fall short today, and what to do to get to top notch.

---

## 1. Data accuracy gaps

| Area | Current state | Issue |
|------|----------------|--------|
| **Blockchain** | On-chain only when `SOLSCAN_PRO_API_KEY` / `ETHERSCAN_API_KEY` set | No keys → no real addresses, no flow, no sniper/LP data. Reports and diagrams use placeholders or “skipped.” |
| **Blockchain labels** | Arkham optional (`ARKHAM_API_KEY`) | Without it: nodes are raw addresses only; no “CEX / mixer / OTC” labels, weaker narrative. |
| **Entity reputation** | DuckDuckGo HTML only | No paid intel (Spur, Cavalier, LeakPeek, IntelX API). Good for public news/lawsuits; weak on breach DBs and deep dossiers. |
| **OSINT breach checks** | HIBP domain API (real); IntelX/Dehashed = link-only | IntelX/Dehashed not queried via API — we just surface “check manually” links. No API keys = no structured breach results from them. |
| **Flow diagrams** | Built from real transfer data when keys exist | When keys missing, card/diagram use example addresses and dates (e.g. 7xK9...mN2p) — clearly placeholder, not investigation output. |

**Accuracy rule:** Any finding that depends on an external API should state whether it’s **live** (keys set, data from API) or **inferred/placeholder** (no key or fallback). No passing placeholder as real.

---

## 2. Research depth gaps

| Area | Current state | Gap |
|------|----------------|-----|
| **Blockchain** | 1 deployer, N tokens, counterparties from Arkham; limited transfer pages | No multi-hop (follow counterparty outflows 2–3 hops); no mixer/off-ramp tagging; no “flow_trace” mode with more history. |
| **Entity / owner** | WHOIS + DDG search for fraud/lawsuit/convicted/FTC/SEC | No court docket APIs, no formal sanctions lists (OFAC, etc.), no “same person across domains” clustering. |
| **OSINT** | WHOIS, DNS, crt.sh, dorks, HIBP, Wayback, link-only IntelX/Dehashed | No Telegram/Discord scrape; no “dev wallet” extraction from social; no LeakPeek/Cavalier/Spur-style paid intel. |
| **Web** | Strong (recon, vulns, headers, API, company_exposure, etc.) | Correlation across skills could be tighter (e.g. “this admin path + this cookie = session takeover”). |
| **Cross-surface** | Separate web vs chain vs entity | No automatic chain: “token metadata → site/social → WHOIS → same server/registrant” in one narrative. |

---

## 3. Prioritized improvements

### High impact (accuracy)

1. **Require and document API keys for “full” mode**  
   - `.env.example` and runbook: list `SOLSCAN_PRO_API_KEY`, `ARKHAM_API_KEY`, `ETHERSCAN_API_KEY` and what turns on (real on-chain, labels, flow).  
   - In reports/diagrams: tag output as “live” vs “placeholder” when keys are missing.

2. **No placeholder as fact**  
   - If blockchain keys are missing: report “On-chain skipped (no API key)”; do not show example wallet/flow as if from this target.  
   - Tweet cards / boards: use real addresses and dates when we have them; otherwise show “Run with Solscan/Arkham keys for wallet flow” instead of fake addresses.

3. **Entity reputation: optional premium sources**  
   - Support IntelX API (or similar) when key present; otherwise keep DDG + “manual check” links.  
   - Add 1–2 structured sources (e.g. court/sanctions) if we can get free or keyed access.

### High impact (research depth)

4. **Blockchain: deeper flow**  
   - “Flow_trace” or “deep” mode: more pages of token/account transfers; optional 2–3 hop follow from counterparties.  
   - Small known-address list: tag mixer/CEX/casino in `flow_graph` so diagrams show “Mixer” / “CEX” where applicable.

5. **Cross-surface narrative**  
   - One “investigation summary” that ties: target → WHOIS/registrant → OSINT entities → blockchain deployer/counterparties (when keys set) → web exposures.  
   - Single place that says “this is what we know from web, this from chain, this from owner research.”

6. **Structured “confidence” or “source” on findings**  
   - Each finding: source (e.g. headers_ssl, solscan, arkham, ddg); optional confidence (high/medium/low).  
   - Reduces risk of treating inferred/placeholder data as verified.

### Medium impact

7. **OSINT: breach APIs**  
   - Where possible, use IntelX/Dehashed (or similar) APIs with keys for structured breach results; fallback to “check manually” link if no key.

8. **Blockchain: post-rug one-shot**  
   - Input = deployer or token only; run full pipeline without URL; report “live” when keys set.

9. **Entity: date and relevance**  
   - Entity reputation: extract and show year/range for each finding; “relevance” (direct hit vs same name/org).

---

## 4. Implemented (100% truthful data)

- **Crime report:** `data_sources` added (on_chain_used, on_chain_reason, flow_graph_from_live_data_only). Every blockchain report states explicitly whether data is from API or skipped.
- **Scan/attack completion:** Data status line (Blockchain: live | skipped, Entity, OSINT, Web) plus "_All findings from live tools; no placeholder data._"
- **Flow diagram:** Generated only when `on_chain_used` is true; never from placeholder data.
- **Tweet cards:** Card 4 and 5 use no fake addresses; card 5 shows structure only (Primary → Wallet → CEX) with "amount · date"; copy states real addresses only when API keys set.
- **.env.example:** Documents SOLSCAN_PRO_API_KEY, ARKHAM_API_KEY, ETHERSCAN_API_KEY and DIVERG_KNOWN_CEX_MIXER; "100% real data only when set."
- **Blockchain:** Multi-hop when `flow_depth=deep`: 1-hop transfers from top 3 counterparties added to flow graph. CEX/mixer tagging via Arkham labels and DIVERG_KNOWN_CEX_MIXER.

---

## 5. Summary

- **Accuracy:** Depends on real data (API keys). Stop showing placeholder wallets/dates as investigation result; label “live” vs “skipped/placeholder” and document which keys enable what.  
- **Research:** Deeper chain (multi-hop, mixer/CEX tags), better entity (APIs + optional court/sanctions), cross-surface narrative, and explicit source/confidence on findings will get us to top notch.

Use this as a checklist: implement the high-impact items first, then medium. Re-run the same target with keys set to compare “placeholder” vs “live” and tune from there.
