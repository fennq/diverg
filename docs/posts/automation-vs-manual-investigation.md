# Automation vs manual investigation: speed, scale, and where Diverg fits

High-signal blockchain OSINT—threads that map wallets, bridges, mixers, and narratives across months—has a clear public archetype: investigators who work **by hand** in explorers, spreadsheets, and screenshots, then publish when the story holds up. **[ZachXBT](https://twitter.com/zachxbt)** is widely cited for that style: deep, patient, manually assembled evidence chains.

**Diverg is built for a different layer of the same problem**: repeated, **automated first-pass investigations** that teams can run inside authorized workflows—so you get **structured output in minutes**, not after a full manual dossier is finished.

This article compares the two *modes* of work (not a scorecard against any individual). **Timing ranges below are order-of-magnitude illustrations** for planning conversations, not lab benchmarks or claims about a specific researcher’s calendar.

---

## Two ways to produce evidence

| | **Manual expert investigation** (thread-grade) | **Diverg (automated triage)** |
|--|--|--|
| **Primary output** | Narrative + curated screenshots, tuned for public persuasion | JSON / dashboard findings, skills output, reproducible runs |
| **Typical first meaningful pass** | Often **hours to days** before you’d publish or brief stakeholders—depending on chain depth, sleep, and case complexity | Often **~2–20 minutes** wall-clock for a **first machine pass** on a target (token bundle, domain scan, blockchain skill)—depending on API keys, rate limits, and scope |
| **Cross-chain / bridges** | Manual hops across Solana / EVM explorers, bridge UIs, labels | Bundled **program allowlists**, optional **Wormhole Scan** sampling, **EVM bridge-contract** checks in structured reports |
| **Repeatability** | The thread is the artifact; redoing everything is mostly manual | Same command / API again; **scan diff** over time; DB history in console workflows |
| **Parallelism** | Usually one narrative at a time per investigator | Many targets or tenants in parallel subject to infra and policy |

**Takeaway:** Manual work optimizes for **judgment, context, and story**. Automation optimizes for **speed to first hypothesis**, **coverage**, and **operational repeatability**.

---

## Why “quicker” matters (without claiming replacement)

Automated triage does **not** replace careful human review before legal, compliance, or public accusations. It **compresses** the early phase:

1. **Time to first map** — In illustrative terms, work that might take an analyst **a half-day of explorer hopping** to sketch who funded whom and whether bridges or clusters show up can often be **surfaced in minutes** as structured signals (holders, funder clustering, bridge-adjacent wallets, cross-chain hints).
2. **Opportunity surface** — When each case no longer **starts at zero** every time, you can **touch more targets**, run **before/after diffs**, and **deprioritize** faster when automation returns low signal.
3. **Efficiency for teams** — Outputs are **diffable**, **exportable**, and **consistent**—useful for internal triage, not only for public threads.

So the comparison isn’t “Diverg vs ZachXBT.” It’s **dossier-grade manual artistry** vs **platform-grade automated first looks**—and many organizations will use **both**: machines for breadth and speed; humans for final calls and narrative.

---

## Illustrative timing table (not measured head-to-head)

Use these only as **planning heuristics**.

| Stage | Manual (typical analyst workflow) | Diverg (automated) |
|-------|-------------------------------------|---------------------|
| **Initial wallet / token sketch** | ~30 min – 4+ hr before you trust your own notes | Often **~2–15 min** to first consolidated skill output |
| **Cross-chain hints + bridge touches** | Often **1–6+ hr** chaining explorers and registries | **Bundled** in one pipeline pass (plus optional Wormhole Scan sampling) in the same run |
| **Re-check after new deployment or mint** | Large portions of work **re-done by hand** | Re-run scan; **compare reports** (e.g. scan diff) for what changed |
| **Publishing bar** | High—social and legal stakes | Diverg emphasizes **authorized use**; automation output is **triage**, not automatic accusation |

---

## What Diverg does *not* automate

- Final **legal or reputational** judgment  
- **Public thread** craft, tone, and community norms  
- **Primary-source** ownership of every hop (you still verify on official explorers and bridge docs)  
- Replacement for **investigator discretion** where automation is wrong or incomplete  

---

## Closing

**ZachXBT-style work** remains the benchmark many people picture when they say “on-chain investigation”—because **depth and patience** are obvious in the output.

**Diverg-style automation** is for teams that need **faster first answers**, **more cases screened per week**, and **repeatable baselines**—so humans spend their time on the cases that actually deserve a manual deep dive.

**Illustrative stats** in this article are **not** a claim that any automated workflow beats any specific manual investigator on quality—only that **time-to-first-structured-signal** and **parallel throughput** are the lever automation is designed to move.

Authorized testing and professional use only. Verify everything that matters on-chain.

---

## Related in this repo

- [Scan diffing](scan-diffing.md) — what changed between two runs for the same target  
- Cross-chain / bundle context: [`docs/TWEET_CROSS_CHAIN_INVESTIGATION.md`](../TWEET_CROSS_CHAIN_INVESTIGATION.md) (high-level product note)
