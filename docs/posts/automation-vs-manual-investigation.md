# 500 tabs or 5 minutes: the ZachXBT dilemma every security team faces

Easiest copy: `automation-vs-manual-investigation-plain.txt` (plain text; includes an X post block in Phase 3/4 ship-note format at the top). Tweet-only variants: [TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md](../TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md).

---

## The hook

You have seen the threads. One investigator, a frightening number of tabs, and a story that clearly took real time to assemble.

That work, the kind people associate with names like [ZachXBT](https://twitter.com/zachxbt), is not the problem. It is the standard for serious manual OSINT.

The problem is this: most teams do not get a spare week on every token, wallet, or deployment before they need a direction.

So the real question is not "can we replace the thread." It is "what do we do in the first hour when we still do not know if the case is worth a week."

That is where first-pass automation shows up.

---

## What this article is (and is not)

This article compares two modes of work. It is not a scorecard against any individual.

Any timing numbers here are order-of-magnitude illustrations for planning, not a lab race and not a claim about how any specific researcher spends their calendar.

---

## Two modes side by side

Manual expert investigation (thread-grade)

What you optimize for: judgment, context, and a story that holds up under scrutiny.

What the first meaningful pass often looks like: hours to days before you would brief someone or post, depending on depth and complexity.

What you get: narrative plus curated screenshots and links, tuned for persuasion.

Cross-chain and bridges: you hop chains by hand in explorers, bridge sites, labels.

Repeatability: the thread is the artifact; redoing the work is mostly manual.

Parallelism: usually one deep narrative at a time per investigator.

---

Diverg (automated triage)

What you optimize for: speed to a first structured picture, coverage, repeatability.

What the first meaningful pass often looks like: on the order of about two to twenty minutes wall-clock for a first machine pass on a target (bundle scan, domain scan, blockchain skill), depending on keys, rate limits, and scope.

What you get: JSON, dashboard findings, skills output, repeatable runs.

Cross-chain and bridges: bundled signals such as program allowlists, optional Wormhole Scan sampling for bridge-adjacent wallets, EVM bridge-contract style checks in structured reports where applicable.

Repeatability: run the same command or API again; compare scans over time (for example scan diff); history in console workflows.

Parallelism: many targets in parallel, within infra and policy limits.

---

Takeaway in one line: manual work wins on narrative finish and discretion. Automation wins on how fast you get to a first map and how many leads you can screen before you commit human weeks.

---

## Why speed on the first mile still matters

Automation does not replace legal judgment, compliance sign-off, or the decision to go public.

It compresses the messy opening phase.

Time to first map. Sketching who funded whom, whether clusters or bridges show up, and whether a token maps elsewhere can cost an analyst a large fraction of a day in explorer hopping. The same shape of signal can often surface in minutes as structured output (holders, clusters, bridge-adjacent wallets, cross-chain hints) before humans sharpen it.

Opportunity surface. If every case does not start from a blank spreadsheet, you can touch more targets, diff before and after a deploy or mint, and walk away faster when the machine pass is quiet.

Team efficiency. Outputs are easier to diff, export, and compare run to run, which matters more for internal triage than for a viral thread.

The comparison is not "Diverg versus ZachXBT." It is "dossier-grade manual work" versus "platform-grade first look." Plenty of teams will use both.

---

## Illustrative timing (planning only, not head-to-head)

Use these as rough heuristics only.

Initial wallet or token sketch

Manual: on the order of thirty minutes to four-plus hours before you trust your own notes.

Diverg: often about two to fifteen minutes to a first consolidated skill output.

Cross-chain hints plus bridge touches

Manual: often one to six-plus hours chaining explorers and registries.

Diverg: bundled into one pipeline pass in the same run, including optional Wormhole Scan sampling where configured.

Re-check after a new deployment or mint

Manual: large parts of the trace redone by hand.

Diverg: re-run the scan and compare reports (for example scan diff) for what changed.

Publishing bar

Manual: high, because social and legal stakes are real.

Diverg: output is triage under authorized use, not an automatic accusation or a substitute for verification on-chain.

One more caveat: a polished public thread is not the same artifact as a first machine pass. The minutes-to-low-tens-of-minutes band is not comparable to the polish bar of a finished investigation.

---

## What Diverg does not automate

Final legal or reputational judgment.

Public thread craft, tone, and community norms.

Your obligation to verify primary sources on official explorers and bridge documentation.

Replacing investigator discretion when the machine is wrong or incomplete.

---

## Closing

ZachXBT-style depth remains what many people picture when they say on-chain investigation, and that is for good reason.

Diverg-style automation is for teams that need faster first answers, more cases screened per week, and baselines they can reproduce, so people spend their depth budget where it counts.

Illustrative stats here are not claiming automation beats a named investigator on quality of final narrative. They only describe the lever platforms push: time to first structured signal and parallel throughput.

Authorized testing and professional use only. Verify what matters on-chain.

---

## Appendix: single post for social (copy-paste)

Manual thread-grade work (explorers, tabs, serious clock) optimizes for story and proof.

Diverg optimizes for first structured signal: minutes for a rough map versus hours by hand, re-run and diff instead of replaying the whole trace, many targets in parallel instead of one narrative at a time.

Different job: automation for triage speed and throughput, humans for final call and thread.

@DivergSec

---

## Appendix: thread for social (copy-paste)

1/ Everyone knows the manual masterclass: one investigator, infinite tabs, a thread that took serious clock. That is not what we are trying to replace.

2/ Diverg is the first mile: holders, funders, coordination heuristics, bridge and cross-chain flags. Machine output in about minutes to low tens of minutes versus the hours it takes to build the same map by hand before you know if the case matters.

3/ That gap is throughput: more leads screened, faster no, faster escalate to a human deep dive. Plus scan diff for what changed without replaying the whole manual movie.

4/ We are not claiming automation beats a finished public investigation on narrative quality. We are claiming it beats starting from zero on speed to a first structured picture. Authorized use. Verify on-chain.

---

## Related in this repo

Plain copy-paste: [automation-vs-manual-investigation-plain.txt](automation-vs-manual-investigation-plain.txt)

X post (Phase-style, matches Diverg phase announcements): [TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md](../TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md)

Scan diffing: [scan-diffing.md](scan-diffing.md)

More tweet variants: [TWEET_AUTOMATION_VS_MANUAL.md](../TWEET_AUTOMATION_VS_MANUAL.md)

Phase-style X post (same format as Phase 3/4 ship notes): [TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md](../TWEET_AUTOMATION_ZACHXBT_PHASE_STYLE.md)

Cross-chain / bundle note: [TWEET_CROSS_CHAIN_INVESTIGATION.md](../TWEET_CROSS_CHAIN_INVESTIGATION.md)
