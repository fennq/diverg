# Tweet — Cross-chain bundle UI + signals (dashboard + extension)

**Code:** [`dashboard/js/app.js`](../dashboard/js/app.js) (`_invTokenBundleSummaryHtml` cross-chain block) · [`extension/popup.js`](../extension/popup.js) (`renderSolResult` cross-chain card)

---

## Post (medium)

**Cross-chain bundle signals** in Diverg are easier to read now.

On the **dashboard**, we replace a jargon-heavy single-line stat dump with a **small grid** — “Bridge activity”, **wallets with bridge contacts**, **funded via bridge path**, and **cross-chain token hints** when relevant. A divider separates this from coordination signals above. **Stacked-risk** cases get a short escalation line. Deep detail stays in **collapsible** sections (funders, shared bridge programs, Wormhole EVM destinations). The first investigator note is visible; **“More context”** holds the rest.

The **Chrome extension** keeps one **compact summary line** (activity + counts + mixer hints), **no hex dumps** for EVM destinations in the popup — “see full report” instead — and **one** short note.

Hints only — verify on **official explorers** and bridge docs. Authorized use.

---

## Short (~260 chars)

Diverg **Solana bundle** cross-chain UI: **plain-English stat grid**, divider from coordination block, **collapsible** funder/Wormhole/bridge detail, notes **progressive disclosure**. Extension: **one-line summary**, **no spammy hex** in the popup. Hints only. @DivergSec

---

## Thread (3 posts) — optional

**1/** Bundle scans shouldn’t bury you in acronyms. Diverg’s **cross-chain / bridge** panel on the dashboard now uses a **simple stat grid** and pulls long lists into **details** — first investigator note up front, rest under **More context**.

**2/** When **stacked** signals fire (token hints + bridge-adjacent holders + mixer-tagged paths), you get a **short escalation line** — triage first, dig in second. Wormhole **EVM destinations** stay behind a disclosure with explorer links.

**3/** The **extension** stays tiny: **one summary line** + “Wormhole bridge history: N destinations — see full report” instead of half addresses in a popup. Same pipeline, calmer UX.
