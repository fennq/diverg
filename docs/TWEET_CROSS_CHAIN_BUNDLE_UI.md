# Tweet — Cross-chain bundle UI cleanup (dashboard + extension)

**Code:** [`dashboard/js/app.js`](../dashboard/js/app.js) · [`dashboard/css/dashboard.css`](../dashboard/css/dashboard.css) · [`extension/popup.js`](../extension/popup.js)

**Related:** [`docs/TWEET_CROSS_CHAIN_INVESTIGATION.md`](TWEET_CROSS_CHAIN_INVESTIGATION.md) (registry + bundle signals ship note)

---

## Snippet (tiny)

```javascript
// dashboard/js/app.js — separate cross-chain from coordination, stats as tiles
const divider = '<hr class="inv-divider">';
let statGrid = `<div class="inv-cc-stat-grid">…</div>`; // Bridge activity, contacts, funder path, hints
coordLine += `<div class="inv-cross-chain-bundle">${divider}…${statGrid}…</div>`;
```

---

## Post (medium, same structure as Phase 3 / 4 ship notes)

**Cross-chain bundle UI** got a cleanup in Diverg.

- **Dashboard** — **plain-English stat grid** instead of one long jargon line; **divider** before the section; **collapsible** funders, shared bridge programs, Wormhole EVM links; first investigator note visible, rest under **More context**
- **Extension** — **one summary line** (activity + counts); **no hex** in the popup for EVM destinations — “see full report” only; **one** short note

Hints only — verify on **official explorers**. Authorized use.

---

## Short (~260 chars)

Diverg **bundle** cross-chain panel: **stat grid** + **divider**, **details** for deep lists, **More context** for extra notes. Extension: **one-line** triage, **no address spam**. @DivergSec

---

## Single post (copy-paste — normal tweet)

Shipped a **cross-chain / bridge** UI pass on Diverg’s Solana bundle.

Dashboard: **small stat tiles** (bridge activity, contacts, funder path, token hints), **section divider**, long stuff tucked into **collapsibles**, stacked-risk **one-liner** when it matters.

Extension popup: **single readable line** + wormhole **count** — not half a wallet address in a 300px box.

Hints only. @DivergSec

---

## Thread (3 posts) — optional

**1/** Cross-chain bundle output shouldn’t read like a stack trace. Diverg’s dashboard now uses a **stat grid** and **progressive disclosure** — scan the tiles, expand when you need the receipts.

**2/** **Stacked signals** (token hints + bridge-adjacent holders + mixer-tagged funders) get a **short escalation** line. Wormhole **EVM destinations** stay in a disclosure with explorer links.

**3/** The **extension** matches the same API with a **one-line summary** and “N EVM destinations — full report” instead of raw hex in the popup.
