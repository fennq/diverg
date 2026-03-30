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

## Post (medium)

Cleaned up how Diverg shows cross-chain / bridge stuff on the Solana bundle.

The dashboard had turned into one long line of numbers and jargon. Now it’s a few small tiles you can scan, a line between that block and the rest, and the heavy detail lives under expand/collapse. Extra investigator notes hide behind “more context” so you’re not staring at eight paragraphs.

The extension was worse — tiny popup, truncated 0x addresses everywhere. Now it’s basically one sentence plus “N destinations, open the full report if you care.”

Still hints. Still check the chain yourself. Authorized use only.

---

## Short (~260 chars)

Fixed the Solana bundle cross-chain UI: dashboard is tiles + fold-open detail instead of a wall of text; extension stops dumping half an address in a popup. Diverg. @DivergSec

---

## Single post (copy-paste — normal tweet)

The Solana bundle cross-chain section was unreadable — one mega paragraph of stats. Split it into actual tiles, put a divider in, shove the long lists under details.

Extension: same data, but you’re not decoding hex in a 300px window. One line + a count is enough.

@DivergSec

---

## Thread (3 posts) — optional

**1/** Cross-chain on the bundle scan used to dump everything in your face. We reworked the dashboard so you get a quick read first — numbers in a grid, boring stuff folded away.

**2/** When a bunch of signals stack (bridges + mixers + “this token might exist elsewhere”) there’s a short warning up top. The wormhole / EVM stuff is still there if you open it.

**3/** Chrome extension got the same idea: one summary, no fake “here’s six characters of an address” cosplay. Open the full result when you’re at a desk.
