# We gave our scanner 17 checks. Twitter won't like what we found.

**Use this as your thread or article. Each block is one tweet (or one paragraph).**

---

## Tweet 1 (hook)
We gave our scanner 17 checks. Twitter won't like what we found.

---

## Tweet 2
Most security tools run a handful of tests. Headers. Maybe some injection. Call it a day. We wanted to see what happens when you actually run the full stack — recon, headers, auth, APIs, payment flows, client-side leaks, the works. So we did.

---

## Tweet 3
Seventeen checks. Things like: Is the admin panel reachable? Can someone complete an order without paying? Are your cookies and tokens leaking into the frontend? Are third-party scripts reading storage? We're not naming names. But the pattern is clear.

---

## Tweet 4
Sites that handle money — launchpads, checkout flows, anything with a "pay" button — often pass the old-school tests. Green on headers, fine on basic injection. Then we hit the workflow. Can you skip the payment step? Submit zero? The number of places that said "yes" was not zero.

---

## Tweet 5
Another one: admin and debug surfaces. phpMyAdmin, /admin/, panels that should never see the public internet — reachable. With methods that can change or delete data. No auth. We're not talking about a niche corner of the web. We're talking about platforms people trust with funds.

---

## Tweet 6
Headers matter. Missing CSP, weak HSTS, no X-Frame-Options — we see it everywhere. It's not sexy. It doesn't trend. But it's the kind of thing that turns a single XSS or a single clickjacking into a very bad day. Most scans don't even look at half of it.

---

## Tweet 7
So we built something that does. Seventeen checks. No blockchain fluff in this run — just the web surface: what's exposed, what's misconfigured, what's abusable. The goal isn't to scare people. It's to show what "we ran a scan" could mean if you actually ran the scan.

---

## Tweet 8
If you're building in crypto, DeFi, or any product that touches payments — your token might be fine. Your contract might be fine. Your website might be wide open. We're not here to dunk. We're here to make the bar visible. So you can clear it.

---

## Tweet 9 (CTA)
We're Diverg. We run the full stack so you don't have to guess what's broken. Extension in the bio. Run it yourself. Then fix the stuff that shouldn't be there.

---

## Optional shorter CTA
We're Diverg. Full-stack security checks — the kind most tools skip. Try it: [link]

---

## Diagrams

Two HTML cards are in `content/twitter-article-17-checks-diagram.html`. Open in a browser and screenshot (or export as image) to drop into the thread.

- **Card 1 — "We gave our scanner 17 checks"**  
  Lists the 17 checks (recon, headers, workflow, payment, client-side, etc.). Use after Tweet 2 or 3.

- **Card 2 — "Twitter won't like what we found"**  
  Lists what we actually find (exposed admin, payment bypass risk, missing CSP, etc.). Use after Tweet 5 or 6.

Suggested placement: put Card 1 after Tweet 3, Card 2 after Tweet 6. Or use only one in the middle of the thread.

---

## Notes for the article
- Keep sentences short. One idea per sentence when you can.
- No "leverage," "robust," "comprehensive," "delve" — sounds like a press release.
- "We" and "you" are fine. Direct address.
- If you turn this into a blog post, use the same tone. Add the diagram after the "Seventeen checks" paragraph (Tweet 3).
