# Twitter/X Thread: okara.ai/chat — We Scanned It. Here’s Why We Call It Safe.

Run the scan from the **main Diverg repo**, then fill the thread and diagrams with the results.

---

## 1. Run the scan (Sectester repo)

```bash
cd /path/to/Sectester   # main Diverg repo
pip install -r requirements.txt   # if not already
python3 scripts/scan_url.py "https://okara.ai/chat" > content/okara-scan-results.json
```

Open `content/okara-scan-results.json` and note:
- `summary.total_findings` or `len(findings)`
- Counts: `summary.critical`, `summary.high`, `summary.medium`, `summary.low`, `summary.info`

---

## 2. Screenshot the diagram cards

Open **`content/okara-scan-diagrams.html`** in Chrome (from the repo: `open content/okara-scan-diagrams.html` or drag the file into the browser).

- **Set your real counts** via URL params:  
  `?c=0&h=0&m=2&l=6&i=5`  
  (c=Critical, h=High, m=Medium, l=Low, i=Info). Use the same numbers from your scan results.
- **Screenshot each card** (scroll to each card, crop to the 1200×628 card frame). Use Card 1 for Tweet 4, Card 2 for Tweet 5. Card 3 is an optional “safe” badge.
---

## 3. Thread tweets (5 tweets — copy/paste ready)

**Tweet 1**  
We ran a full security scan on okara.ai/chat. Here’s the report. 🧵

**Tweet 2**  
17 checks: headers, TLS, cookies, CORS, path probe (admin, API, backup), client-side. No login. Just the URL.

**Tweet 3**  
0 Critical. 0 High. The rest were Low/Info — config and best-practice notes, not exploitable. For an AI chat product that handles real conversations, that’s a strong baseline.  
→ Attach screenshot: Card 1 (severity breakdown) from okara-scan-diagrams.html

**Tweet 4**  
We checked HTTPS, HSTS, security headers, cookie flags, CORS, 40+ paths, and client-side surface. One URL. Full picture.  
→ Attach screenshot: Card 2 (what we checked) from okara-scan-diagrams.html

**Tweet 5**  
AI chat sees a lot of sensitive input. okara.ai showing no Critical or High in a full scan is a signal they care about how it’s built. We’re calling that a really safe baseline. We use Diverg to scan before we recommend — try it on your own URL. 🔒

---

**Note:** If your scan has different severity counts, replace “0 Critical. 0 High” in Tweet 3 with your actual numbers (e.g. “1 High” if you had one).
