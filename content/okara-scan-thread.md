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

## 3. Thread tweets

**Tweet 1 (Hook)**  
We ran a full security scan on https://okara.ai/chat — the AI chat product. Here’s the report. 🧵

**Tweet 2 (What we ran)**  
Diverg ran 17 checks: headers, TLS, cookies, CORS, path probe (admin, API, backup, config), client-side surface, and more. No login. Just the URL.

**Tweet 3 (The result — safe angle)**  
[FILL: e.g. "0 Critical. 0 High."] The rest were Low/Info — configuration and best-practice notes, not exploitable issues. For an AI chat product that handles conversations, that’s a strong baseline.

**Tweet 4 (Diagram — attach Card 1: Severity breakdown)**  
[Attach screenshot of Card 1 from okara-scan-diagrams.html]

**Tweet 5 (Diagram — attach Card 2: What we checked)**  
[Attach screenshot of Card 2 from okara-scan-diagrams.html]

**Tweet 6 (Why “safe” matters for AI)**  
AI chat products see a lot of sensitive input. okara.ai showing [FILL: e.g. "no Critical/High"] in a full scan is a signal they care about transport, headers, and exposure. We’re calling that a really safe baseline.

**Tweet 7 (CTA)**  
We use Diverg to scan before we recommend. Full scan or focused (headers, payment, admin). Try it on your own URL. 🔒

---

## 4. Short copy for “really safe” angle

- “We scanned okara.ai. No Critical, no High. We’re calling that a really safe baseline.”
- “okara.ai/chat — full security scan. Strong headers, clean path probe. Safe to recommend.”
- “AI chat that handles sensitive convos — we ran 17 checks on okara.ai. Here’s why we call it safe.”
