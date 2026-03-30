# Tweet + asset — scan diffing (CLI)

**What shipped:** `scripts/scan_diff.py` compares two Diverg scans for the same target and buckets findings as **new**, **fixed**, **changed severity**, and **unchanged**. Same `findings[]` shape as the web console (`scans.report_json`) and orchestrator JSON under `reports/`.

**Visual (recommended):** `docs/diagrams/scan-diff-flow.svg` — dark theme flow: Console DB + `reports/*.json` → `scan_diff.py` → delta buckets.

**Long read:** `docs/posts/scan-diffing.md`

---

## Single post (medium)

**Scan diffing** — stop eyeballing two JSON exports.

Diverg’s CLI picks the **latest two** runs for a host (from the **dashboard DB**, from **`reports/*.json`**, or both), keys each finding by **title + URL + category**, and tells you what **appeared**, what **disappeared**, what **moved in severity**, and what stayed the same.

Pipe to **Markdown** with `-o` for release notes or tickets. Set `DIVERG_DB_PATH` if your DB isn’t `data/dashboard.db`.

Authorized testing only. @DivergSec

---

## Short (~280 chars)

Scan diff for Diverg: compare two runs per target → **new / fixed / changed severity / unchanged**. Same finding schema as console + CLI JSON. `python scripts/scan_diff.py --target example.com` or `-o delta.md`. Diagram: repo `docs/diagrams/scan-diff-flow.svg`. @DivergSec

---

## Thread (3 posts)

**1/** Two scans, same site — the useful question is **what changed**. We added a small CLI that diffs Diverg reports: new issues, cleared items, severity shifts, unchanged noise.

**2/** It reads **dashboard history** and/or **`reports/*.json`**, matches findings on title + URL + category, and prints a clear delta. Optional **`-o file.md`** for tickets or ship notes.

**3/** Flow diagram: `docs/diagrams/scan-diff-flow.svg` · write-up: `docs/posts/scan-diffing.md` · tool: `scripts/scan_diff.py`. Use only on systems you’re allowed to test.
