# Tweet — Scan diffing (CLI)

**Diagram (SVG):** [`docs/diagrams/scan-diff-flow.svg`](diagrams/scan-diff-flow.svg)

**Long read:** [`docs/posts/scan-diffing.md`](posts/scan-diffing.md)

---

## Post (medium, same structure as Phase 3 / 4 ship notes)

**Scan diffing** is live in Diverg.

We compare **two scans for the same target** so you see the delta, not two full reports:

- **Sources** — **dashboard DB** (`scans.report_json` → `findings[]`) and/or **`reports/*.json`** from the orchestrator; same finding shape everywhere
- **Matching** — stable key on **title + URL + category** so the same issue tracks across runs
- **Buckets** — **new**, **fixed**, **changed severity**, **unchanged**
- **Output** — terminal, or **Markdown** with **`python scripts/scan_diff.py … -o delta.md`** for tickets and release notes
- **Config** — **`DIVERG_DB_PATH`** when the console DB isn’t `data/dashboard.db`

Authorized testing only.

---

## Short (~260 chars)

Scan diff in Diverg: **latest two runs per target**, **DB + reports/**, **new / fixed / severity change / unchanged**, **`-o` Markdown**. Same **`findings[]`** as console + orchestrator. `DIVERG_DB_PATH` when needed. @DivergSec

---

## Alt text (SVG)

Dark flowchart: Console database findings and reports JSON feed into scan_diff.py; arrows to output box listing new, fixed, changed severity, unchanged, terminal or markdown; footer shows example CLI command.

---

## Thread (3 posts) — optional

**1/** Two scans, same site — the question is **what changed**. Diverg’s **scan_diff** CLI compares the **latest two** runs: **new** findings, **fixed** ones, **severity moves**, and what stayed **unchanged**.

**2/** It pulls from the **dashboard DB** and/or **`reports/*.json`**, keys on **title + URL + category**, and prints a clear delta — or **`-o file.md`** for ship notes. Set **`DIVERG_DB_PATH`** if your DB path isn’t default.

**3/** Flow: **`docs/diagrams/scan-diff-flow.svg`** · write-up: **`docs/posts/scan-diffing.md`** · tool: **`scripts/scan_diff.py`**. Authorized use only.
