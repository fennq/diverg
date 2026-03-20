#!/usr/bin/env python3
"""
Read investigation/synq_data.json and prepend an "EVIDENCE FROM ON-CHAIN FETCH" section
to investigation/SYNQ_Investigation_Report.md (or update in place). Keeps rest of report intact.
Run after run_synq_research.py. Do not commit investigation/ to repo.
"""
import json
from pathlib import Path

BASE = Path(__file__).parent.parent
INV = BASE / "investigation"
DATA_PATH = INV / "synq_data.json"
REPORT_PATH = INV / "SYNQ_Investigation_Report.md"


def main():
    if not DATA_PATH.exists():
        print(f"Missing {DATA_PATH}. Run scripts/run_synq_research.py first.")
        return 1
    with open(DATA_PATH, encoding="utf-8") as f:
        data = json.load(f)

    lines = []
    lines.append("")
    lines.append("---")
    lines.append("## 2a. EVIDENCE FROM ON-CHAIN FETCH (auto-generated)")
    lines.append("")
    lines.append("Source: `investigation/synq_data.json` (from `scripts/run_synq_research.py`).")
    lines.append("RPC: Solana public getBalance + getSignaturesForAddress. Token: Solscan holder total + metadata.")
    lines.append("Optional: `HELIUS_API_KEY` for parsed wallet history/transfers; `ARKHAM_API_KEY` for address labels/entities.")
    lines.append("")
    lines.append("### Wallets (SOL balance, recent tx count, Helius/Arkham)")
    lines.append("")
    lines.append("| # | Address (short) | SOL | Recent sigs | Arkham entity/label |")
    lines.append("|---|-----------------|-----|-------------|----------------------|")
    for i, w in enumerate(data.get("wallets", []), 1):
        addr = w.get("address", "")
        short = f"{addr[:8]}...{addr[-8:]}" if len(addr) > 20 else addr
        sol = w.get("sol_balance_sol")
        sol_s = f"{sol:.4f}" if sol is not None else "—"
        count = w.get("recent_signatures_count", 0)
        arkham = w.get("arkham_summary") or {}
        entity = arkham.get("entity_name") or arkham.get("label_name") or "—"
        lines.append(f"| {i} | {short} | {sol_s} | {count} | {entity} |")
    lines.append("")
    lines.append("### Token of interest")
    lines.append("")
    tok = data.get("token") or {}
    mint = tok.get("mint", "")
    total = tok.get("holders_total") or {}
    meta = tok.get("metadata") or {}
    lines.append(f"- **Mint:** `{mint}`")
    lines.append(f"- **Holders (total):** {total.get('holders', '—')}")
    lines.append(f"- **Supply (raw):** {total.get('supply', '—')}")
    if meta:
        lines.append(f"- **Metadata (Solscan):** price_usdt={meta.get('price_usdt')}, marketcap={meta.get('marketcap')} (verify on explorer — may be SOL market data if wrong endpoint).")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not REPORT_PATH.exists():
        REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote new {REPORT_PATH}")
        return 0

    body = REPORT_PATH.read_text(encoding="utf-8")
    # Insert new section 2a between "---" after section 2 and "## 3. WALLET REGISTER"
    needle = "\n---\n\n## 3. WALLET REGISTER"
    insertion = "\n---\n\n" + "\n".join(lines) + "\n## 3. WALLET REGISTER"
    if needle in body:
        new_body = body.replace(needle, insertion, 1)
    else:
        new_body = body + "\n\n" + "\n".join(lines)
    REPORT_PATH.write_text(new_body, encoding="utf-8")
    print(f"Updated {REPORT_PATH} with on-chain evidence section.")
    return 0


if __name__ == "__main__":
    exit(main())
