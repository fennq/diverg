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
    lines.append("Optional: `BAGS_API_KEY` for Bags Sections 1–3 (creators/fees/claims, pool keys, per-claimer claim-stats).")
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
    bags = tok.get("bags") or {}
    if isinstance(bags, dict) and bags:
        lines.append("")
        lines.append("### Bags API (Sections 1–3)")
        lf = bags.get("lifetime_fees") or {}
        if isinstance(lf, dict) and lf.get("sol") is not None:
            lines.append(f"- **Lifetime fees (approx):** {lf.get('sol')} SOL (lamports: {lf.get('lamports')})")
        pool = bags.get("pool") or {}
        if isinstance(pool, dict) and pool.get("liquidity_stage"):
            lines.append(f"- **Liquidity stage:** `{pool.get('liquidity_stage')}` (DBC/DAMM context)")
            cc = pool.get("consistency_check") or {}
            if isinstance(cc, dict) and cc.get("mint_matches") is not None:
                lines.append(f"- **Mint consistency (API vs request):** {cc.get('mint_matches')}")
        cs = bags.get("claim_stats") or {}
        if isinstance(cs, dict) and not cs.get("error"):
            lines.append(
                f"- **Claim stats (Section 3):** {cs.get('claimers_count', '—')} fee claimers; "
                f"total claimed ~{cs.get('total_claimed_sol')} SOL; "
                f"creator share of total: {cs.get('creator_share_of_total')}; "
                f"top-1 share: {cs.get('top1_share_of_total')}; top-3 share: {cs.get('top3_share_of_total')}"
            )
        elif isinstance(cs, dict) and cs.get("error"):
            lines.append(f"- **Claim stats (Section 3):** error — {cs.get('error')}")
        if isinstance(cs, dict) and cs.get("distribution_label"):
            lines.append(
                f"- **Fee distribution (Section 3):** `{cs.get('distribution_label')}` "
                f"(HHI={cs.get('fee_herfindahl_index')}, top1 share={cs.get('top1_share_of_total')})"
            )
        rec = bags.get("claim_stats_reconciliation") or {}
        if isinstance(rec, dict) and not rec.get("error") and rec.get("events_to_stats_claimed_ratio") is not None:
            lines.append(
                f"- **Claim stats vs events sample:** ratio={rec.get('events_to_stats_claimed_ratio')} "
                f"(stats lamports {rec.get('stats_total_claimed_lamports')} vs events sample {rec.get('events_sample_total_claimed_lamports')})"
            )
        adm = bags.get("section3_fee_share_admin") or {}
        if isinstance(adm, dict) and adm.get("checks"):
            for chk in adm.get("checks", [])[:2]:
                lines.append(
                    f"- **Fee-share admin list:** creator `{chk.get('wallet', '')[:8]}…` → "
                    f"mint in admin scope: **{chk.get('mint_in_fee_share_admin_list')}** "
                    f"({chk.get('fee_share_admin_token_count')} tokens as admin)"
                )
        pl = bags.get("pools_list")
        if isinstance(pl, dict) and pl.get("count") is not None:
            lines.append(
                f"- **Bags pools list (optional):** {pl.get('count')} pools"
                f"{' (only migrated)' if pl.get('only_migrated') else ''}"
                f"; mint in list: **{pl.get('requested_mint_in_list')}**"
            )
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
