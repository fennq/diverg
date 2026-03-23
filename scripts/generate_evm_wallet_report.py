#!/usr/bin/env python3
"""
Build markdown report from EVM wallet investigation JSON.

Usage:
  python scripts/generate_evm_wallet_report.py --in investigation/evm_wallet_x.json --out investigation/REPORT.md
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _fmt_amt(v):
    try:
        return f"{float(v):,.6f}"
    except Exception:
        return str(v)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate markdown report from EVM investigation JSON")
    ap.add_argument("--in", dest="input_path", required=True, help="Input JSON path")
    ap.add_argument("--out", dest="output_path", required=True, help="Output markdown path")
    args = ap.parse_args()

    in_path = Path(args.input_path)
    out_path = Path(args.output_path)
    if not in_path.exists():
        print(f"Missing input file: {in_path}")
        return 1

    data = json.loads(in_path.read_text(encoding="utf-8"))
    wallet = data.get("wallet")
    origin = data.get("origin_funders") or {}
    native = origin.get("first_native_funder") or {}
    token = origin.get("first_token_funder") or {}
    wash = data.get("cex_wash_assessment") or {}
    cps = data.get("major_counterparties") or []
    lineage = data.get("native_lineage") or []
    pass_pairs = data.get("pass_through_pairs") or []
    linked = ((data.get("linked_wallets_by_time") or {}).get("linked_wallets")) or []
    addr_info = data.get("address_info") or {}

    lines = []
    lines.append("# Diverg EVM Wallet Investigation")
    lines.append("")
    lines.append("## Scope")
    lines.append(f"- Target wallet: `{wallet}`")
    lines.append("- Chain: Ethereum")
    lines.append("- Goal: identify original funder, test CEX-wash behavior, and map timestamp-linked wallets.")
    lines.append("")
    lines.append("## Executive summary")
    lines.append(f"- First native funder: `{native.get('address')}`")
    lines.append(f"- First token funder: `{token.get('address')}` ({token.get('token_symbol')})")
    lines.append(
        f"- Wash heuristic score: **{wash.get('score_0_to_100')} / 100** ({wash.get('risk_level')})"
    )
    lines.append(f"- Detected pass-through pairs: **{len(pass_pairs)}**")
    lines.append(f"- Current ETH balance snapshot: **{addr_info.get('eth_balance')} ETH**")
    lines.append("")
    lines.append("## Native funder lineage")
    lines.append("| Hop | Wallet | Funder | Timestamp | Value ETH |")
    lines.append("|---|---|---|---:|---:|")
    for row in lineage:
        lines.append(
            f"| {row.get('hop')} | `{row.get('address')}` | `{row.get('funder')}` | {row.get('timestamp')} | {row.get('value_eth')} |"
        )
    lines.append("")
    lines.append("## Major counterparties")
    lines.append("| Counterparty | Interactions | Approx token amount sum |")
    lines.append("|---|---:|---:|")
    for c in cps[:12]:
        lines.append(
            f"| `{c.get('address')}` | {c.get('interaction_count')} | {_fmt_amt(c.get('approx_amount_sum'))} |"
        )
    lines.append("")
    lines.append("## Pass-through evidence")
    lines.append("| Token | In amount | Out amount | Delta sec | In from | Out to |")
    lines.append("|---|---:|---:|---:|---|---|")
    for p in pass_pairs[:30]:
        lines.append(
            f"| {p.get('token')} | {_fmt_amt(p.get('in_amount'))} | {_fmt_amt(p.get('out_amount'))} | {p.get('time_delta_s')} | `{p.get('in_from')}` | `{p.get('out_to')}` |"
        )
    lines.append("")
    lines.append("## Timestamp-linked wallets around counterparties")
    lines.append("| Wallet | Co-occurrence count |")
    lines.append("|---|---:|")
    for lw in linked[:30]:
        lines.append(f"| `{lw.get('address')}` | {lw.get('co_occurrence')} |")
    lines.append("")
    lines.append("## Notes")
    lines.append("- This report is behavior-focused and does not claim real-world identity.")
    lines.append("- CEX-wash result is heuristic scoring, not legal conclusion.")
    lines.append("- For stronger attribution, enrich with Arkham/Nansen/TRM labels and exchange wallet datasets.")
    lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

