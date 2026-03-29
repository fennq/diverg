#!/usr/bin/env python3
"""
Compare two Diverg scan report JSONs and output a Markdown diff summary.

Auto-detect mode:  find the two most recent reports for a target domain in ./reports/
Manual mode:       supply two explicit report paths.

Usage:
  python scripts/scan_diff.py --target example.com
  python scripts/scan_diff.py --old reports/sectester_example.com_20260301_120000.json \
                               --new reports/sectester_example.com_20260315_120000.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


# ---------------------------------------------------------------------------
# Finding identity — used to match findings across two reports
# ---------------------------------------------------------------------------

def _finding_key(f: dict) -> tuple[str, str, str]:
    title = (f.get("title") or "").strip()[:120]
    url = (f.get("url") or "").strip()[:200]
    category = (f.get("category") or "").strip()[:80]
    return (title, url, category)


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def _load_report(path: Path) -> dict:
    if not path.exists():
        print(f"Report not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _extract_domain(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0]


def _report_domain(data: dict) -> str:
    target = data.get("target") or data.get("target_url") or ""
    return _extract_domain(target)


def _report_timestamp(data: dict) -> str:
    return data.get("timestamp") or data.get("scanned_at") or ""


def _find_reports_for_target(target: str) -> list[Path]:
    """Return report JSONs whose filename or payload target matches *target*, newest first."""
    domain = _extract_domain(target)
    domain_pattern = re.compile(re.escape(domain), re.IGNORECASE)
    matches: list[tuple[str, Path]] = []
    if not REPORTS_DIR.is_dir():
        return []
    for p in REPORTS_DIR.glob("*.json"):
        if domain_pattern.search(p.stem):
            try:
                data = _load_report(p)
                ts = _report_timestamp(data)
                matches.append((ts, p))
            except Exception:
                continue
        else:
            try:
                data = _load_report(p)
                if _extract_domain(_report_domain(data)) == domain:
                    ts = _report_timestamp(data)
                    matches.append((ts, p))
            except Exception:
                continue
    matches.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in matches]


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def diff_findings(old_findings: list[dict], new_findings: list[dict]) -> dict:
    """Compare two finding lists and classify each as new, fixed, changed, or unchanged."""
    old_map: dict[tuple, dict] = {}
    for f in old_findings:
        key = _finding_key(f)
        if key not in old_map:
            old_map[key] = f

    new_map: dict[tuple, dict] = {}
    for f in new_findings:
        key = _finding_key(f)
        if key not in new_map:
            new_map[key] = f

    new_keys = set(new_map) - set(old_map)
    fixed_keys = set(old_map) - set(new_map)
    common_keys = set(old_map) & set(new_map)

    changed: list[dict] = []
    unchanged: list[dict] = []
    for key in common_keys:
        old_sev = (old_map[key].get("severity") or "Info").strip()
        new_sev = (new_map[key].get("severity") or "Info").strip()
        if old_sev != new_sev:
            changed.append({
                "finding": new_map[key],
                "old_severity": old_sev,
                "new_severity": new_sev,
            })
        else:
            unchanged.append(new_map[key])

    def _sev_sort(finding: dict) -> int:
        return SEVERITY_RANK.get((finding.get("severity") or "Info").strip(), 99)

    sorted_new = [new_map[k] for k in sorted(new_keys, key=lambda k: _sev_sort(new_map[k]))]
    sorted_fixed = [old_map[k] for k in sorted(fixed_keys, key=lambda k: _sev_sort(old_map[k]))]

    return {
        "new": sorted_new,
        "fixed": sorted_fixed,
        "changed": sorted(changed, key=lambda c: SEVERITY_RANK.get(c["new_severity"], 99)),
        "unchanged": unchanged,
    }


# ---------------------------------------------------------------------------
# Severity summary counts
# ---------------------------------------------------------------------------

def _sev_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = (f.get("severity") or "Info").strip()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def _escape_md(s: str, max_len: int = 100) -> str:
    s = (s or "").strip().replace("\n", " ").replace("|", "\\|")
    return s[:max_len] + ("…" if len(s) > max_len else "")


def format_markdown(
    diff: dict,
    old_path: Path,
    new_path: Path,
    old_data: dict,
    new_data: dict,
) -> str:
    lines: list[str] = []
    old_ts = _report_timestamp(old_data)
    new_ts = _report_timestamp(new_data)
    target = _report_domain(new_data) or _report_domain(old_data)

    lines.append(f"# Scan Diff: {target}")
    lines.append("")
    lines.append("| | Old | New |")
    lines.append("|---|---|---|")
    lines.append(f"| **Report** | `{old_path.name}` | `{new_path.name}` |")
    lines.append(f"| **Timestamp** | {old_ts} | {new_ts} |")

    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])
    old_counts = _sev_counts(old_findings)
    new_counts = _sev_counts(new_findings)

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        o, n = old_counts.get(sev, 0), new_counts.get(sev, 0)
        delta = n - o
        arrow = f" (+{delta})" if delta > 0 else (f" ({delta})" if delta < 0 else "")
        lines.append(f"| **{sev}** | {o} | {n}{arrow} |")

    lines.append(f"| **Total** | {len(old_findings)} | {len(new_findings)} |")
    lines.append("")

    # Summary line
    n_new = len(diff["new"])
    n_fixed = len(diff["fixed"])
    n_changed = len(diff["changed"])
    n_unch = len(diff["unchanged"])
    lines.append(
        f"**Summary**: {n_new} new, {n_fixed} fixed, "
        f"{n_changed} changed severity, {n_unch} unchanged"
    )
    lines.append("")

    if diff["new"]:
        lines.append("## New findings")
        lines.append("")
        lines.append("| # | Severity | Title | Category |")
        lines.append("|---|----------|-------|----------|")
        for i, f in enumerate(diff["new"], 1):
            sev = f.get("severity", "Info")
            title = _escape_md(f.get("title", ""), 80)
            cat = _escape_md(f.get("category", ""), 40)
            lines.append(f"| {i} | {sev} | {title} | {cat} |")
        lines.append("")

    if diff["fixed"]:
        lines.append("## Fixed findings")
        lines.append("")
        lines.append("| # | Severity | Title | Category |")
        lines.append("|---|----------|-------|----------|")
        for i, f in enumerate(diff["fixed"], 1):
            sev = f.get("severity", "Info")
            title = _escape_md(f.get("title", ""), 80)
            cat = _escape_md(f.get("category", ""), 40)
            lines.append(f"| {i} | {sev} | {title} | {cat} |")
        lines.append("")

    if diff["changed"]:
        lines.append("## Changed severity")
        lines.append("")
        lines.append("| # | Title | Old | New |")
        lines.append("|---|-------|-----|-----|")
        for i, c in enumerate(diff["changed"], 1):
            title = _escape_md(c["finding"].get("title", ""), 80)
            lines.append(f"| {i} | {title} | {c['old_severity']} | {c['new_severity']} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compare two Diverg scan reports and output a Markdown diff",
    )
    ap.add_argument("--target", help="Target domain — auto-finds and diffs latest 2 reports in ./reports/")
    ap.add_argument("--old", type=Path, help="Path to the older report JSON")
    ap.add_argument("--new", type=Path, help="Path to the newer report JSON")
    ap.add_argument("--output", "-o", type=Path, help="Write Markdown output to file instead of stdout")
    args = ap.parse_args()

    if args.target:
        reports = _find_reports_for_target(args.target)
        if len(reports) < 2:
            print(
                f"Need at least 2 reports for '{args.target}' in {REPORTS_DIR}/ "
                f"(found {len(reports)}). Run scans first or use --old / --new.",
                file=sys.stderr,
            )
            sys.exit(1)
        new_path, old_path = reports[0], reports[1]
        print(f"Auto-detected reports for {args.target}:", file=sys.stderr)
        print(f"  Old: {old_path.name}", file=sys.stderr)
        print(f"  New: {new_path.name}", file=sys.stderr)
    elif args.old and args.new:
        old_path = args.old if args.old.is_absolute() else REPO_ROOT / args.old
        new_path = args.new if args.new.is_absolute() else REPO_ROOT / args.new
    else:
        ap.error("Provide --target <domain> or both --old and --new report paths.")
        return

    old_data = _load_report(old_path)
    new_data = _load_report(new_path)

    diff = diff_findings(old_data.get("findings", []), new_data.get("findings", []))
    md = format_markdown(diff, old_path, new_path, old_data, new_data)

    if args.output:
        out_path = args.output if args.output.is_absolute() else REPO_ROOT / args.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
        print(f"Diff written to {out_path}", file=sys.stderr)
    else:
        print(md)


if __name__ == "__main__":
    main()
