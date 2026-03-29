#!/usr/bin/env python3
"""
Compare two Diverg scan report JSONs and output a Markdown diff summary.

Sources (checked in order when using --target):
  1. Console database  (data/dashboard.db — scans stored by the web API)
  2. CLI report files  (reports/*.json — written by orchestrator.py)

Usage:
  python scripts/scan_diff.py --target example.com
  python scripts/scan_diff.py --target example.com --source db
  python scripts/scan_diff.py --target example.com --source files
  python scripts/scan_diff.py --old reports/sectester_example.com_20260301_120000.json \\
                               --new reports/sectester_example.com_20260315_120000.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_DB_PATH = Path(
    os.environ.get("DIVERG_DB_PATH", str(REPO_ROOT / "data" / "dashboard.db"))
    .strip().lstrip("=")
)

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
# Report loading — file-based
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


def _find_reports_for_target(target: str) -> list[tuple[str, Path]]:
    """Return (timestamp, path) pairs for file-based reports matching *target*, newest first."""
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
    return matches


# ---------------------------------------------------------------------------
# Report loading — database (web console scans)
# ---------------------------------------------------------------------------

def _find_db_scans_for_target(
    target: str,
    db_path: Path | None = None,
) -> list[dict]:
    """Return scan dicts from the console DB matching *target*, newest first.

    Each returned dict has keys: label, timestamp, findings, target_url,
    scope — mirroring the shape used by the rest of this script.
    """
    db = db_path or DEFAULT_DB_PATH
    if not db.exists():
        return []
    domain = _extract_domain(target)
    try:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, target_url, scope, scanned_at, created_at,
                      report_json
               FROM scans
               WHERE target_url LIKE ?
               ORDER BY COALESCE(scanned_at, created_at) DESC""",
            (f"%{domain}%",),
        ).fetchall()
        conn.close()
    except Exception:
        return []

    results: list[dict] = []
    for row in rows:
        r = dict(row)
        report_json = r.get("report_json") or "{}"
        try:
            report = json.loads(report_json)
        except Exception:
            continue
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            continue
        ts = r.get("scanned_at") or r.get("created_at") or ""
        scan_id = r.get("id", "unknown")
        results.append({
            "label": f"db:{scan_id}",
            "timestamp": ts,
            "target_url": r.get("target_url", ""),
            "scope": r.get("scope", ""),
            "findings": findings,
        })
    return results


# ---------------------------------------------------------------------------
# Unified report source: merge DB + file sources
# ---------------------------------------------------------------------------

def _find_all_for_target(
    target: str,
    source: str = "all",
    db_path: Path | None = None,
) -> list[dict]:
    """Return report dicts for *target* from requested sources, newest first.

    Each dict has keys: label, timestamp, findings, target_url.
    """
    items: list[dict] = []

    if source in ("all", "db"):
        items.extend(_find_db_scans_for_target(target, db_path))

    if source in ("all", "files"):
        for ts, path in _find_reports_for_target(target):
            try:
                data = _load_report(path)
            except Exception:
                continue
            items.append({
                "label": f"file:{path.name}",
                "timestamp": _report_timestamp(data),
                "target_url": (
                    data.get("target") or data.get("target_url") or ""
                ),
                "findings": data.get("findings", []),
            })

    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return items


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
        return SEVERITY_RANK.get(
            (finding.get("severity") or "Info").strip(), 99,
        )

    sorted_new = [
        new_map[k]
        for k in sorted(new_keys, key=lambda k: _sev_sort(new_map[k]))
    ]
    sorted_fixed = [
        old_map[k]
        for k in sorted(fixed_keys, key=lambda k: _sev_sort(old_map[k]))
    ]

    return {
        "new": sorted_new,
        "fixed": sorted_fixed,
        "changed": sorted(
            changed,
            key=lambda c: SEVERITY_RANK.get(c["new_severity"], 99),
        ),
        "unchanged": unchanged,
    }


# ---------------------------------------------------------------------------
# Severity summary counts
# ---------------------------------------------------------------------------

def _sev_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
    }
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
    old_label: str,
    new_label: str,
    old_data: dict,
    new_data: dict,
) -> str:
    lines: list[str] = []
    old_ts = old_data.get("timestamp", "")
    new_ts = new_data.get("timestamp", "")
    target = (
        _extract_domain(new_data.get("target_url", ""))
        or _extract_domain(old_data.get("target_url", ""))
    )

    lines.append(f"# Scan Diff: {target}")
    lines.append("")
    lines.append("| | Old | New |")
    lines.append("|---|---|---|")
    lines.append(f"| **Report** | `{old_label}` | `{new_label}` |")
    lines.append(f"| **Timestamp** | {old_ts} | {new_ts} |")

    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])
    old_counts = _sev_counts(old_findings)
    new_counts = _sev_counts(new_findings)

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        o, n = old_counts.get(sev, 0), new_counts.get(sev, 0)
        delta = n - o
        if delta > 0:
            arrow = f" (+{delta})"
        elif delta < 0:
            arrow = f" ({delta})"
        else:
            arrow = ""
        lines.append(f"| **{sev}** | {o} | {n}{arrow} |")

    lines.append(
        f"| **Total** | {len(old_findings)} | {len(new_findings)} |"
    )
    lines.append("")

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
            lines.append(
                f"| {i} | {title} | {c['old_severity']}"
                f" | {c['new_severity']} |"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compare two Diverg scan reports and output a Markdown diff",
    )
    ap.add_argument(
        "--target",
        help="Target domain — auto-finds and diffs the latest 2 scans "
             "(from console DB and/or ./reports/)",
    )
    ap.add_argument(
        "--source",
        choices=["all", "db", "files"],
        default="all",
        help="Where to look for scans: 'db' (console), "
             "'files' (reports/), or 'all' (default: all)",
    )
    ap.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to dashboard.db (default: data/dashboard.db)",
    )
    ap.add_argument(
        "--old", type=Path,
        help="Path to the older report JSON (manual mode)",
    )
    ap.add_argument(
        "--new", type=Path,
        help="Path to the newer report JSON (manual mode)",
    )
    ap.add_argument(
        "--output", "-o", type=Path,
        help="Write Markdown output to file instead of stdout",
    )
    args = ap.parse_args()

    if args.target:
        items = _find_all_for_target(
            args.target,
            source=args.source,
            db_path=args.db,
        )
        if len(items) < 2:
            sources_msg = {
                "all": "console DB + reports/",
                "db": "console DB",
                "files": "reports/",
            }[args.source]
            print(
                f"Need at least 2 scans for '{args.target}' in "
                f"{sources_msg} (found {len(items)}). "
                f"Run scans first or use --old / --new.",
                file=sys.stderr,
            )
            sys.exit(1)
        new_item, old_item = items[0], items[1]
        print(
            f"Auto-detected scans for {args.target}:",
            file=sys.stderr,
        )
        print(f"  Old: {old_item['label']}", file=sys.stderr)
        print(f"  New: {new_item['label']}", file=sys.stderr)

        diff = diff_findings(
            old_item["findings"], new_item["findings"],
        )
        md = format_markdown(
            diff,
            old_item["label"],
            new_item["label"],
            old_item,
            new_item,
        )
    elif args.old and args.new:
        old_path = (
            args.old if args.old.is_absolute() else REPO_ROOT / args.old
        )
        new_path = (
            args.new if args.new.is_absolute() else REPO_ROOT / args.new
        )
        old_data = _load_report(old_path)
        new_data = _load_report(new_path)

        diff = diff_findings(
            old_data.get("findings", []),
            new_data.get("findings", []),
        )
        md = format_markdown(
            diff,
            f"file:{old_path.name}",
            f"file:{new_path.name}",
            {
                "timestamp": _report_timestamp(old_data),
                "target_url": (
                    old_data.get("target")
                    or old_data.get("target_url")
                    or ""
                ),
                "findings": old_data.get("findings", []),
            },
            {
                "timestamp": _report_timestamp(new_data),
                "target_url": (
                    new_data.get("target")
                    or new_data.get("target_url")
                    or ""
                ),
                "findings": new_data.get("findings", []),
            },
        )
    else:
        ap.error(
            "Provide --target <domain> or both --old and --new report paths."
        )
        return

    if args.output:
        out = (
            args.output if args.output.is_absolute()
            else REPO_ROOT / args.output
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"Diff written to {out}", file=sys.stderr)
    else:
        print(md)


if __name__ == "__main__":
    main()
