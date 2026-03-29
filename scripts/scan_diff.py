#!/usr/bin/env python3
"""
Compare two Diverg scan reports and show what changed.

Sources (checked when using --target):
  1. Console database  (data/dashboard.db — scans from the web dashboard)
  2. CLI report files  (reports/*.json — from orchestrator.py)

Usage:
  python scripts/scan_diff.py --target example.com
  python scripts/scan_diff.py --target example.com --source db
  python scripts/scan_diff.py --target example.com --source files
  python scripts/scan_diff.py --old reports/old.json --new reports/new.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_DB_PATH = Path(
    os.environ.get(
        "DIVERG_DB_PATH", str(REPO_ROOT / "data" / "dashboard.db"),
    ).strip().lstrip("=")
)

SEVERITY_RANK = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_key(f: dict) -> tuple[str, str, str]:
    title = (f.get("title") or "").strip()[:120]
    url = (f.get("url") or "").strip()[:200]
    category = (f.get("category") or "").strip()[:80]
    return (title, url, category)


def _extract_domain(target: str) -> str:
    return (
        target.replace("https://", "").replace("http://", "").split("/")[0]
    )


def _friendly_ts(iso: str) -> str:
    """Turn an ISO timestamp into a short human-readable string."""
    if not iso:
        return "unknown date"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        # Portable day (avoid %-d / %#d — not portable across macOS vs Linux)
        mon = dt.strftime("%b")
        hm = dt.strftime("%H:%M")
        return f"{mon} {dt.day}, {dt.year} at {hm} UTC"
    except Exception:
        return iso[:19]


def _days_between(ts_old: str, ts_new: str) -> int | None:
    """Return the number of days between two ISO timestamps, or None."""
    try:
        a = datetime.fromisoformat(ts_old.replace("Z", "+00:00"))
        b = datetime.fromisoformat(ts_new.replace("Z", "+00:00"))
        return abs((b - a).days)
    except Exception:
        return None


def _short_label(label: str) -> str:
    """Shorten a label for display (truncate UUIDs, clean prefixes)."""
    if label.startswith("db:"):
        uid = label[3:]
        return f"scan {uid[:8]}"
    if label.startswith("file:"):
        return label[5:]
    return label


# ---------------------------------------------------------------------------
# Report loading — file-based
# ---------------------------------------------------------------------------

def _load_report(path: Path) -> dict:
    if not path.exists():
        print(f"Report not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _report_timestamp(data: dict) -> str:
    return data.get("timestamp") or data.get("scanned_at") or ""


def _find_reports_for_target(target: str) -> list[tuple[str, Path]]:
    """Return (timestamp, path) for file-based reports matching *target*."""
    domain = _extract_domain(target)
    domain_pat = re.compile(re.escape(domain), re.IGNORECASE)
    matches: list[tuple[str, Path]] = []
    if not REPORTS_DIR.is_dir():
        return []
    for p in REPORTS_DIR.glob("*.json"):
        try:
            data = _load_report(p)
        except Exception:
            continue
        t = data.get("target") or data.get("target_url") or ""
        if domain_pat.search(p.stem) or _extract_domain(t) == domain:
            matches.append((_report_timestamp(data), p))
    matches.sort(key=lambda x: x[0], reverse=True)
    return matches


# ---------------------------------------------------------------------------
# Report loading — database (web console scans)
# ---------------------------------------------------------------------------

def _find_db_scans_for_target(
    target: str,
    db_path: Path | None = None,
) -> list[dict]:
    """Return scan dicts from the console DB matching *target*."""
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
        try:
            report = json.loads(r.get("report_json") or "{}")
        except Exception:
            continue
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            continue
        ts = r.get("scanned_at") or r.get("created_at") or ""
        results.append({
            "label": f"db:{r.get('id', 'unknown')}",
            "timestamp": ts,
            "target_url": r.get("target_url", ""),
            "scope": r.get("scope", ""),
            "findings": findings,
        })
    return results


# ---------------------------------------------------------------------------
# Unified source: merge DB + files
# ---------------------------------------------------------------------------

def _find_all_for_target(
    target: str,
    source: str = "all",
    db_path: Path | None = None,
) -> list[dict]:
    """Return report dicts for *target*, newest first."""
    items: list[dict] = []

    if source in ("all", "db"):
        items.extend(_find_db_scans_for_target(target, db_path))

    if source in ("all", "files"):
        for _ts, path in _find_reports_for_target(target):
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

def diff_findings(
    old_findings: list[dict],
    new_findings: list[dict],
) -> dict:
    """Compare two finding lists → new / fixed / changed / unchanged."""
    old_map: dict[tuple, dict] = {}
    for f in old_findings:
        old_map.setdefault(_finding_key(f), f)

    new_map: dict[tuple, dict] = {}
    for f in new_findings:
        new_map.setdefault(_finding_key(f), f)

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

    def _sev(f: dict) -> int:
        return SEVERITY_RANK.get(
            (f.get("severity") or "Info").strip(), 99,
        )

    return {
        "new": sorted(
            [new_map[k] for k in new_keys], key=_sev,
        ),
        "fixed": sorted(
            [old_map[k] for k in fixed_keys], key=_sev,
        ),
        "changed": sorted(
            changed, key=lambda c: SEVERITY_RANK.get(c["new_severity"], 99),
        ),
        "unchanged": unchanged,
    }


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _sev_counts(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        sev = (f.get("severity") or "Info").strip()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _escape_md(s: str, max_len: int = 100) -> str:
    s = (s or "").strip().replace("\n", " ").replace("|", "\\|")
    return s[:max_len] + ("…" if len(s) > max_len else "")


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_output(
    diff: dict,
    old_label: str,
    new_label: str,
    old_data: dict,
    new_data: dict,
) -> str:
    old_ts = old_data.get("timestamp", "")
    new_ts = new_data.get("timestamp", "")
    target = (
        _extract_domain(new_data.get("target_url", ""))
        or _extract_domain(old_data.get("target_url", ""))
    )

    n_new = len(diff["new"])
    n_fixed = len(diff["fixed"])
    n_changed = len(diff["changed"])
    n_unch = len(diff["unchanged"])
    no_changes = (n_new == 0 and n_fixed == 0 and n_changed == 0)

    lines: list[str] = []

    # Header
    days = _days_between(old_ts, new_ts)
    gap = f" ({days} days apart)" if days and days > 0 else ""
    lines.append(f"Scan Diff for {target}{gap}")
    lines.append("=" * len(lines[0]))
    lines.append("")
    lines.append(
        f"  Old scan:  {_short_label(old_label)}  "
        f"— {_friendly_ts(old_ts)}"
    )
    lines.append(
        f"  New scan:  {_short_label(new_label)}  "
        f"— {_friendly_ts(new_ts)}"
    )
    lines.append("")

    # No-change fast path
    if no_changes:
        lines.append(
            f"No changes detected. "
            f"All {n_unch} finding(s) are the same as last scan."
        )
        return "\n".join(lines)

    # Counts table
    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])
    old_c = _sev_counts(old_findings)
    new_c = _sev_counts(new_findings)

    lines.append(
        f"  Findings:  {len(old_findings)} → {len(new_findings)}  "
        f"({n_new} new, {n_fixed} fixed, {n_changed} changed)"
    )
    lines.append("")

    # Severity breakdown
    sev_parts: list[str] = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        o, n = old_c.get(sev, 0), new_c.get(sev, 0)
        if o == 0 and n == 0:
            continue
        delta = n - o
        if delta > 0:
            sev_parts.append(f"  {sev}: {o} → {n} (+{delta})")
        elif delta < 0:
            sev_parts.append(f"  {sev}: {o} → {n} ({delta})")
        else:
            sev_parts.append(f"  {sev}: {n}")
    if sev_parts:
        lines.extend(sev_parts)
        lines.append("")

    # New findings
    if diff["new"]:
        lines.append(f"NEW ({n_new}):")
        for i, f in enumerate(diff["new"], 1):
            sev = f.get("severity", "Info")
            title = (f.get("title") or "Untitled")[:90]
            lines.append(f"  {i}. [{sev}] {title}")
        lines.append("")

    # Fixed findings
    if diff["fixed"]:
        lines.append(f"FIXED ({n_fixed}):")
        for i, f in enumerate(diff["fixed"], 1):
            sev = f.get("severity", "Info")
            title = (f.get("title") or "Untitled")[:90]
            lines.append(f"  {i}. [{sev}] {title}")
        lines.append("")

    # Changed severity
    if diff["changed"]:
        lines.append(f"CHANGED SEVERITY ({n_changed}):")
        for i, c in enumerate(diff["changed"], 1):
            title = (c["finding"].get("title") or "Untitled")[:90]
            lines.append(
                f"  {i}. {title}  "
                f"({c['old_severity']} → {c['new_severity']})"
            )
        lines.append("")

    return "\n".join(lines)


def format_markdown(
    diff: dict,
    old_label: str,
    new_label: str,
    old_data: dict,
    new_data: dict,
) -> str:
    """Full Markdown output (for --output file mode)."""
    old_ts = old_data.get("timestamp", "")
    new_ts = new_data.get("timestamp", "")
    target = (
        _extract_domain(new_data.get("target_url", ""))
        or _extract_domain(old_data.get("target_url", ""))
    )

    n_new = len(diff["new"])
    n_fixed = len(diff["fixed"])
    n_changed = len(diff["changed"])
    n_unch = len(diff["unchanged"])
    no_changes = (n_new == 0 and n_fixed == 0 and n_changed == 0)

    days = _days_between(old_ts, new_ts)
    gap = f" ({days} days apart)" if days and days > 0 else ""

    lines: list[str] = []
    lines.append(f"# Scan Diff: {target}{gap}")
    lines.append("")
    lines.append("| | Old | New |")
    lines.append("|---|---|---|")
    lines.append(
        f"| **Scan** | {_short_label(old_label)} "
        f"| {_short_label(new_label)} |"
    )
    lines.append(
        f"| **Date** | {_friendly_ts(old_ts)} "
        f"| {_friendly_ts(new_ts)} |"
    )

    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])
    old_c = _sev_counts(old_findings)
    new_c = _sev_counts(new_findings)

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        o, n = old_c.get(sev, 0), new_c.get(sev, 0)
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

    if no_changes:
        lines.append(
            f"> **No changes detected.** "
            f"All {n_unch} finding(s) are the same as last scan."
        )
        return "\n".join(lines)

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
                f"| {i} | {title} "
                f"| {c['old_severity']} | {c['new_severity']} |"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _resolve_items(args) -> tuple[dict, dict]:
    """Return (old_item, new_item) from CLI args."""
    if args.target:
        items = _find_all_for_target(
            args.target, source=args.source, db_path=args.db,
        )
        if len(items) < 2:
            src = {
                "all": "console DB + reports/",
                "db": "console DB",
                "files": "reports/",
            }[args.source]
            print(
                f"Need at least 2 scans for '{args.target}' in "
                f"{src} (found {len(items)}). "
                f"Run scans first or use --old / --new.",
                file=sys.stderr,
            )
            sys.exit(1)
        new_item, old_item = items[0], items[1]
        print(
            f"Comparing scans for {args.target}:",
            file=sys.stderr,
        )
        print(
            f"  Old: {_short_label(old_item['label'])} "
            f"({_friendly_ts(old_item['timestamp'])})",
            file=sys.stderr,
        )
        print(
            f"  New: {_short_label(new_item['label'])} "
            f"({_friendly_ts(new_item['timestamp'])})",
            file=sys.stderr,
        )
        return old_item, new_item

    if args.old and args.new:
        old_p = (
            args.old if args.old.is_absolute() else REPO_ROOT / args.old
        )
        new_p = (
            args.new if args.new.is_absolute() else REPO_ROOT / args.new
        )
        old_data = _load_report(old_p)
        new_data = _load_report(new_p)
        return (
            {
                "label": f"file:{old_p.name}",
                "timestamp": _report_timestamp(old_data),
                "target_url": (
                    old_data.get("target")
                    or old_data.get("target_url") or ""
                ),
                "findings": old_data.get("findings", []),
            },
            {
                "label": f"file:{new_p.name}",
                "timestamp": _report_timestamp(new_data),
                "target_url": (
                    new_data.get("target")
                    or new_data.get("target_url") or ""
                ),
                "findings": new_data.get("findings", []),
            },
        )

    print(
        "Provide --target <domain> or both --old and --new report paths.",
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compare two Diverg scan reports and show what changed",
    )
    ap.add_argument(
        "--target",
        help="Target domain — auto-finds and diffs the latest 2 scans",
    )
    ap.add_argument(
        "--source", choices=["all", "db", "files"], default="all",
        help="Where to look: db (console), files (reports/), "
             "or all (default)",
    )
    ap.add_argument(
        "--db", type=Path, default=None,
        help="Path to dashboard.db (default: data/dashboard.db)",
    )
    ap.add_argument(
        "--old", type=Path,
        help="Older report JSON (manual mode)",
    )
    ap.add_argument(
        "--new", type=Path,
        help="Newer report JSON (manual mode)",
    )
    ap.add_argument(
        "--output", "-o", type=Path,
        help="Write Markdown to file (terminal gets plain text by default)",
    )
    args = ap.parse_args()

    old_item, new_item = _resolve_items(args)
    diff = diff_findings(old_item["findings"], new_item["findings"])

    if args.output:
        md = format_markdown(
            diff, old_item["label"], new_item["label"],
            old_item, new_item,
        )
        out = (
            args.output if args.output.is_absolute()
            else REPO_ROOT / args.output
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"Diff written to {out}", file=sys.stderr)
    else:
        print(format_output(
            diff, old_item["label"], new_item["label"],
            old_item, new_item,
        ))


if __name__ == "__main__":
    main()
