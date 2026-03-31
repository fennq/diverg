#!/usr/bin/env python3
"""
Adjudicate disputed bundle benchmark items in a repeatable queue.

Queue format is JSONL (one item per line), usually produced by:
  scripts/run_bundle_benchmark.py --queue-out ...
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_DECISIONS = {"confirmed_issue", "false_positive", "false_negative", "needs_more_data"}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t:
            continue
        rows.append(json.loads(t))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    payload = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows)
    if payload:
        payload += "\n"
    path.write_text(payload, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Adjudicate one benchmark queue item.")
    ap.add_argument("--queue", required=True, help="Path to adjudication queue JSONL")
    ap.add_argument("--case-id", required=True, help="Case ID to adjudicate")
    ap.add_argument("--signal", default=None, help="Optional signal key to narrow case item")
    ap.add_argument("--reviewer", required=True, help="Reviewer name/handle")
    ap.add_argument("--decision", required=True, choices=sorted(VALID_DECISIONS))
    ap.add_argument("--notes", required=True, help="Evidence-backed review notes")
    args = ap.parse_args()

    qpath = Path(args.queue)
    rows = _read_jsonl(qpath)

    target_idx = None
    for i, r in enumerate(rows):
        if str(r.get("case_id") or "") != args.case_id:
            continue
        if args.signal and str(r.get("signal") or "") != args.signal:
            continue
        if str(r.get("status") or "pending") != "pending":
            continue
        target_idx = i
        break

    if target_idx is None:
        raise SystemExit("No pending queue item matched case-id/signal.")

    rows[target_idx]["status"] = "adjudicated"
    rows[target_idx]["adjudication"] = {
        "decision": args.decision,
        "reviewer": args.reviewer,
        "notes": args.notes,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }

    _write_jsonl(qpath, rows)
    print(json.dumps(rows[target_idx], ensure_ascii=True))


if __name__ == "__main__":
    main()

"""
Legacy duplicate block removed.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t:
            continue
        out.append(json.loads(t))
    return out


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows) + ("\n" if rows else "")
    path.write_text(payload, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Adjudicate bundle benchmark queue entries.")
    ap.add_argument("--queue", required=True, help="Path to adjudication queue JSONL.")
    ap.add_argument("--case-id", required=True, help="Case id to adjudicate.")
    ap.add_argument("--signal", default=None, help="Optional signal filter (default all pending for case).")
    ap.add_argument("--reviewer", required=True, help="Reviewer name/handle.")
    ap.add_argument(
        "--decision",
        required=True,
        choices=("confirmed_issue", "false_positive", "false_negative", "needs_more_data"),
        help="Adjudication decision.",
    )
    ap.add_argument("--notes", required=True, help="Evidence-backed adjudication notes.")
    args = ap.parse_args()

    path = Path(args.queue)
    rows = _read_jsonl(path)
    changed = 0
    ts = datetime.now(timezone.utc).isoformat()
    for r in rows:
        if str(r.get("case_id") or "") != args.case_id:
            continue
        if args.signal and str(r.get("signal") or "") != args.signal:
            continue
        if str(r.get("status") or "pending") != "pending":
            continue
        r["status"] = "adjudicated"
        r["adjudication"] = {
            "reviewer": args.reviewer,
            "decision": args.decision,
            "notes": args.notes,
            "adjudicated_at": ts,
        }
        changed += 1

    _write_jsonl(path, rows)
    print(json.dumps({"updated": changed, "queue": str(path)}, ensure_ascii=True))


if __name__ == "__main__":
    main()

"""
Legacy duplicate block removed.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALID_DECISIONS = {"confirmed_issue", "false_positive", "false_negative", "needs_more_data"}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t:
            continue
        out.append(json.loads(t))
    return out


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows) + ("\n" if rows else "")
    path.write_text(data, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Adjudicate one queue item from bundle benchmark queue.")
    ap.add_argument("--queue", required=True, help="Queue JSONL path.")
    ap.add_argument("--case-id", required=True, help="Case ID to adjudicate.")
    ap.add_argument("--signal", default=None, help="Optional signal key (if multiple for same case).")
    ap.add_argument("--reviewer", required=True, help="Reviewer name/handle.")
    ap.add_argument("--decision", required=True, choices=sorted(VALID_DECISIONS))
    ap.add_argument("--notes", default="", help="Freeform evidence notes.")
    args = ap.parse_args()

    path = Path(args.queue)
    rows = _read_jsonl(path)
    found = False
    now = datetime.now(timezone.utc).isoformat()

    for row in rows:
        if str(row.get("case_id")) != args.case_id:
            continue
        if args.signal and str(row.get("signal")) != args.signal:
            continue
        row["status"] = "adjudicated"
        row["adjudication"] = {
            "reviewer": args.reviewer,
            "decision": args.decision,
            "notes": args.notes,
            "timestamp": now,
        }
        found = True

    if not found:
        raise SystemExit(f"No matching queue item found for case_id={args.case_id} signal={args.signal or '*'}")

    _write_jsonl(path, rows)
    print(json.dumps({"ok": True, "case_id": args.case_id, "signal": args.signal, "decision": args.decision}))


if __name__ == "__main__":
    main()

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t:
            continue
        rows.append(json.loads(t))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows)
    path.write_text(body + ("\n" if body else ""), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Adjudicate disputed bundle benchmark alerts.")
    ap.add_argument("--queue", default="data/benchmarks/adjudication_queue.jsonl")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--reviewer", required=True)
    ap.add_argument(
        "--decision",
        required=True,
        choices=("confirmed_issue", "false_positive", "false_negative", "needs_more_data"),
    )
    ap.add_argument("--notes", default="")
    args = ap.parse_args()

    p = Path(args.queue)
    rows = _read_jsonl(p)
    if not rows:
        print(f"No adjudication rows found: {p}")
        return 1

    found = False
    for r in rows:
        if str(r.get("case_id")) != args.case_id:
            continue
        r["status"] = "closed" if args.decision != "needs_more_data" else "pending"
        r["reviewer"] = args.reviewer
        r["decision"] = args.decision
        r["decision_notes"] = args.notes or None
        r["updated_at"] = _iso_now()
        found = True
        break

    if not found:
        print(f"Case not found in queue: {args.case_id}")
        return 2

    _write_jsonl(p, rows)
    print(f"Updated adjudication for case: {args.case_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

