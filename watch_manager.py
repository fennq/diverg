"""
Continuous Threat Monitor (CTM) — scheduled watch targets with automatic diff & alerting.

Manages watch registrations, background scan scheduling, finding-level diffing between
consecutive runs, risk-score trend tracking, and webhook notifications on meaningful deltas.

Used by api_server.py — all DB operations use the same SQLite database via _db() helper.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Callable

log = logging.getLogger("diverg.watch")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CADENCE_SECONDS = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
}

VALID_CADENCES = tuple(CADENCE_SECONDS.keys())

# Per-user limits
MAX_WATCHES_PER_USER = int(os.environ.get("DIVERG_MAX_WATCHES_PER_USER", "20"))

# Scheduler tick interval (seconds)
SCHEDULER_TICK = int(os.environ.get("DIVERG_WATCH_SCHEDULER_TICK", "60"))

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

WATCH_SCHEMA = """
CREATE TABLE IF NOT EXISTS watches (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    target_url   TEXT NOT NULL,
    scope        TEXT NOT NULL DEFAULT 'quick',
    cadence      TEXT NOT NULL DEFAULT 'daily',
    webhook_url  TEXT DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',
    last_run_at  TEXT,
    next_run_at  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_runs (
    id           TEXT PRIMARY KEY,
    watch_id     TEXT NOT NULL,
    scan_id      TEXT,
    risk_score   INTEGER,
    risk_verdict TEXT,
    total        INTEGER DEFAULT 0,
    critical     INTEGER DEFAULT 0,
    high         INTEGER DEFAULT 0,
    medium       INTEGER DEFAULT 0,
    low          INTEGER DEFAULT 0,
    info         INTEGER DEFAULT 0,
    diff_json    TEXT,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (watch_id) REFERENCES watches(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_watches_user ON watches(user_id);
CREATE INDEX IF NOT EXISTS idx_watches_next_run ON watches(next_run_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_watch_runs_watch ON watch_runs(watch_id);
"""


def init_watch_tables(conn) -> None:
    """Create CTM tables if they don't exist. Called from api_server init_db()."""
    conn.executescript(WATCH_SCHEMA)


# ---------------------------------------------------------------------------
# Finding diff engine (inline, mirrors scripts/scan_diff.py diff_findings)
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding_key(f: dict) -> tuple[str, str, str]:
    title = (f.get("title") or "").strip()[:120]
    url = (f.get("url") or "").strip()[:200]
    category = (f.get("category") or "").strip()[:80]
    return (title, url, category)


def diff_findings(old_findings: list[dict], new_findings: list[dict]) -> dict:
    """Compare two finding lists -> new / fixed / changed / unchanged."""
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
        return SEVERITY_RANK.get((f.get("severity") or "Info").strip(), 99)

    return {
        "new": sorted([new_map[k] for k in new_keys], key=_sev),
        "fixed": sorted([old_map[k] for k in fixed_keys], key=_sev),
        "changed": sorted(changed, key=lambda c: SEVERITY_RANK.get(c["new_severity"], 99)),
        "unchanged": unchanged,
    }


def diff_is_meaningful(diff: dict) -> bool:
    """True if the diff contains any new, fixed, or severity-changed findings."""
    return bool(diff.get("new") or diff.get("fixed") or diff.get("changed"))


def diff_summary(diff: dict, old_score: int | None, new_score: int | None) -> dict:
    """Build a compact JSON summary of what changed between two runs."""
    summary: dict = {
        "new_findings": len(diff.get("new", [])),
        "fixed_findings": len(diff.get("fixed", [])),
        "severity_changed": len(diff.get("changed", [])),
        "unchanged": len(diff.get("unchanged", [])),
    }

    # Severity counts for new findings only
    new_by_sev: dict[str, int] = {}
    for f in diff.get("new", []):
        sev = (f.get("severity") or "Info").strip()
        new_by_sev[sev] = new_by_sev.get(sev, 0) + 1
    if new_by_sev:
        summary["new_by_severity"] = new_by_sev

    # Risk score drift
    if old_score is not None and new_score is not None:
        delta = new_score - old_score
        summary["risk_score_old"] = old_score
        summary["risk_score_new"] = new_score
        summary["risk_score_delta"] = delta
        if delta < -10:
            summary["risk_trend"] = "degrading"
        elif delta > 10:
            summary["risk_trend"] = "improving"
        else:
            summary["risk_trend"] = "stable"

    return summary


# ---------------------------------------------------------------------------
# Severity count helper
# ---------------------------------------------------------------------------

def _count_severity(findings: list, level: str) -> int:
    return sum(1 for f in findings if (f.get("severity") or "").lower() == level.lower())


# ---------------------------------------------------------------------------
# Watch CRUD
# ---------------------------------------------------------------------------

def create_watch(
    conn,
    user_id: str,
    target_url: str,
    scope: str = "quick",
    cadence: str = "daily",
    webhook_url: str = "",
) -> dict:
    """Create a new watch target. Returns the watch dict."""
    # Check user limit
    count = conn.execute(
        "SELECT COUNT(*) FROM watches WHERE user_id = ? AND status != 'deleted'",
        (user_id,),
    ).fetchone()[0]
    if count >= MAX_WATCHES_PER_USER:
        raise ValueError(f"Watch limit reached ({MAX_WATCHES_PER_USER})")

    # Check for duplicate active watch on same target+scope
    existing = conn.execute(
        "SELECT id FROM watches WHERE user_id = ? AND target_url = ? AND scope = ? AND status = 'active'",
        (user_id, target_url, scope),
    ).fetchone()
    if existing:
        raise ValueError("Active watch already exists for this target and scope")

    now = datetime.now(timezone.utc).isoformat()
    watch_id = str(uuid.uuid4())
    interval = CADENCE_SECONDS.get(cadence, CADENCE_SECONDS["daily"])
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat()

    conn.execute(
        """INSERT INTO watches (id, user_id, target_url, scope, cadence, webhook_url,
                                status, last_run_at, next_run_at, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (watch_id, user_id, target_url, scope, cadence, webhook_url or "",
         "active", None, next_run, now, now),
    )
    return {
        "id": watch_id,
        "user_id": user_id,
        "target_url": target_url,
        "scope": scope,
        "cadence": cadence,
        "webhook_url": webhook_url or "",
        "status": "active",
        "last_run_at": None,
        "next_run_at": next_run,
        "created_at": now,
    }


def get_watch(conn, watch_id: str, user_id: str) -> dict | None:
    """Fetch a single watch owned by user_id."""
    row = conn.execute(
        "SELECT * FROM watches WHERE id = ? AND user_id = ?",
        (watch_id, user_id),
    ).fetchone()
    return dict(row) if row else None


def list_watches(conn, user_id: str) -> list[dict]:
    """List all non-deleted watches for a user."""
    rows = conn.execute(
        """SELECT * FROM watches WHERE user_id = ? AND status != 'deleted'
           ORDER BY created_at DESC""",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_watch(conn, watch_id: str, user_id: str, **fields) -> dict | None:
    """Update mutable fields on a watch. Returns updated watch or None."""
    watch = get_watch(conn, watch_id, user_id)
    if not watch:
        return None

    allowed = {"cadence", "webhook_url", "scope", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        return watch

    # Validate cadence if changing
    if "cadence" in updates and updates["cadence"] not in VALID_CADENCES:
        raise ValueError(f"Invalid cadence: {updates['cadence']}")

    # Validate status transitions
    if "status" in updates:
        new_status = updates["status"]
        if new_status not in ("active", "paused", "deleted"):
            raise ValueError(f"Invalid status: {new_status}")
        # Resuming a paused watch → recalculate next_run_at
        if new_status == "active" and watch["status"] == "paused":
            cadence = updates.get("cadence", watch["cadence"])
            interval = CADENCE_SECONDS.get(cadence, CADENCE_SECONDS["daily"])
            updates["next_run_at"] = (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat()

    # Recalculate next_run_at if cadence changed on active watch
    if "cadence" in updates and watch["status"] == "active" and "next_run_at" not in updates:
        interval = CADENCE_SECONDS[updates["cadence"]]
        base = datetime.now(timezone.utc)
        if watch.get("last_run_at"):
            try:
                base = datetime.fromisoformat(watch["last_run_at"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        updates["next_run_at"] = (base + timedelta(seconds=interval)).isoformat()

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [watch_id, user_id]
    conn.execute(
        f"UPDATE watches SET {set_clause} WHERE id = ? AND user_id = ?",
        values,
    )
    return get_watch(conn, watch_id, user_id)


def delete_watch(conn, watch_id: str, user_id: str) -> bool:
    """Soft-delete a watch."""
    now = datetime.now(timezone.utc).isoformat()
    n = conn.execute(
        "UPDATE watches SET status = 'deleted', updated_at = ? WHERE id = ? AND user_id = ?",
        (now, watch_id, user_id),
    ).rowcount
    return n > 0


# ---------------------------------------------------------------------------
# Watch runs
# ---------------------------------------------------------------------------

def list_runs(conn, watch_id: str, limit: int = 30) -> list[dict]:
    """Return recent runs for a watch, newest first."""
    rows = conn.execute(
        """SELECT id, watch_id, scan_id, risk_score, risk_verdict,
                  total, critical, high, medium, low, info, diff_json, created_at
           FROM watch_runs WHERE watch_id = ?
           ORDER BY created_at DESC LIMIT ?""",
        (watch_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_previous_run(conn, watch_id: str) -> dict | None:
    """Get the most recent run for a watch."""
    row = conn.execute(
        """SELECT * FROM watch_runs WHERE watch_id = ?
           ORDER BY created_at DESC LIMIT 1""",
        (watch_id,),
    ).fetchone()
    return dict(row) if row else None


def save_run(
    conn,
    watch_id: str,
    scan_id: str,
    report: dict,
    diff: dict | None,
    diff_sum: dict | None,
) -> str:
    """Persist a watch run. Returns run_id."""
    run_id = str(uuid.uuid4())
    findings = report.get("findings", [])
    now = datetime.now(timezone.utc).isoformat()

    diff_payload = None
    if diff_sum is not None:
        diff_payload = json.dumps(diff_sum, default=str)

    conn.execute(
        """INSERT INTO watch_runs
           (id, watch_id, scan_id, risk_score, risk_verdict,
            total, critical, high, medium, low, info, diff_json, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            run_id, watch_id, scan_id,
            report.get("risk_score"),
            report.get("risk_verdict"),
            len(findings),
            _count_severity(findings, "Critical"),
            _count_severity(findings, "High"),
            _count_severity(findings, "Medium"),
            _count_severity(findings, "Low"),
            _count_severity(findings, "Info"),
            diff_payload,
            now,
        ),
    )
    return run_id


def get_trend(conn, watch_id: str, limit: int = 30) -> list[dict]:
    """Risk score trend data for a watch (oldest-first for charting)."""
    rows = conn.execute(
        """SELECT risk_score, risk_verdict, total, critical, high, medium, low, info, created_at
           FROM watch_runs WHERE watch_id = ?
           ORDER BY created_at ASC
           LIMIT ?""",
        (watch_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Webhook dispatcher
# ---------------------------------------------------------------------------

def _fire_webhook(webhook_url: str, payload: dict) -> bool:
    """POST JSON payload to webhook_url. Returns True on 2xx."""
    if not webhook_url:
        return False
    try:
        import requests
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json", "User-Agent": "Diverg-CTM/1.0"},
        )
        return 200 <= resp.status_code < 300
    except Exception as e:
        log.warning("Webhook failed for %s: %s", webhook_url, e)
        return False


def build_webhook_payload(watch: dict, run_summary: dict, report: dict) -> dict:
    """Build a webhook notification payload."""
    return {
        "event": "watch_run_complete",
        "watch_id": watch["id"],
        "target_url": watch["target_url"],
        "scope": watch["scope"],
        "risk_score": report.get("risk_score"),
        "risk_verdict": report.get("risk_verdict"),
        "diff": run_summary,
        "scanned_at": report.get("scanned_at"),
    }


# ---------------------------------------------------------------------------
# Scheduler — executes due watches
# ---------------------------------------------------------------------------

class WatchScheduler:
    """Background thread that polls for due watches and executes scans."""

    def __init__(self, db_factory: Callable, scan_fn: Callable, save_scan_fn: Callable):
        """
        Args:
            db_factory: callable returning a sqlite3.Connection (same as api_server._db)
            scan_fn: run_web_scan(target, scope=...) -> dict
            save_scan_fn: save_scan(scan_id, result, scope, user_id) -> None
        """
        self._db = db_factory
        self._scan = scan_fn
        self._save_scan = save_scan_fn
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ctm-scheduler")
        self._thread.start()
        log.info("CTM scheduler started (tick=%ds)", SCHEDULER_TICK)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("CTM scheduler stopped")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                log.exception("CTM scheduler tick failed")
            self._stop.wait(SCHEDULER_TICK)

    def _tick(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._db() as conn:
            due = conn.execute(
                """SELECT * FROM watches
                   WHERE status = 'active' AND next_run_at <= ?
                   ORDER BY next_run_at ASC LIMIT 5""",
                (now,),
            ).fetchall()

        for row in due:
            watch = dict(row)
            try:
                self._execute_watch(watch)
            except Exception:
                log.exception("CTM run failed for watch %s (%s)", watch["id"], watch["target_url"])

    def _execute_watch(self, watch: dict) -> None:
        watch_id = watch["id"]
        target = watch["target_url"]
        scope = watch["scope"]
        user_id = watch["user_id"]

        log.info("CTM executing watch %s → %s (scope=%s)", watch_id, target, scope)

        # Run the scan
        report = self._scan(target, scope=scope)
        scan_id = str(uuid.uuid4())
        self._save_scan(scan_id, report, scope, user_id=user_id)

        new_findings = report.get("findings", [])
        new_score = report.get("risk_score")

        # Diff against previous run
        diff = None
        diff_sum = None
        old_score = None

        with self._db() as conn:
            prev = get_previous_run(conn, watch_id)
            if prev and prev.get("scan_id"):
                # Load previous scan's findings
                prev_scan = conn.execute(
                    "SELECT report_json FROM scans WHERE id = ?",
                    (prev["scan_id"],),
                ).fetchone()
                if prev_scan:
                    try:
                        prev_report = json.loads(prev_scan["report_json"] or "{}")
                        old_findings = prev_report.get("findings", [])
                        old_score = prev.get("risk_score")
                        diff = diff_findings(old_findings, new_findings)
                        diff_sum = diff_summary(diff, old_score, new_score)
                    except (json.JSONDecodeError, KeyError):
                        pass

            # Save the run
            run_id = save_run(conn, watch_id, scan_id, report, diff, diff_sum)

            # Update watch timing
            interval = CADENCE_SECONDS.get(watch["cadence"], CADENCE_SECONDS["daily"])
            now = datetime.now(timezone.utc)
            conn.execute(
                "UPDATE watches SET last_run_at = ?, next_run_at = ?, updated_at = ? WHERE id = ?",
                (now.isoformat(), (now + timedelta(seconds=interval)).isoformat(), now.isoformat(), watch_id),
            )

            # Award points
            try:
                from dashboard_points import award_watch_run_points
                award_watch_run_points(conn, user_id, run_id, scope)
            except Exception:
                pass

        # Fire webhook if meaningful diff
        if watch.get("webhook_url") and diff_sum and diff_is_meaningful(diff):
            payload = build_webhook_payload(watch, diff_sum, report)
            threading.Thread(
                target=_fire_webhook,
                args=(watch["webhook_url"], payload),
                daemon=True,
            ).start()

        log.info(
            "CTM run complete: watch=%s run=%s risk=%s new=%d fixed=%d",
            watch_id, run_id, new_score,
            len(diff["new"]) if diff else 0,
            len(diff["fixed"]) if diff else 0,
        )

    def run_now(self, watch: dict, db_factory: Callable) -> dict:
        """Trigger a watch run immediately (for manual trigger via API). Returns run summary."""
        target = watch["target_url"]
        scope = watch["scope"]
        user_id = watch["user_id"]
        watch_id = watch["id"]

        report = self._scan(target, scope=scope)
        scan_id = str(uuid.uuid4())
        self._save_scan(scan_id, report, scope, user_id=user_id)

        new_findings = report.get("findings", [])
        new_score = report.get("risk_score")

        diff = None
        diff_sum = None

        with db_factory() as conn:
            prev = get_previous_run(conn, watch_id)
            if prev and prev.get("scan_id"):
                prev_scan = conn.execute(
                    "SELECT report_json FROM scans WHERE id = ?",
                    (prev["scan_id"],),
                ).fetchone()
                if prev_scan:
                    try:
                        prev_report = json.loads(prev_scan["report_json"] or "{}")
                        old_findings = prev_report.get("findings", [])
                        old_score = prev.get("risk_score")
                        diff = diff_findings(old_findings, new_findings)
                        diff_sum = diff_summary(diff, old_score, new_score)
                    except (json.JSONDecodeError, KeyError):
                        pass

            run_id = save_run(conn, watch_id, scan_id, report, diff, diff_sum)

            interval = CADENCE_SECONDS.get(watch["cadence"], CADENCE_SECONDS["daily"])
            now = datetime.now(timezone.utc)
            conn.execute(
                "UPDATE watches SET last_run_at = ?, next_run_at = ?, updated_at = ? WHERE id = ?",
                (now.isoformat(), (now + timedelta(seconds=interval)).isoformat(), now.isoformat(), watch_id),
            )

            try:
                from dashboard_points import award_watch_run_points
                award_watch_run_points(conn, user_id, run_id, scope)
            except Exception:
                pass

        if watch.get("webhook_url") and diff_sum and diff_is_meaningful(diff):
            payload = build_webhook_payload(watch, diff_sum, report)
            threading.Thread(
                target=_fire_webhook,
                args=(watch["webhook_url"], payload),
                daemon=True,
            ).start()

        return {
            "run_id": run_id,
            "scan_id": scan_id,
            "risk_score": new_score,
            "risk_verdict": report.get("risk_verdict"),
            "diff": diff_sum,
        }
