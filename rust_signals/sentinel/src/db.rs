use crate::types::{
    now_iso, Finding, RegressionRunResult, RegressionTest, StoredScan, SurfaceSnapshot,
};
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

const SENTINEL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sentinel_surface_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          TEXT NOT NULL,
    target_url       TEXT NOT NULL,
    status_code      INTEGER,
    final_url        TEXT NOT NULL,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    captured_at      TEXT NOT NULL,
    snapshot_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sentinel_surface_snapshots_user_target
    ON sentinel_surface_snapshots(user_id, target_url, captured_at DESC);

CREATE TABLE IF NOT EXISTS sentinel_regressions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    target_url      TEXT NOT NULL,
    finding_title   TEXT NOT NULL,
    method          TEXT NOT NULL,
    request_url     TEXT NOT NULL,
    headers_json    TEXT NOT NULL DEFAULT '{}',
    params_json     TEXT NOT NULL DEFAULT '{}',
    body            TEXT,
    expected_status INTEGER,
    match_pattern   TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sentinel_regressions_user_target
    ON sentinel_regressions(user_id, target_url, created_at DESC);

CREATE TABLE IF NOT EXISTS sentinel_regression_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id          INTEGER NOT NULL REFERENCES sentinel_regressions(id) ON DELETE CASCADE,
    user_id          TEXT NOT NULL,
    target_url       TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    status_code      INTEGER,
    match_found      INTEGER,
    response_time_ms INTEGER,
    body_preview     TEXT,
    error            TEXT,
    ran_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sentinel_regression_runs_test
    ON sentinel_regression_runs(test_id, ran_at DESC);
"#;

pub fn open_db(path: impl AsRef<Path>) -> Result<Connection> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create db directory {}", parent.display()))?;
    }
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open database {}", path.display()))?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
        .context("failed to configure sqlite pragmas")?;
    init_tables(&conn)?;
    Ok(conn)
}

pub fn init_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(SENTINEL_SCHEMA)
        .context("failed to initialize Sentinel tables")
}

pub fn fetch_scan(conn: &Connection, scan_id: &str) -> Result<StoredScan> {
    let row = conn
        .query_row(
            "SELECT id, target_url, scanned_at, risk_score, report_json FROM scans WHERE id = ?1",
            [scan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .with_context(|| format!("failed to load scan {}", scan_id))?;

    let report_json = row
        .4
        .ok_or_else(|| anyhow!("scan {} is missing report_json", scan_id))?;
    let report: Value =
        serde_json::from_str(&report_json).context("failed to parse scan report_json")?;
    let findings_value = report.get("findings").cloned().unwrap_or(Value::Array(vec![]));
    let findings: Vec<Finding> = serde_json::from_value(findings_value)
        .context("failed to parse findings from report_json")?;
    Ok(StoredScan {
        scan_id: row.0,
        target_url: row.1,
        scanned_at: row.2,
        risk_score: row.3,
        findings,
    })
}

pub fn latest_surface_snapshot(
    conn: &Connection,
    user_id: &str,
    target_url: &str,
) -> Result<Option<SurfaceSnapshot>> {
    conn.query_row(
        "SELECT id, snapshot_json FROM sentinel_surface_snapshots
         WHERE user_id = ?1 AND target_url = ?2
         ORDER BY captured_at DESC
         LIMIT 1",
        params![user_id, target_url],
        |row| {
            let id = row.get::<_, i64>(0)?;
            let snapshot_json = row.get::<_, String>(1)?;
            Ok((id, snapshot_json))
        },
    )
    .optional()
    .context("failed to fetch latest surface snapshot")?
    .map(|(id, snapshot_json)| deserialize_snapshot(id, snapshot_json))
    .transpose()
}

pub fn list_surface_snapshots(
    conn: &Connection,
    user_id: &str,
    target_url: &str,
    limit: usize,
) -> Result<Vec<SurfaceSnapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, snapshot_json FROM sentinel_surface_snapshots
         WHERE user_id = ?1 AND target_url = ?2
         ORDER BY captured_at DESC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![user_id, target_url, limit as i64], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut snapshots = Vec::new();
    for row in rows {
        let (id, snapshot_json) = row?;
        snapshots.push(deserialize_snapshot(id, snapshot_json)?);
    }
    Ok(snapshots)
}

pub fn insert_surface_snapshot(
    conn: &Connection,
    user_id: &str,
    snapshot: &SurfaceSnapshot,
) -> Result<SurfaceSnapshot> {
    let mut stored = snapshot.clone();
    stored.user_id = Some(user_id.to_string());
    if stored.captured_at.trim().is_empty() {
        stored.captured_at = now_iso();
    }
    let snapshot_json =
        serde_json::to_string(&stored).context("failed to serialize surface snapshot")?;
    conn.execute(
        "INSERT INTO sentinel_surface_snapshots
         (user_id, target_url, status_code, final_url, response_time_ms, captured_at, snapshot_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user_id,
            stored.target_url,
            stored.status_code.map(i64::from),
            stored.final_url,
            stored.response_time_ms as i64,
            stored.captured_at,
            snapshot_json,
        ],
    )
    .context("failed to insert surface snapshot")?;
    stored.id = Some(conn.last_insert_rowid());
    Ok(stored)
}

pub fn insert_regression(conn: &Connection, test: &RegressionTest) -> Result<RegressionTest> {
    let mut stored = test.clone();
    if stored.created_at.trim().is_empty() {
        stored.created_at = now_iso();
    }
    let user_id = stored
        .user_id
        .clone()
        .ok_or_else(|| anyhow!("regression is missing user_id"))?;
    let headers_json =
        serde_json::to_string(&stored.headers).context("failed to serialize regression headers")?;
    let params_json =
        serde_json::to_string(&stored.params).context("failed to serialize regression params")?;

    conn.execute(
        "INSERT INTO sentinel_regressions
         (user_id, target_url, finding_title, method, request_url, headers_json, params_json, body, expected_status, match_pattern, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            user_id,
            stored.target_url,
            stored.finding_title,
            stored.method,
            stored.request_url,
            headers_json,
            params_json,
            stored.body,
            stored.expected_status.map(i64::from),
            stored.match_pattern,
            stored.created_at,
        ],
    )
    .context("failed to insert regression")?;
    stored.id = conn.last_insert_rowid();
    Ok(stored)
}

pub fn list_regressions(
    conn: &Connection,
    user_id: &str,
    target_url: &str,
) -> Result<Vec<RegressionTest>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, target_url, finding_title, method, request_url, headers_json, params_json, body, expected_status, match_pattern, created_at
         FROM sentinel_regressions
         WHERE user_id = ?1 AND target_url = ?2
         ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![user_id, target_url], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<i64>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, String>(11)?,
        ))
    })?;

    let mut tests = Vec::new();
    for row in rows {
        let (
            id,
            row_user_id,
            row_target_url,
            finding_title,
            method,
            request_url,
            headers_json,
            params_json,
            body,
            expected_status,
            match_pattern,
            created_at,
        ) = row?;
        let headers: HashMap<String, String> =
            serde_json::from_str(&headers_json).context("failed to parse regression headers")?;
        let params: HashMap<String, String> =
            serde_json::from_str(&params_json).context("failed to parse regression params")?;
        tests.push(RegressionTest {
            id,
            user_id: Some(row_user_id),
            target_url: row_target_url,
            finding_title,
            method,
            request_url,
            headers,
            params,
            body,
            expected_status: expected_status.map(|value| value as u16),
            match_pattern,
            created_at,
        });
    }
    Ok(tests)
}

pub fn delete_regression(conn: &Connection, user_id: &str, id: i64) -> Result<bool> {
    let deleted = conn
        .execute(
            "DELETE FROM sentinel_regressions WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .context("failed to delete regression")?;
    Ok(deleted > 0)
}

pub fn insert_regression_run(
    conn: &Connection,
    user_id: &str,
    target_url: &str,
    result: &RegressionRunResult,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sentinel_regression_runs
         (test_id, user_id, target_url, outcome, status_code, match_found, response_time_ms, body_preview, error, ran_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            result.test_id,
            user_id,
            target_url,
            result.outcome,
            result.status_code.map(i64::from),
            result.match_found.map(|value| if value { 1_i64 } else { 0_i64 }),
            result.response_time_ms.map(|value| value as i64),
            result.body_preview,
            result.error,
            result.ran_at,
        ],
    )
    .context("failed to insert regression run")?;
    Ok(())
}

fn deserialize_snapshot(id: i64, snapshot_json: String) -> Result<SurfaceSnapshot> {
    let mut snapshot: SurfaceSnapshot =
        serde_json::from_str(&snapshot_json).context("failed to parse surface snapshot_json")?;
    snapshot.id = Some(id);
    Ok(snapshot)
}
