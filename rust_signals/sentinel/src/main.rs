mod db;
mod differ;
mod fingerprint;
mod regress;
mod types;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;

use crate::db::{
    delete_regression, fetch_scan, insert_regression, insert_regression_run, insert_surface_snapshot,
    latest_surface_snapshot, list_regressions, list_surface_snapshots, open_db,
};
use crate::differ::compute_diff;
use crate::fingerprint::{capture_snapshot, diff_snapshots, normalize_target_url};
use crate::regress::{parse_pairs, run_regressions, validate_regression_input};
use crate::types::{now_iso, RegressionTest};

#[derive(Parser, Debug)]
#[command(name = "diverg-sentinel", about = "Diverg Sentinel: diff scans, track surface drift, and replay regressions")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Diff(DiffArgs),
    Surface {
        #[command(subcommand)]
        command: SurfaceCommand,
    },
    Regress {
        #[command(subcommand)]
        command: RegressCommand,
    },
}

#[derive(Args, Debug)]
struct DiffArgs {
    #[arg(long)]
    scan_a: String,
    #[arg(long)]
    scan_b: String,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Subcommand, Debug)]
enum SurfaceCommand {
    Capture(SurfaceCaptureArgs),
    History(SurfaceHistoryArgs),
}

#[derive(Args, Debug)]
struct SurfaceCaptureArgs {
    #[arg(long)]
    target_url: String,
    #[arg(long)]
    user_id: String,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct SurfaceHistoryArgs {
    #[arg(long)]
    target_url: String,
    #[arg(long)]
    user_id: String,
    #[arg(long, default_value = "25")]
    limit: usize,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Subcommand, Debug)]
enum RegressCommand {
    Add(RegressAddArgs),
    List(RegressListArgs),
    Delete(RegressDeleteArgs),
    Run(RegressRunArgs),
}

#[derive(Args, Debug)]
struct RegressAddArgs {
    #[arg(long)]
    user_id: String,
    #[arg(long)]
    target_url: String,
    #[arg(long)]
    finding_title: String,
    #[arg(long, default_value = "GET")]
    method: String,
    #[arg(long)]
    request_url: String,
    #[arg(long = "header")]
    headers: Vec<String>,
    #[arg(long = "param")]
    params: Vec<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    expected_status: Option<u16>,
    #[arg(long)]
    match_pattern: Option<String>,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct RegressListArgs {
    #[arg(long)]
    user_id: String,
    #[arg(long)]
    target_url: String,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct RegressDeleteArgs {
    #[arg(long)]
    user_id: String,
    #[arg(long)]
    id: i64,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct RegressRunArgs {
    #[arg(long)]
    user_id: String,
    #[arg(long)]
    target_url: String,
    #[arg(long, default_value = "data/dashboard.db")]
    db: PathBuf,
}

#[derive(Serialize)]
struct SurfaceCaptureOutput {
    snapshot: types::SurfaceSnapshot,
    previous: Option<types::SurfaceSnapshot>,
    drift: Option<types::SurfaceDrift>,
}

#[derive(Serialize)]
struct DeletedOutput {
    deleted: bool,
    id: i64,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Diff(args) => {
            let conn = open_db(&args.db)?;
            let scan_a = fetch_scan(&conn, &args.scan_a)?;
            let scan_b = fetch_scan(&conn, &args.scan_b)?;
            print_json(&compute_diff(&scan_a, &scan_b))?;
        }
        Command::Surface {
            command: SurfaceCommand::Capture(args),
        } => {
            let conn = open_db(&args.db)?;
            let target_url = normalize_target_url(&args.target_url)?;
            let previous = latest_surface_snapshot(&conn, &args.user_id, &target_url)?;
            let mut snapshot = capture_snapshot(&target_url).await?;
            snapshot.target_url = target_url.clone();
            let stored = insert_surface_snapshot(&conn, &args.user_id, &snapshot)?;
            let drift = previous
                .as_ref()
                .map(|previous_snapshot| diff_snapshots(previous_snapshot, &stored));
            print_json(&SurfaceCaptureOutput {
                snapshot: stored,
                previous,
                drift,
            })?;
        }
        Command::Surface {
            command: SurfaceCommand::History(args),
        } => {
            let conn = open_db(&args.db)?;
            let target_url = normalize_target_url(&args.target_url)?;
            let snapshots = list_surface_snapshots(&conn, &args.user_id, &target_url, args.limit)?;
            print_json(&json!({
                "target_url": target_url,
                "count": snapshots.len(),
                "snapshots": snapshots,
            }))?;
        }
        Command::Regress {
            command: RegressCommand::Add(args),
        } => {
            let conn = open_db(&args.db)?;
            let target_url = normalize_target_url(&args.target_url)?;
            let test = RegressionTest {
                id: 0,
                user_id: Some(args.user_id),
                target_url,
                finding_title: args.finding_title.trim().to_string(),
                method: args.method.trim().to_ascii_uppercase(),
                request_url: args.request_url.trim().to_string(),
                headers: parse_pairs(&args.headers, "header")?,
                params: parse_pairs(&args.params, "param")?,
                body: args.body,
                expected_status: args.expected_status,
                match_pattern: args.match_pattern.filter(|value| !value.trim().is_empty()),
                created_at: now_iso(),
            };
            validate_regression_input(&test)?;
            let saved = insert_regression(&conn, &test)?;
            print_json(&json!({ "regression": saved }))?;
        }
        Command::Regress {
            command: RegressCommand::List(args),
        } => {
            let conn = open_db(&args.db)?;
            let target_url = normalize_target_url(&args.target_url)?;
            let tests = list_regressions(&conn, &args.user_id, &target_url)?;
            print_json(&json!({
                "target_url": target_url,
                "count": tests.len(),
                "regressions": tests,
            }))?;
        }
        Command::Regress {
            command: RegressCommand::Delete(args),
        } => {
            let conn = open_db(&args.db)?;
            let deleted = delete_regression(&conn, &args.user_id, args.id)?;
            print_json(&DeletedOutput { deleted, id: args.id })?;
        }
        Command::Regress {
            command: RegressCommand::Run(args),
        } => {
            let target_url = normalize_target_url(&args.target_url)?;
            let conn = open_db(&args.db)?;
            let tests = list_regressions(&conn, &args.user_id, &target_url)?;
            let report = run_regressions(&target_url, &tests).await;
            let conn = open_db(&args.db)?;
            for result in &report.results {
                insert_regression_run(&conn, &args.user_id, &target_url, result)?;
            }
            print_json(&report)?;
        }
    }
    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
