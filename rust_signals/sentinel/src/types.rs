use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default, rename = "_source_skill")]
    pub source_skill: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScan {
    pub scan_id: String,
    pub target_url: String,
    pub scanned_at: Option<String>,
    pub risk_score: Option<i64>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub canonical_key: String,
    pub title: String,
    pub url: Option<String>,
    pub category: Option<String>,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChange {
    pub canonical_key: String,
    pub title: String,
    pub url: Option<String>,
    pub category: Option<String>,
    pub from_excerpt: Option<String>,
    pub to_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub severity_changed_count: usize,
    pub evidence_changed_count: usize,
    pub unchanged_count: usize,
    pub risk_score_a: Option<i64>,
    pub risk_score_b: Option<i64>,
    pub risk_delta: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub scan_a: String,
    pub scan_b: String,
    pub target_url: String,
    pub generated_at: String,
    pub summary: DiffSummary,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub severity_changes: Vec<SeverityChange>,
    pub evidence_changes: Vec<EvidenceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceSnapshot {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub user_id: Option<String>,
    pub target_url: String,
    pub captured_at: String,
    #[serde(default)]
    pub status_code: Option<u16>,
    pub final_url: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub x_powered_by: Option<String>,
    #[serde(default)]
    pub x_generator: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
    #[serde(default)]
    pub cf_ray: Option<String>,
    #[serde(default)]
    pub x_varnish: Option<String>,
    #[serde(default)]
    pub x_aspnet_version: Option<String>,
    #[serde(default)]
    pub security_headers: Vec<String>,
    #[serde(default)]
    pub missing_security_headers: Vec<String>,
    #[serde(default)]
    pub detected_tech: Vec<String>,
    #[serde(default)]
    pub response_time_ms: u64,
    #[serde(default)]
    pub redirects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceChange {
    pub severity: String,
    pub kind: String,
    pub field: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceDrift {
    pub compared_at: String,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub change_count: usize,
    pub changes: Vec<SurfaceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegressionTest {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub user_id: Option<String>,
    pub target_url: String,
    pub finding_title: String,
    pub method: String,
    pub request_url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub params: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub match_pattern: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRunResult {
    pub test_id: i64,
    pub finding_title: String,
    pub request_url: String,
    pub outcome: String,
    pub expected_status: Option<u16>,
    pub status_code: Option<u16>,
    pub match_found: Option<bool>,
    pub response_time_ms: Option<u64>,
    pub body_preview: Option<String>,
    pub error: Option<String>,
    pub ran_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRunSummary {
    pub target_url: String,
    pub total: usize,
    pub reproduces: usize,
    pub fixed: usize,
    pub error: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRunReport {
    pub target_url: String,
    pub summary: RegressionRunSummary,
    pub results: Vec<RegressionRunResult>,
}

pub fn default_severity() -> String {
    "Info".to_string()
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn severity_rank(level: &str) -> usize {
    match level.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}
