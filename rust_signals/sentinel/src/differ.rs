use crate::types::{
    now_iso, severity_rank, DiffSummary, EvidenceChange, Finding, ScanDiff, SeverityChange,
    StoredScan,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;

pub fn compute_diff(scan_a: &StoredScan, scan_b: &StoredScan) -> ScanDiff {
    let map_a = to_map(&scan_a.findings);
    let map_b = to_map(&scan_b.findings);

    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();
    let mut severity_changes = Vec::new();
    let mut evidence_changes = Vec::new();
    let mut unchanged_count = 0;

    for (key, finding_b) in &map_b {
        match map_a.get(key) {
            None => new_findings.push(finding_b.clone()),
            Some(finding_a) => {
                let mut changed = false;
                if normalize_level(&finding_a.severity) != normalize_level(&finding_b.severity) {
                    changed = true;
                    severity_changes.push(SeverityChange {
                        canonical_key: key.clone(),
                        title: finding_b.title.clone(),
                        url: finding_b.url.clone(),
                        category: finding_b.category.clone(),
                        from: finding_a.severity.clone(),
                        to: finding_b.severity.clone(),
                    });
                }
                if normalize_evidence(finding_a.evidence.as_deref())
                    != normalize_evidence(finding_b.evidence.as_deref())
                {
                    changed = true;
                    evidence_changes.push(EvidenceChange {
                        canonical_key: key.clone(),
                        title: finding_b.title.clone(),
                        url: finding_b.url.clone(),
                        category: finding_b.category.clone(),
                        from_excerpt: finding_a.evidence.as_ref().map(|v| excerpt(v)),
                        to_excerpt: finding_b.evidence.as_ref().map(|v| excerpt(v)),
                    });
                }
                if !changed {
                    unchanged_count += 1;
                }
            }
        }
    }

    for (key, finding_a) in &map_a {
        if !map_b.contains_key(key) {
            resolved_findings.push(finding_a.clone());
        }
    }

    sort_findings(&mut new_findings);
    sort_findings(&mut resolved_findings);
    severity_changes.sort_by(|left, right| {
        severity_rank(&left.to)
            .cmp(&severity_rank(&right.to))
            .then_with(|| left.title.cmp(&right.title))
    });
    evidence_changes.sort_by(|left, right| left.title.cmp(&right.title));

    ScanDiff {
        scan_a: scan_a.scan_id.clone(),
        scan_b: scan_b.scan_id.clone(),
        target_url: scan_b.target_url.clone(),
        generated_at: now_iso(),
        summary: DiffSummary {
            new_count: new_findings.len(),
            resolved_count: resolved_findings.len(),
            severity_changed_count: severity_changes.len(),
            evidence_changed_count: evidence_changes.len(),
            unchanged_count,
            risk_score_a: scan_a.risk_score,
            risk_score_b: scan_b.risk_score,
            risk_delta: match (scan_a.risk_score, scan_b.risk_score) {
                (Some(a), Some(b)) => Some(b - a),
                _ => None,
            },
        },
        new_findings,
        resolved_findings,
        severity_changes,
        evidence_changes,
    }
}

pub fn canonical_key(finding: &Finding) -> String {
    let title = normalize_identity(&finding.title);
    let category = normalize_identity(finding.category.as_deref().unwrap_or_default());
    let url = normalize_identity(&normalize_url_for_identity(finding.url.as_deref().unwrap_or("")));

    let mut hasher = Sha256::new();
    hasher.update(format!("{title}|{url}|{category}"));
    format!("{:x}", hasher.finalize())
}

fn to_map(findings: &[Finding]) -> HashMap<String, Finding> {
    let mut map = HashMap::new();
    for finding in findings {
        map.entry(canonical_key(finding))
            .and_modify(|existing: &mut Finding| {
                if severity_rank(&finding.severity) < severity_rank(&existing.severity) {
                    *existing = finding.clone();
                }
            })
            .or_insert_with(|| finding.clone());
    }
    map
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then_with(|| left.title.cmp(&right.title))
    });
}

fn normalize_url_for_identity(raw: &str) -> String {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return String::new();
    }
    let parsed = if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Url::parse(candidate).ok()
    } else {
        Url::parse(&format!("https://{candidate}")).ok()
    };

    if let Some(mut url) = parsed {
        url.set_query(None);
        url.set_fragment(None);
        return url.to_string();
    }
    candidate.to_string()
}

fn normalize_identity(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn normalize_level(level: &str) -> String {
    level.trim().to_ascii_lowercase()
}

pub fn normalize_evidence(raw: Option<&str>) -> String {
    raw.unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn excerpt(raw: &str) -> String {
    let normalized = normalize_evidence(Some(raw));
    normalized.chars().take(220).collect()
}

#[cfg(test)]
mod tests {
    use super::{canonical_key, compute_diff, normalize_evidence};
    use crate::types::{Finding, StoredScan};

    fn finding(title: &str, severity: &str, url: &str, category: &str, evidence: &str) -> Finding {
        Finding {
            title: title.to_string(),
            severity: severity.to_string(),
            url: Some(url.to_string()),
            category: Some(category.to_string()),
            evidence: Some(evidence.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn canonical_key_ignores_query_and_fragment() {
        let left = finding(
            "Broken access control",
            "High",
            "https://example.com/api/users?id=1#frag",
            "Access Control",
            "one",
        );
        let right = finding(
            "Broken access control",
            "High",
            "https://example.com/api/users?id=2",
            "Access Control",
            "two",
        );
        assert_eq!(canonical_key(&left), canonical_key(&right));
    }

    #[test]
    fn normalize_evidence_collapses_whitespace() {
        assert_eq!(
            normalize_evidence(Some("line one\n\n line   two\t\tvalue")),
            "line one line two value"
        );
    }

    #[test]
    fn compute_diff_classifies_new_resolved_and_changed() {
        let scan_a = StoredScan {
            scan_id: "a".to_string(),
            target_url: "https://example.com".to_string(),
            scanned_at: None,
            risk_score: Some(2),
            findings: vec![
                finding("A", "Low", "https://example.com/a?id=1", "Access", "same"),
                finding("B", "Medium", "https://example.com/b", "Headers", "old evidence"),
                finding("C", "High", "https://example.com/c", "Auth", "gone"),
            ],
        };
        let scan_b = StoredScan {
            scan_id: "b".to_string(),
            target_url: "https://example.com".to_string(),
            scanned_at: None,
            risk_score: Some(7),
            findings: vec![
                finding("A", "High", "https://example.com/a?id=99", "Access", "same"),
                finding("B", "Medium", "https://example.com/b", "Headers", "new evidence"),
                finding("D", "Critical", "https://example.com/d", "Auth", "new"),
            ],
        };

        let diff = compute_diff(&scan_a, &scan_b);
        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.resolved_count, 1);
        assert_eq!(diff.summary.severity_changed_count, 1);
        assert_eq!(diff.summary.evidence_changed_count, 1);
        assert_eq!(diff.summary.unchanged_count, 0);
        assert_eq!(diff.summary.risk_delta, Some(5));
        assert_eq!(diff.new_findings[0].title, "D");
        assert_eq!(diff.resolved_findings[0].title, "C");
    }
}
