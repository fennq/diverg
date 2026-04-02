use crate::types::{now_iso, RegressionRunReport, RegressionRunResult, RegressionRunSummary, RegressionTest};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use url::Url;

const MAX_PREVIEW_LEN: usize = 500;

pub fn parse_pairs(values: &[String], label: &str) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for value in values {
        let (key, val) = value
            .split_once('=')
            .ok_or_else(|| anyhow!("{label} must use key=value format"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("{label} key cannot be empty"));
        }
        out.insert(key.to_string(), val.to_string());
    }
    Ok(out)
}

pub fn validate_regression_input(test: &RegressionTest) -> Result<()> {
    if test.finding_title.trim().is_empty() {
        return Err(anyhow!("finding_title is required"));
    }
    if test.request_url.trim().is_empty() {
        return Err(anyhow!("request_url is required"));
    }
    if test.expected_status.is_none()
        && test
            .match_pattern
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(anyhow!(
            "regression must include expected_status or match_pattern"
        ));
    }
    if let Some(pattern) = test.match_pattern.as_deref() {
        Regex::new(pattern).context("match_pattern is not a valid regex")?;
    }
    Ok(())
}

pub async fn run_regressions(target_url: &str, tests: &[RegressionTest]) -> RegressionRunReport {
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("reqwest client should build");
    let semaphore = Arc::new(Semaphore::new(10));
    let client = Arc::new(client);
    let mut handles = Vec::new();

    for test in tests.iter().cloned() {
        let client = Arc::clone(&client);
        let semaphore = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
            execute_single_test(&test, &client).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(error) => results.push(RegressionRunResult {
                test_id: 0,
                finding_title: "Unknown regression".to_string(),
                request_url: target_url.to_string(),
                outcome: "error".to_string(),
                expected_status: None,
                status_code: None,
                match_found: None,
                response_time_ms: None,
                body_preview: None,
                error: Some(format!("task join error: {error}")),
                ran_at: now_iso(),
            }),
        }
    }

    results.sort_by(|left, right| left.finding_title.cmp(&right.finding_title));
    build_report(target_url, results)
}

pub fn classify_outcome(
    expected_status: Option<u16>,
    actual_status: u16,
    match_pattern: Option<&str>,
    body: &str,
) -> Result<(String, Option<bool>)> {
    let status_matches = expected_status.map(|expected| expected == actual_status).unwrap_or(true);
    let match_found = if let Some(pattern) = match_pattern {
        Some(Regex::new(pattern).context("match_pattern is not a valid regex")?.is_match(body))
    } else {
        None
    };
    let regex_matches = match_found.unwrap_or(true);
    let outcome = if status_matches && regex_matches {
        "reproduces"
    } else {
        "fixed"
    };
    Ok((outcome.to_string(), match_found))
}

async fn execute_single_test(test: &RegressionTest, client: &Client) -> RegressionRunResult {
    let ran_at = now_iso();
    match execute_request(test, client).await {
        Ok(result) => result,
        Err(error) => RegressionRunResult {
            test_id: test.id,
            finding_title: test.finding_title.clone(),
            request_url: test.request_url.clone(),
            outcome: "error".to_string(),
            expected_status: test.expected_status,
            status_code: None,
            match_found: None,
            response_time_ms: None,
            body_preview: None,
            error: Some(error.to_string()),
            ran_at,
        },
    }
}

async fn execute_request(test: &RegressionTest, client: &Client) -> Result<RegressionRunResult> {
    let method = Method::from_bytes(test.method.as_bytes())
        .with_context(|| format!("invalid HTTP method {}", test.method))?;
    let request_url = normalize_request_url(&test.request_url)?;
    let url = with_query_params(&request_url, &test.params)?;

    let mut request = client.request(method.clone(), url.clone());
    for (key, value) in &test.headers {
        request = request.header(key, value);
    }
    if method != Method::GET && method != Method::HEAD {
        if let Some(body) = &test.body {
            request = request.body(body.clone());
        }
    }

    let started = Instant::now();
    let response = request
        .send()
        .await
        .with_context(|| format!("request failed for {}", test.request_url))?;
    let status_code = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let body_preview = truncate_body(&text);
    let (outcome, match_found) = classify_outcome(
        test.expected_status,
        status_code,
        test.match_pattern.as_deref(),
        &text,
    )?;

    Ok(RegressionRunResult {
        test_id: test.id,
        finding_title: test.finding_title.clone(),
        request_url: test.request_url.clone(),
        outcome,
        expected_status: test.expected_status,
        status_code: Some(status_code),
        match_found,
        response_time_ms: Some(started.elapsed().as_millis() as u64),
        body_preview: Some(body_preview),
        error: None,
        ran_at: now_iso(),
    })
}

fn build_report(target_url: &str, results: Vec<RegressionRunResult>) -> RegressionRunReport {
    let summary = RegressionRunSummary {
        target_url: target_url.to_string(),
        total: results.len(),
        reproduces: results.iter().filter(|result| result.outcome == "reproduces").count(),
        fixed: results.iter().filter(|result| result.outcome == "fixed").count(),
        error: results.iter().filter(|result| result.outcome == "error").count(),
    };
    RegressionRunReport {
        target_url: target_url.to_string(),
        summary,
        results,
    }
}

fn normalize_request_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("request_url is required"));
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("https://{trimmed}"))
    }
}

fn with_query_params(request_url: &str, params: &HashMap<String, String>) -> Result<String> {
    let mut url = Url::parse(request_url)?;
    if !params.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
        drop(pairs);
    }
    Ok(url.to_string())
}

fn truncate_body(body: &str) -> String {
    let normalized = body.trim();
    if normalized.chars().count() > MAX_PREVIEW_LEN {
        normalized.chars().take(MAX_PREVIEW_LEN).collect::<String>() + "..."
    } else {
        normalized.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_outcome, parse_pairs};

    #[test]
    fn parse_pairs_supports_repeated_key_values() {
        let parsed = parse_pairs(&["Authorization=Bearer abc".to_string(), "X-Test=yes".to_string()], "header")
            .expect("pairs should parse");
        assert_eq!(parsed.get("Authorization").map(String::as_str), Some("Bearer abc"));
        assert_eq!(parsed.get("X-Test").map(String::as_str), Some("yes"));
    }

    #[test]
    fn classify_outcome_requires_all_assertions() {
        let result = classify_outcome(Some(200), 200, Some("admin"), "hello admin")
            .expect("classification should succeed");
        assert_eq!(result.0, "reproduces");
        assert_eq!(result.1, Some(true));

        let result = classify_outcome(Some(200), 403, Some("admin"), "hello admin")
            .expect("classification should succeed");
        assert_eq!(result.0, "fixed");

        let result = classify_outcome(Some(200), 200, Some("admin"), "guest page")
            .expect("classification should succeed");
        assert_eq!(result.0, "fixed");
        assert_eq!(result.1, Some(false));
    }

    #[test]
    fn invalid_regex_returns_error() {
        assert!(classify_outcome(Some(200), 200, Some("["), "body").is_err());
    }
}
