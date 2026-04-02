use crate::types::{now_iso, SurfaceChange, SurfaceDrift, SurfaceSnapshot};
use anyhow::{anyhow, Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE, LOCATION},
    redirect::Policy,
    Client,
};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use url::Url;

const REQUIRED_SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
];

const USER_AGENT: &str = "Mozilla/5.0 (compatible; Diverg-Sentinel/1.0; +https://divergsec.com)";

pub fn normalize_target_url(raw: &str) -> Result<String> {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err(anyhow!("target_url is required"));
    }
    let url = if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Url::parse(candidate)
    } else {
        Url::parse(&format!("https://{candidate}"))
    }
    .with_context(|| format!("invalid target_url {candidate}"))?;

    if url.host_str().is_none() {
        return Err(anyhow!("target_url must include a hostname"));
    }

    let mut normalized = url;
    normalized.set_query(None);
    normalized.set_fragment(None);
    Ok(normalized.to_string())
}

pub async fn capture_snapshot(target_url: &str) -> Result<SurfaceSnapshot> {
    let normalized_target = normalize_target_url(target_url)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to build HTTP client")?;

    let mut current_url = normalized_target.clone();
    let mut redirects = vec![current_url.clone()];
    let start = Instant::now();
    let mut final_headers = HeaderMap::new();
    let mut final_status = None;
    let mut final_url = current_url.clone();

    for _ in 0..8 {
        let response = client
            .get(current_url.clone())
            .header("User-Agent", HeaderValue::from_static(USER_AGENT))
            .send()
            .await
            .with_context(|| format!("surface probe failed for {current_url}"))?;

        final_status = Some(response.status().as_u16());
        final_headers = response.headers().clone();
        final_url = current_url.clone();

        if response.status().is_redirection() {
            if let Some(location) = response.headers().get(LOCATION) {
                let next_url = resolve_redirect(&current_url, location)?;
                if redirects.contains(&next_url) {
                    break;
                }
                current_url = next_url.clone();
                redirects.push(next_url);
                continue;
            }
        }
        break;
    }

    let security_headers: Vec<String> = REQUIRED_SECURITY_HEADERS
        .iter()
        .filter_map(|(key, display)| final_headers.contains_key(*key).then_some((*display).to_string()))
        .collect();

    let present: HashSet<String> = security_headers.iter().cloned().collect();
    let missing_security_headers: Vec<String> = REQUIRED_SECURITY_HEADERS
        .iter()
        .filter_map(|(_, display)| (!present.contains(*display)).then_some((*display).to_string()))
        .collect();

    let server = header_value(&final_headers, "server");
    let x_powered_by = header_value(&final_headers, "x-powered-by");
    let x_generator = header_value(&final_headers, "x-generator");
    let via = header_value(&final_headers, "via");
    let cf_ray = header_value(&final_headers, "cf-ray");
    let x_varnish = header_value(&final_headers, "x-varnish");
    let x_aspnet_version = header_value(&final_headers, "x-aspnet-version");
    let content_type = header_value(&final_headers, CONTENT_TYPE.as_str());

    let mut detected_tech = Vec::new();
    for (label, value) in [
        ("server", server.clone()),
        ("x-powered-by", x_powered_by.clone()),
        ("x-generator", x_generator.clone()),
        ("via", via.clone()),
        ("cf-ray", cf_ray.clone()),
        ("x-varnish", x_varnish.clone()),
        ("x-aspnet-version", x_aspnet_version.clone()),
    ] {
        if let Some(value) = value {
            detected_tech.push(format!("{label}: {value}"));
        }
    }

    Ok(SurfaceSnapshot {
        id: None,
        user_id: None,
        target_url: normalized_target,
        captured_at: now_iso(),
        status_code: final_status,
        final_url,
        content_type,
        server,
        x_powered_by,
        x_generator,
        via,
        cf_ray,
        x_varnish,
        x_aspnet_version,
        security_headers,
        missing_security_headers,
        detected_tech,
        response_time_ms: start.elapsed().as_millis() as u64,
        redirects,
    })
}

pub fn diff_snapshots(previous: &SurfaceSnapshot, current: &SurfaceSnapshot) -> SurfaceDrift {
    let mut changes = Vec::new();

    if host(previous.final_url.as_str()) != host(current.final_url.as_str()) {
        changes.push(change(
            "high",
            "redirect",
            "final_url",
            Some(previous.final_url.clone()),
            Some(current.final_url.clone()),
            "Final response host changed",
        ));
    } else if previous.final_url != current.final_url {
        changes.push(change(
            "low",
            "redirect",
            "final_url",
            Some(previous.final_url.clone()),
            Some(current.final_url.clone()),
            "Final response URL changed",
        ));
    }

    if previous.status_code != current.status_code {
        changes.push(change(
            "medium",
            "status",
            "status_code",
            previous.status_code.map(|v| v.to_string()),
            current.status_code.map(|v| v.to_string()),
            "HTTP status changed",
        ));
    }

    let prev_headers: HashSet<String> = previous.security_headers.iter().cloned().collect();
    let curr_headers: HashSet<String> = current.security_headers.iter().cloned().collect();

    for header in prev_headers.difference(&curr_headers) {
        changes.push(change(
            "high",
            "security_header",
            header,
            Some("present".to_string()),
            Some("missing".to_string()),
            "Security header disappeared",
        ));
    }
    for header in curr_headers.difference(&prev_headers) {
        changes.push(change(
            "low",
            "security_header",
            header,
            Some("missing".to_string()),
            Some("present".to_string()),
            "Security header appeared",
        ));
    }

    compare_optional(&mut changes, "low", "tech", "server", &previous.server, &current.server, "Server header changed");
    compare_optional(
        &mut changes,
        "medium",
        "tech",
        "x_powered_by",
        &previous.x_powered_by,
        &current.x_powered_by,
        "X-Powered-By header changed",
    );
    compare_optional(
        &mut changes,
        "medium",
        "content",
        "content_type",
        &previous.content_type,
        &current.content_type,
        "Content-Type changed",
    );

    let latency_delta = current.response_time_ms.abs_diff(previous.response_time_ms);
    if latency_delta > 500 {
        changes.push(change(
            "info",
            "latency",
            "response_time_ms",
            Some(previous.response_time_ms.to_string()),
            Some(current.response_time_ms.to_string()),
            "Response time changed by more than 500ms",
        ));
    }

    let high_count = changes.iter().filter(|change| change.severity == "high").count();
    let medium_count = changes.iter().filter(|change| change.severity == "medium").count();
    let low_count = changes.iter().filter(|change| change.severity == "low").count();
    let info_count = changes.iter().filter(|change| change.severity == "info").count();

    SurfaceDrift {
        compared_at: now_iso(),
        high_count,
        medium_count,
        low_count,
        info_count,
        change_count: changes.len(),
        changes,
    }
}

fn resolve_redirect(current_url: &str, location: &HeaderValue) -> Result<String> {
    let location = location
        .to_str()
        .context("redirect location header was not valid utf-8")?;
    let base = Url::parse(current_url)?;
    let resolved = base.join(location)?;
    Ok(resolved.to_string())
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn host(url: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|parsed| parsed.host_str().map(ToString::to_string))
}

fn change(
    severity: &str,
    kind: &str,
    field: &str,
    before: Option<String>,
    after: Option<String>,
    detail: &str,
) -> SurfaceChange {
    SurfaceChange {
        severity: severity.to_string(),
        kind: kind.to_string(),
        field: field.to_string(),
        before,
        after,
        detail: detail.to_string(),
    }
}

fn compare_optional(
    changes: &mut Vec<SurfaceChange>,
    severity: &str,
    kind: &str,
    field: &str,
    previous: &Option<String>,
    current: &Option<String>,
    detail: &str,
) {
    if previous != current {
        changes.push(change(
            severity,
            kind,
            field,
            previous.clone(),
            current.clone(),
            detail,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::diff_snapshots;
    use crate::types::SurfaceSnapshot;

    fn snapshot(headers: &[&str], final_url: &str) -> SurfaceSnapshot {
        SurfaceSnapshot {
            target_url: "https://example.com/".to_string(),
            captured_at: "2025-01-01T00:00:00Z".to_string(),
            status_code: Some(200),
            final_url: final_url.to_string(),
            server: Some("nginx/1.24".to_string()),
            x_powered_by: Some("Express".to_string()),
            content_type: Some("text/html".to_string()),
            security_headers: headers.iter().map(|value| (*value).to_string()).collect(),
            missing_security_headers: vec![],
            detected_tech: vec![],
            response_time_ms: 100,
            redirects: vec!["https://example.com/".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn disappearing_security_header_is_high_severity() {
        let previous = snapshot(&["Content-Security-Policy", "X-Frame-Options"], "https://example.com/app");
        let current = snapshot(&["X-Frame-Options"], "https://example.com/app");
        let drift = diff_snapshots(&previous, &current);
        assert_eq!(drift.high_count, 1);
        assert!(drift
            .changes
            .iter()
            .any(|change| change.field == "Content-Security-Policy" && change.severity == "high"));
    }

    #[test]
    fn host_change_is_high_severity() {
        let previous = snapshot(&["Content-Security-Policy"], "https://example.com/app");
        let current = snapshot(&["Content-Security-Policy"], "https://evil.example.net/app");
        let drift = diff_snapshots(&previous, &current);
        assert!(drift
            .changes
            .iter()
            .any(|change| change.field == "final_url" && change.severity == "high"));
    }
}
