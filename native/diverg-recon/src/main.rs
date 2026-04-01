//! JSON CLI for Diverg recon: `ports` and `dns-brute` (stdin JSON, stdout JSON).
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

#[derive(Debug, Deserialize)]
struct PortsInput {
    host: String,
    ports: Vec<u16>,
    #[serde(default = "default_connect_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default = "default_deadline_ports_ms")]
    deadline_ms: u64,
    #[serde(default = "default_max_in_flight_ports")]
    max_in_flight: usize,
}

fn default_connect_timeout_ms() -> u64 {
    450
}
fn default_deadline_ports_ms() -> u64 {
    5000
}
fn default_max_in_flight_ports() -> usize {
    96
}

#[derive(Debug, Serialize)]
struct PortsOutput {
    open: Vec<OpenPort>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OpenPort {
    port: u16,
    state: String,
    service: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
}

#[derive(Debug, Deserialize)]
struct DnsBruteInput {
    domain: String,
    prefixes: Vec<String>,
    #[serde(default = "default_deadline_dns_ms")]
    deadline_ms: u64,
    #[serde(default = "default_max_in_flight_dns")]
    max_in_flight: usize,
}

fn default_deadline_dns_ms() -> u64 {
    12000
}
fn default_max_in_flight_dns() -> usize {
    48
}

#[derive(Debug, Serialize)]
struct DnsBruteOutput {
    hits: Vec<DnsHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DnsHit {
    subdomain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
}

fn service_name_for_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1723 => "pptp",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5900 => "vnc",
        8080 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9090 => "zeus-admin",
        _ => "unknown",
    }
}

async fn resolve_ipv4(host: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let IpAddr::V4(v4) = ip {
            return Ok(v4);
        }
        return Err("IPv6-only host not supported for port scan in v1".into());
    }
    let mut iter = tokio::net::lookup_host((host, 80u16))
        .await
        .map_err(|e| format!("lookup_host: {e}"))?;
    for addr in iter.by_ref() {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    Err("no IPv4 address for host".into())
}

async fn ports_cmd(input: PortsInput) -> PortsOutput {
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(input.deadline_ms.max(1));
    let connect_to = Duration::from_millis(input.connect_timeout_ms.max(50).min(10_000));
    let max_f = input.max_in_flight.max(1).min(256);

    let ip = match resolve_ipv4(&input.host).await {
        Ok(ip) => ip,
        Err(e) => {
            errors.push(e);
            return PortsOutput {
                open: vec![],
                errors,
            };
        }
    };

    let sem = Arc::new(Semaphore::new(max_f));
    let mut tasks = Vec::new();

    for port in input.ports {
        if Instant::now() >= deadline {
            errors.push("deadline reached before queuing all ports".into());
            break;
        }
        let sem = Arc::clone(&sem);
        let ip = ip;
        tasks.push(tokio::spawn(async move {
            let _permit: OwnedSemaphorePermit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            if Instant::now() >= deadline {
                return None;
            }
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            match timeout(connect_to, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    let _ = stream.shutdown().await;
                    Some(OpenPort {
                        port,
                        state: "open".into(),
                        service: service_name_for_port(port).into(),
                        version: String::new(),
                    })
                }
                Ok(Err(_)) | Err(_) => None,
            }
        }));
    }

    let mut open = Vec::new();
    for t in tasks {
        if Instant::now() >= deadline {
            errors.push("deadline reached while collecting port results".into());
            break;
        }
        match t.await {
            Ok(Some(p)) => open.push(p),
            Ok(None) => {}
            Err(e) => errors.push(format!("join: {e}")),
        }
    }
    open.sort_by_key(|p| p.port);
    PortsOutput { open, errors }
}

async fn dns_brute_cmd(input: DnsBruteInput) -> DnsBruteOutput {
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(input.deadline_ms.max(1));
    let max_f = input.max_in_flight.max(1).min(128);

    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        r => r,
    };

    let sem = Arc::new(Semaphore::new(max_f));
    let domain = input.domain.trim().trim_end_matches('.').to_lowercase();
    let mut tasks = Vec::new();

    for prefix in input.prefixes {
        if Instant::now() >= deadline {
            errors.push("deadline reached before queuing all DNS queries".into());
            break;
        }
        let p = prefix.trim().to_lowercase();
        if p.is_empty() {
            continue;
        }
        let fqdn = format!("{}.{}", p, domain);
        let sem = Arc::clone(&sem);
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let _permit: OwnedSemaphorePermit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            if Instant::now() >= deadline {
                return None;
            }
            match resolver.lookup_ip(fqdn.as_str()).await {
                Ok(lookup) => {
                    let mut v4: Option<String> = None;
                    for ip in lookup.iter() {
                        if let IpAddr::V4(a) = ip {
                            v4 = Some(a.to_string());
                            break;
                        }
                    }
                    if v4.is_some() {
                        Some(DnsHit {
                            subdomain: fqdn,
                            ip: v4,
                        })
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }));
    }

    let mut hits = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    for t in tasks {
        if Instant::now() >= deadline {
            errors.push("deadline reached while collecting DNS results".into());
            break;
        }
        match t.await {
            Ok(Some(h)) => {
                if seen.insert(h.subdomain.clone(), ()).is_none() {
                    hits.push(h);
                }
            }
            Ok(None) => {}
            Err(e) => errors.push(format!("join: {e}")),
        }
    }
    hits.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    DnsBruteOutput { hits, errors }
}

fn read_stdin_json() -> Result<String, String> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("stdin: {e}"))?;
    Ok(buf)
}

#[tokio::main]
async fn main() {
    let code = run().await;
    std::process::exit(code);
}

async fn run() -> i32 {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprintln!("usage: diverg-recon ports <stdin.json | dns-brute <stdin.json");
        return 2;
    };

    let stdin = match read_stdin_json() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{{\"error\":{}}}", serde_json::to_string(&e).unwrap_or_default());
            return 1;
        }
    };

    match cmd.as_str() {
        "ports" => match serde_json::from_str::<PortsInput>(&stdin) {
            Ok(input) => {
                let out = ports_cmd(input).await;
                match serde_json::to_string(&out) {
                    Ok(json) => {
                        println!("{json}");
                        0
                    }
                    Err(e) => {
                        eprintln!("serialize: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("{{\"error\":\"invalid ports json: {e}\"}}");
                1
            }
        },
        "dns-brute" => match serde_json::from_str::<DnsBruteInput>(&stdin) {
            Ok(input) => {
                let out = dns_brute_cmd(input).await;
                match serde_json::to_string(&out) {
                    Ok(json) => {
                        println!("{json}");
                        0
                    }
                    Err(e) => {
                        eprintln!("serialize: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("{{\"error\":\"invalid dns-brute json: {e}\"}}");
                1
            }
        },
        _ => {
            eprintln!("unknown command: {cmd}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_input_deserialize_defaults() {
        let j = r#"{"host":"127.0.0.1","ports":[65535]}"#;
        let p: PortsInput = serde_json::from_str(j).unwrap();
        assert_eq!(p.connect_timeout_ms, 450);
        assert_eq!(p.deadline_ms, 5000);
        assert_eq!(p.max_in_flight, 96);
    }
}
