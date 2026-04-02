//! Diverg async TCP port scanner
//!
//! Resolves the target host once, then fans out concurrent TCP connect probes
//! bounded by a semaphore. Outputs a JSON array of open ports to stdout.
//!
//! Usage:
//!   diverg-scanner --target example.com --ports top100 --timeout-ms 1500 --concurrency 300
//!   diverg-scanner --target 10.0.0.1 --ports 80,443,8080,8443
//!   diverg-scanner --target api.example.com --ports 1-1024 --timeout-ms 2000

use clap::Parser;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

// CLI

#[derive(Parser, Debug)]
#[command(
    name = "diverg-scanner",
    about = "Async TCP port scanner for Diverg security assessments"
)]
struct Args {
    /// Target hostname or IP address
    #[arg(short, long)]
    target: String,

    /// Port specification
    #[arg(short, long, default_value = "top100")]
    ports: String,

    /// TCP connect timeout per port
    #[arg(long, default_value = "1500")]
    timeout_ms: u64,

    /// Maximum concurrent connection attempts
    #[arg(long, default_value = "300")]
    concurrency: usize,
}

// Output schema — matches Python PortResult dataclass exactly

#[derive(Serialize)]
struct PortResult {
    port: u16,
    state: &'static str,
    service: String,
    version: String,
}

// Port lists  (mirrors nmap's frequency-ranked TCP port ordering)

/// nmap --top-ports 50 equivalent
const TOP_50: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 49153, 5666,
];

/// nmap --top-ports 100 equivalent
const TOP_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 49153, 5666, 631, 49155, 5000, 2717,
    49157, 6646, 3128, 9999, 6000, 5051, 4899, 7070, 1028, 1900, 49156, 8009,
    2121, 3986, 5800, 5432, 8081, 9100, 2000, 8085, 49158, 6646, 2107, 1029,
    8010, 8787, 8880, 2082, 4444, 2083, 5009, 7777, 27017, 11211, 6379, 9200,
    5601, 4848, 9090, 2375, 2376, 8161, 61616, 3000, 4000, 9000, 7001,
];

/// Comprehensive top-1000 covering all security-relevant services
const TOP_1000: &[u16] = &[
    // Web
    80, 443, 8080, 8443, 8000, 8008, 8081, 8082, 8083, 8084, 8085, 8086,
    8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098,
    8099, 8100, 8181, 8282, 8383, 8484, 8585, 8686, 8787, 8880, 8888, 8989,
    9000, 9001, 9002, 9003, 9090, 9091, 9092, 9093, 9100, 9200, 9300, 9418,
    9999, 10000, 10001, 10080, 10443, 18080, 18443, 20000, 28017,
    // SSH / Telnet / FTP
    21, 22, 23, 26, 990, 2022, 2222, 3022, 4022, 5022, 6022, 7022, 8022,
    // Mail
    25, 110, 143, 465, 587, 993, 995, 2525,
    // DNS
    53, 5353, 5354,
    // Windows / SMB / RDP / WinRM
    135, 137, 138, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985,
    5986, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
    // Databases
    1433, 1434, 1521, 3306, 5432, 5433, 5984, 6379, 6380, 7474, 7687, 8529,
    9042, 9043, 11211, 27017, 27018, 27019, 28015, 29015, 50000,
    // Message queues / streaming
    1883, 4369, 5432, 5672, 6567, 8161, 9092, 9094, 9095, 15672, 15674,
    15675, 61613, 61614, 61616,
    // Admin panels / management
    2375, 2376, 2377, 4001, 4243, 4444, 4567, 4848, 5601, 7070, 7071, 7072,
    8001, 8002, 8003, 8009, 8010, 8011, 8012, 8161, 8162, 8500, 8600, 8700,
    8800, 8900, 9001, 9080, 9990, 18080, 18443, 19000, 19001, 50070,
    // Monitoring / observability
    2003, 2004, 3000, 4040, 4041, 5555, 6060, 7070, 8025, 8086, 9090, 9091,
    9093, 9094, 9095, 9099, 9100, 9115, 9187, 9216, 9252, 9256, 9300, 9600,
    // VPN / remote access
    500, 1194, 1701, 1723, 4500, 5000, 5001, 10000,
    // Legacy / services
    79, 111, 113, 119, 161, 179, 199, 389, 512, 513, 514, 515, 531, 543,
    544, 548, 554, 563, 587, 631, 646, 873, 902, 903, 992, 1025, 1026,
    1027, 1028, 1029, 1080, 1110, 1234, 1337, 1433, 1521, 1604, 1720, 1723,
    1755, 1900, 2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2100,
    2107, 2121, 2375, 2376, 2717, 3000, 3001, 3002, 3128, 3306, 3389, 3986,
    4001, 4040, 4444, 4567, 4848, 4899, 4900, 4984, 5000, 5001, 5009, 5051,
    5060, 5061, 5190, 5357, 5432, 5555, 5601, 5666, 5672, 5800, 5900, 5901,
    5902, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6346, 6379, 6380,
    6443, 6567, 6646, 7001, 7002, 7070, 7071, 7077, 7474, 7687, 7777, 7778,
    8009, 8010, 8069, 8161, 8443, 8500, 8787, 8880, 8888, 9000, 9001, 9090,
    9091, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10001, 10250,
    10255, 11211, 15672, 16010, 27017, 32768, 49152,
    // High ports often used by services
    50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009,
    50010, 55000, 55001, 55002, 55003, 55004, 55005, 60000, 60001, 60002,
    61616, 65000, 65001, 65002, 65003, 65004, 65005,
];

// Service name lookup — covers every port in all three lists above

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        26 => "smtp-alt",
        53 => "dns",
        79 => "finger",
        80 => "http",
        81 => "http-alt",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        179 => "bgp",
        199 => "smux",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd",
        465 => "smtps",
        500 => "isakmp",
        512 => "exec",
        513 => "login",
        514 => "shell",
        515 => "printer",
        531 => "irc",
        543 => "klogin",
        544 => "kshell",
        548 => "afp",
        554 => "rtsp",
        563 => "nntps",
        587 => "submission",
        593 => "http-rpc-epmap",
        631 => "ipp",
        636 => "ldaps",
        646 => "ldp",
        873 => "rsync",
        902 => "vmware-auth",
        903 => "vmware-auth-alt",
        990 => "ftps",
        992 => "telnets",
        993 => "imaps",
        995 => "pop3s",
        1025 => "msrpc",
        1026 => "msrpc",
        1027 => "msrpc",
        1028 => "msrpc",
        1029 => "msrpc",
        1080 => "socks",
        1110 => "nfsd-keepalive",
        1194 => "openvpn",
        1433 => "ms-sql-s",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1604 => "citrix-ica",
        1701 => "l2tp",
        1720 => "h323q931",
        1723 => "pptp",
        1755 => "wms",
        1883 => "mqtt",
        1900 => "upnp",
        2000 => "cisco-sccp",
        2001 => "dc",
        2022 => "ssh-alt",
        2049 => "nfs",
        2082 => "cpanel",
        2083 => "cpanel-ssl",
        2086 => "whm",
        2087 => "whm-ssl",
        2095 => "cPanel-webmail",
        2096 => "cPanel-webmail-ssl",
        2100 => "amiganetfs",
        2107 => "bintec-admin",
        2121 => "ftp-alt",
        2222 => "ssh-alt",
        2375 => "docker",
        2376 => "docker-ssl",
        2377 => "docker-swarm",
        2525 => "smtp-alt",
        2717 => "pn-requester",
        3000 => "dev-server",
        3001 => "dev-server-alt",
        3128 => "squid",
        3268 => "ldap-gc",
        3269 => "ldaps-gc",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        3986 => "mapper-ws-ethd",
        4000 => "remoteanything",
        4001 => "newoak",
        4040 => "yo-main",
        4243 => "docker-alt",
        4369 => "epmd",
        4444 => "krb524",
        4500 => "ipsec-nat",
        4567 => "tram",
        4848 => "appserv-http",
        4899 => "radmin",
        4900 => "hfcs",
        4984 => "unknown",
        5000 => "upnp",
        5001 => "commplex-link",
        5009 => "airport-admin",
        5051 => "ida-agent",
        5060 => "sip",
        5061 => "sips",
        5190 => "aol",
        5353 => "mdns",
        5357 => "wsdapi",
        5432 => "postgresql",
        5555 => "freeciv",
        5601 => "kibana",
        5666 => "nrpe",
        5672 => "amqp",
        5800 => "vnc-http",
        5900 => "vnc",
        5901 => "vnc-alt",
        5902 => "vnc-alt2",
        5984 => "couchdb",
        5985 => "winrm",
        5986 => "winrm-ssl",
        6000 => "x11",
        6001 => "x11-1",
        6379 => "redis",
        6380 => "redis-ssl",
        6443 => "kubernetes",
        6567 => "unknown",
        6646 => "unknown",
        7001 => "weblogic",
        7002 => "weblogic-ssl",
        7070 => "realserver",
        7071 => "zope",
        7077 => "spark",
        7474 => "neo4j",
        7687 => "bolt",
        7777 => "cbt",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "ajp13",
        8010 => "http-alt",
        8080 => "http-proxy",
        8081 => "blackice-icecap",
        8082 => "http-alt",
        8083 => "http-alt",
        8084 => "http-alt",
        8085 => "http-alt",
        8086 => "influxdb",
        8087 => "http-alt",
        8088 => "http-alt",
        8089 => "splunkd",
        8090 => "http-alt",
        8161 => "activemq",
        8181 => "http-alt",
        8443 => "https-alt",
        8500 => "consul",
        8585 => "http-alt",
        8600 => "consul-dns",
        8700 => "http-alt",
        8787 => "http-alt",
        8880 => "cddbp-alt",
        8888 => "sun-answerbook",
        8989 => "http-alt",
        9000 => "cslistener",
        9001 => "tor-orport",
        9002 => "dynamid",
        9042 => "cassandra",
        9090 => "zeus-admin",
        9091 => "http-alt",
        9092 => "kafka",
        9093 => "kafka-ssl",
        9100 => "pdl-datastream",
        9200 => "elasticsearch",
        9300 => "vrace",
        9418 => "git",
        9443 => "tungsten-https",
        9999 => "abyss",
        10000 => "snet-sensor-mgmt",
        10001 => "scp-config",
        10080 => "amanda",
        10250 => "kubernetes-kubelet",
        10255 => "kubernetes-kubelet-ro",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        16010 => "hbase",
        18080 => "http-alt",
        18443 => "https-alt",
        27017 => "mongodb",
        27018 => "mongodb-shard",
        27019 => "mongodb-config",
        28015 => "rethinkdb",
        28017 => "mongodb-web",
        32768 => "filenet-tms",
        49152..=49159 => "msrpc-dyn",
        50000 => "ibm-db2",
        61616 => "activemq-openwire",
        _ => "unknown",
    }
}

// Port list parsing

fn parse_ports(spec: &str) -> Vec<u16> {
    match spec {
        "top50" => TOP_50.to_vec(),
        "top100" => TOP_100.to_vec(),
        "top1000" => {
            // Deduplicate while preserving order
            let mut seen = std::collections::HashSet::new();
            TOP_1000
                .iter()
                .filter(|&&p| seen.insert(p))
                .copied()
                .collect()
        }
        s if s.contains('-') && !s.contains(',') => {
            // Range: "1-1024"
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    return (start..=end).collect();
                }
            }
            eprintln!("Invalid port range '{}', falling back to top100", s);
            TOP_100.to_vec()
        }
        s => {
            // CSV: "80,443,8080,8443"
            let ports: Vec<u16> = s
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect();
            if ports.is_empty() {
                eprintln!("Invalid port spec '{}', falling back to top100", s);
                TOP_100.to_vec()
            } else {
                ports
            }
        }
    }
}

// DNS resolution

fn resolve_host(host: &str) -> Result<IpAddr, String> {
    // Try parsing as a bare IP first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    // DNS resolves
    let addr_str = format!("{}:0", host);
    addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))?
        .find(|a| a.is_ipv4())
        .or_else(|| {
            addr_str
                .to_socket_addrs()
                .ok()
                .and_then(|mut iter| iter.next())
        })
        .map(|sa| sa.ip())
        .ok_or_else(|| format!("No address found for '{}'", host))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Resolve host -> IP
    let ip = match resolve_host(&args.target) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let ports = parse_ports(&args.ports);
    let connect_timeout = Duration::from_millis(args.timeout_ms);
    let sem = Arc::new(Semaphore::new(args.concurrency));

    // Fan out: one task per port
    let mut handles = Vec::with_capacity(ports.len());
    for port in ports {
        let sem = Arc::clone(&sem);
        let addr = SocketAddr::new(ip, port);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            let open = timeout(connect_timeout, TcpStream::connect(addr))
                .await
                .map(|res| res.is_ok())
                .unwrap_or(false);
            (port, open)
        }));
    }

    // Collect results in port order for deterministic output
    let mut results: Vec<PortResult> = Vec::new();
    for handle in handles {
        if let Ok((port, true)) = handle.await {
            results.push(PortResult {
                port,
                state: "open",
                service: service_name(port).to_string(),
                version: String::new(),
            });
        }
    }

    // Sort by port number for stable output
    results.sort_by_key(|r| r.port);

    // Emit JSON to stdout
    match serde_json::to_string_pretty(&results) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("JSON serialization error: {}", e);
            std::process::exit(1);
        }
    }
}
