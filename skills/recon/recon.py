"""
Reconnaissance skill — port scanning, subdomain enumeration, technology
fingerprinting, sensitive file discovery, and WAF detection for authorized
security assessments.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse

# Strict internal budget so we never hit bot SKILL_TIMEOUT (120s)
RUN_BUDGET_SEC = 25
# Native diverg-recon usually finishes in <2s; nmap fallback still capped.
PORT_SCAN_MAX_SEC = 5
PORT_SCAN_MAX_SEC_TOP1000_NATIVE = 12

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
import stealth
from http_baseline import capture_baseline, is_soft_404, Baseline
from typing import Optional

import dns.resolver
from port_lists import parse_custom_port_list, ports_for_native_scan
import nmap
import requests
try:
    from Wappalyzer import Wappalyzer, WebPage
except Exception:
    try:
        from wappalyzer import Wappalyzer, WebPage
    except Exception:
        Wappalyzer = None
        WebPage = None

SESSION: stealth.StealthSession = stealth.get_session()


def _diverg_recon_path() -> Optional[Path]:
    """Path to diverg-recon binary if present (release build or PATH)."""
    env = os.environ.get("DIVERG_RECON_BIN", "").strip()
    if env:
        p = Path(env).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return p
    root = Path(__file__).resolve().parents[2]
    for name in ("diverg-recon", "diverg-recon.exe"):
        p = root / "native" / "diverg-recon" / "target" / "release" / name
        if p.is_file() and os.access(p, os.X_OK):
            return p
    which = shutil.which("diverg-recon")
    if which:
        wp = Path(which)
        if wp.is_file() and os.access(wp, os.X_OK):
            return wp
    return None


def _host_for_scan(target: str) -> str:
    """Strip URL / path / port to hostname or IP for port scan / DNS."""
    t = (target or "").strip()
    if not t:
        return t
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or ""
        return host or t.split("://", 1)[-1].split("/")[0].split(":")[0]
    return t.split("/")[0].split(":")[0]


def _scan_ports_native(target: str, port_range: str) -> Optional[list[PortResult]]:
    """Run diverg-recon ports (JSON stdin). Returns None on any failure → use nmap/socket."""
    exe = _diverg_recon_path()
    if not exe:
        return None
    host = _host_for_scan(target)
    if not host:
        return None
    ports = ports_for_native_scan(port_range)
    if not ports:
        ports = parse_custom_port_list(port_range) or []
    if not ports:
        return None
    pr = port_range.strip().lower()
    if pr == "top1000":
        deadline_ms = min(10_000, max(3000, len(ports) * 25))
        sub_timeout = float(PORT_SCAN_MAX_SEC_TOP1000_NATIVE)
    else:
        deadline_ms = min(4500, max(2000, len(ports) * 40))
        sub_timeout = float(PORT_SCAN_MAX_SEC)
    payload = {
        "host": host,
        "ports": ports,
        "connect_timeout_ms": 450,
        "deadline_ms": deadline_ms,
        "max_in_flight": 96,
    }
    try:
        proc = subprocess.run(
            [str(exe), "ports"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=sub_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    out: list[PortResult] = []
    for row in data.get("open") or []:
        try:
            out.append(
                PortResult(
                    port=int(row["port"]),
                    state=str(row.get("state", "open")),
                    service=str(row.get("service", "unknown")),
                    version=str(row.get("version", "")),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _dns_brute_native(
    domain: str,
    prefixes: list[str],
    deadline_ms: int,
    max_in_flight: int = 48,
) -> Optional[list[SubdomainResult]]:
    exe = _diverg_recon_path()
    if not exe:
        return None
    payload = {
        "domain": domain.strip().lower().rstrip("."),
        "prefixes": prefixes,
        "deadline_ms": max(500, min(deadline_ms, 60_000)),
        "max_in_flight": max_in_flight,
    }
    try:
        proc = subprocess.run(
            [str(exe), "dns-brute"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=min(90.0, deadline_ms / 1000.0 + 3.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    hits: list[SubdomainResult] = []
    for row in data.get("hits") or []:
        try:
            hits.append(
                SubdomainResult(
                    subdomain=str(row["subdomain"]),
                    ip=row.get("ip"),
                    source="dns",
                )
            )
        except (KeyError, TypeError):
            continue
    return hits


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str
    service: str
    version: str = ""


@dataclass
class SubdomainResult:
    subdomain: str
    ip: Optional[str] = None
    source: str = "dns"


@dataclass
class TechResult:
    name: str
    categories: list[str] = field(default_factory=list)
    version: str = ""


@dataclass
class SensitiveFileResult:
    path: str
    status_code: int
    severity: str
    category: str
    evidence: str = ""


@dataclass
class WAFResult:
    detected: bool
    name: str = ""
    confidence: str = ""
    evidence: str = ""


@dataclass
class ReconReport:
    target: str
    ports: list[PortResult] = field(default_factory=list)
    subdomains: list[SubdomainResult] = field(default_factory=list)
    technologies: list[TechResult] = field(default_factory=list)
    sensitive_files: list[SensitiveFileResult] = field(default_factory=list)
    waf: Optional[WAFResult] = None
    favicon_hash: str = ""  # MD5 of /favicon.ico for Shodan/signature lookup
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Favicon hash (for Shodan / fingerprint lookup)
# ---------------------------------------------------------------------------

def get_favicon_hash(target: str) -> str:
    """Fetch /favicon.ico and return MD5 hex digest; empty if fetch fails. Use hash in Shodan for fingerprinting."""
    try:
        base = target if target.startswith("http") else f"https://{target}"
        url = base.rstrip("/") + "/favicon.ico"
        resp = SESSION.get(url, timeout=5, allow_redirects=True)
        if resp.status_code != 200 or not resp.content:
            return ""
        return hashlib.md5(resp.content).hexdigest()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090,
]


def scan_ports(target: str, port_range: str = "top100", host_timeout: int = 20) -> list[PortResult]:
    native = _scan_ports_native(target, port_range)
    if native is not None:
        return native

    results: list[PortResult] = []
    scan_host = _host_for_scan(target)
    try:
        scanner = nmap.PortScanner()
        pr = port_range.strip().lower()
        if pr == "top100":
            args = f"-sT -T4 --top-ports 50 --host-timeout {min(host_timeout, 20)}"
        elif pr == "top10":
            plist = ",".join(str(p) for p in ports_for_native_scan("top10"))
            args = f"-sT -T4 -p {plist} --host-timeout {min(host_timeout, 20)}"
        elif pr == "top1000":
            args = f"-sV -T4 --top-ports 1000 --host-timeout {min(host_timeout, 90)}"
        else:
            args = f"-sV -T4 -p {port_range} --host-timeout {min(host_timeout, 60)}"
        scanner.scan(scan_host, arguments=args)

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    info = scanner[host][proto][port]
                    results.append(PortResult(
                        port=port,
                        state=info.get("state", "unknown"),
                        service=info.get("name", "unknown"),
                        version=info.get("version", ""),
                    ))
    except nmap.PortScannerError:
        results = _fallback_port_scan(scan_host)
    return results


def _fallback_port_scan(target: str) -> list[PortResult]:
    """TCP connect fallback when nmap binary is unavailable."""
    results: list[PortResult] = []
    host = _host_for_scan(target)
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                if sock.connect_ex((host, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    results.append(PortResult(port=port, state="open", service=service))
        except (socket.timeout, OSError):
            continue
    return results


# ---------------------------------------------------------------------------
# Subdomain wordlist — 500+ entries organized by category
# ---------------------------------------------------------------------------

SUBDOMAIN_WORDLIST = [
    # --- Standard / Common ---
    "www", "www1", "www2", "www3", "www4", "web", "web1", "web2",
    "site", "main", "home", "landing", "public",

    # --- Mail ---
    "mail", "mail2", "mail3", "email", "webmail", "smtp", "pop", "pop3",
    "imap", "mx", "mx1", "mx2", "exchange", "owa", "autodiscover",
    "autoconfig", "postfix", "mailgw", "mta", "relay",

    # --- FTP / File transfer ---
    "ftp", "ftp2", "sftp", "files", "file", "upload", "download",
    "share", "nas", "nfs", "storage", "media", "images", "img",
    "video", "audio", "content", "assets", "static",

    # --- Admin / Management ---
    "admin", "admin2", "administrator", "manage", "manager", "management",
    "panel", "cpanel", "whm", "plesk", "webmin", "console", "dashboard",
    "control", "controlpanel",

    # --- API / Services ---
    "api", "api2", "api3", "api-v1", "api-v2", "api-gateway", "gateway",
    "rest", "graphql", "grpc", "rpc", "service", "services", "svc",
    "microservices", "ws", "websocket", "socket", "realtime", "push",
    "notifications", "webhook", "webhooks", "callback",

    # --- Development ---
    "dev", "dev2", "develop", "development", "local", "test", "testing",
    "test2", "qa", "qa2", "uat", "staging", "staging2", "stage", "stage2",
    "beta", "alpha", "canary", "nightly", "sandbox", "sandbox2",
    "demo", "demo2", "preview", "pre", "preprod", "pre-prod",
    "prod", "production", "live",

    # --- CI/CD / DevOps ---
    "jenkins", "ci", "cd", "build", "deploy", "release", "artifact",
    "artifacts", "registry", "repo", "repository", "git", "gitlab",
    "github", "bitbucket", "svn", "hg", "drone", "circleci",
    "travis", "teamcity", "bamboo", "argo", "argocd", "flux",
    "terraform", "ansible", "puppet", "chef", "salt",

    # --- Cloud / Infrastructure ---
    "cloud", "aws", "azure", "gcp", "s3", "ec2", "lambda", "cf",
    "cloudfront", "cdn", "cdn2", "edge", "origin", "lb", "loadbalancer",
    "proxy", "reverse-proxy", "nginx", "apache", "haproxy",
    "kubernetes", "k8s", "kube", "docker", "container", "containers",
    "swarm", "rancher", "openshift", "mesos", "nomad",

    # --- DNS ---
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "resolver", "pdns", "bind",

    # --- VPN / Remote access ---
    "vpn", "vpn2", "vpn3", "remote", "access", "ssl-vpn", "sslvpn",
    "ras", "citrix", "rdp", "rd", "rdweb", "bastion", "jump",
    "jumphost", "connect", "anyconnect", "wireguard",

    # --- Security / Auth ---
    "secure", "security", "sso", "login", "auth", "auth2", "oauth",
    "oauth2", "iam", "id", "identity", "idp", "adfs", "cas",
    "saml", "ldap", "kerberos", "radius", "2fa", "mfa",
    "accounts", "account", "signup", "register", "password",

    # --- Monitoring / Observability ---
    "monitor", "monitoring", "status", "health", "uptime", "nagios",
    "zabbix", "grafana", "prometheus", "kibana", "elastic",
    "elasticsearch", "logstash", "splunk", "datadog", "newrelic",
    "sentry", "pagerduty", "opsgenie", "alertmanager", "icinga",
    "cacti", "mrtg", "netdata", "apm", "trace", "tracing",

    # --- Database ---
    "db", "db2", "db3", "database", "mysql", "mariadb", "postgres",
    "postgresql", "mongo", "mongodb", "redis", "memcached",
    "couchdb", "cassandra", "neo4j", "influxdb", "clickhouse",
    "oracle", "mssql", "sql", "nosql", "rds", "dynamo",

    # --- Messaging / Queue ---
    "mq", "rabbit", "rabbitmq", "kafka", "activemq", "zeromq",
    "nats", "pulsar", "celery", "queue",

    # --- CRM / ERP / Business ---
    "crm", "erp", "hr", "finance", "billing", "pay", "payment",
    "payments", "invoice", "checkout", "cart", "order", "orders",
    "shop", "store", "ecommerce", "catalog", "marketplace",
    "inventory", "supply", "procurement", "vendor", "partner",

    # --- CMS / Content ---
    "cms", "wp", "wordpress", "blog", "blog2", "drupal", "joomla",
    "magento", "prestashop", "woocommerce", "shopify", "ghost",
    "strapi", "contentful", "sanity", "typo3", "sitecore",
    "hubspot", "squarespace", "wix",

    # --- Documentation / Knowledge ---
    "docs", "doc", "documentation", "wiki", "help", "helpdesk",
    "kb", "knowledgebase", "faq", "guide", "manual", "reference",
    "confluence", "notion", "bookstack",

    # --- Support / Tickets ---
    "support", "support2", "ticket", "tickets", "helpdesk",
    "servicedesk", "jira", "zendesk", "freshdesk", "intercom",
    "feedback", "survey", "contact",

    # --- Communication ---
    "chat", "im", "messenger", "slack", "teams", "mattermost",
    "rocketchat", "matrix", "xmpp", "irc", "forum", "forums",
    "community", "discuss", "discourse",

    # --- Analytics / Marketing ---
    "analytics", "track", "tracking", "pixel", "ad", "ads",
    "marketing", "campaign", "promo", "promotions", "newsletter",
    "subscribe", "unsubscribe", "segment", "mixpanel",
    "matomo", "piwik", "plausible",

    # --- Search ---
    "search", "solr", "sphinx", "algolia", "typesense",
    "meilisearch", "lucene",

    # --- Mobile / Apps ---
    "app", "app2", "mobile", "m", "ios", "android",
    "api-mobile", "mobileapi", "appstore",

    # --- Corporate / Info ---
    "about", "careers", "jobs", "recruit", "investor", "investors",
    "ir", "press", "news", "events", "corporate", "corp",

    # --- Network / Internal ---
    "intranet", "internal", "private", "extranet", "lan", "wan",
    "network", "noc", "soc",

    # --- Legacy / Backup ---
    "old", "legacy", "archive", "bak", "backup", "backup2",
    "temp", "tmp", "cache", "dr", "failover",

    # --- Version-specific ---
    "v1", "v2", "v3", "v4", "new", "next",

    # --- Miscellaneous services ---
    "portal", "portal2", "gateway2", "hub", "central", "core",
    "platform", "sys", "system", "systems", "tools", "tool",
    "util", "utils", "lab", "labs", "research", "r-d", "rnd",
    "bench", "perf", "performance", "loadtest",

    # --- Collaboration ---
    "sharepoint", "onedrive", "box", "dropbox", "gdrive",
    "collab", "workspace",

    # --- Printing / Scanning ---
    "print", "printer", "scan", "scanner",

    # --- Telephony / VoIP ---
    "voip", "sip", "pbx", "asterisk", "phone", "tel",
    "fax", "callcenter",

    # --- IoT / SCADA ---
    "iot", "scada", "plc", "sensor", "sensors", "device",
    "devices", "embedded",

    # --- Geographic / CDN ---
    "us", "eu", "uk", "de", "fr", "jp", "cn", "au", "ca",
    "us-east", "us-west", "eu-west", "ap-south",
    "east", "west", "north", "south", "central",

    # --- Cryptography / Certificates ---
    "ca", "cert", "certs", "pki", "ocsp", "crl",
    "vault", "secrets", "hsm",

    # --- Logging ---
    "log", "logs", "logging", "syslog", "audit",
    "journal", "events-log",

    # --- Data / BI ---
    "data", "bigdata", "hadoop", "spark", "hive",
    "bi", "reporting", "reports", "report",
    "tableau", "powerbi", "looker", "metabase", "redash",

    # --- Streaming ---
    "stream", "streaming", "live", "broadcast",
    "rtmp", "hls", "webrtc", "video-api",

    # --- Payments ---
    "stripe", "paypal", "braintree", "adyen",
    "pos", "terminal",

    # --- Additional misc ---
    "ns5", "ns6", "mx3", "mx4",
    "relay2", "gw", "gw2", "firewall", "fw",
    "ids", "ips", "waf",
    "siem", "soar",
    "git-lfs", "lfs",
    "npm", "pypi", "nuget", "maven",
    "mirror", "mirrors",
    "torrent", "tracker",
    "calendar", "cal",
    "map", "maps", "geo", "gis", "location",
    "translate", "i18n", "l10n",
    "socket-io", "sse",
    "cname", "txt", "spf", "dkim", "dmarc",
]


# ---------------------------------------------------------------------------
# Passive subdomain discovery via crt.sh
# ---------------------------------------------------------------------------

def _crtsh_subdomains(domain: str) -> list[SubdomainResult]:
    """Query certificate transparency logs via crt.sh for passive subdomain discovery."""
    results: list[SubdomainResult] = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = SESSION.get(url, timeout=20)
        if resp.status_code != 200:
            return results

        entries = resp.json()
        seen: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.lower().split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    if name not in seen and name != domain:
                        seen.add(name)
                        results.append(SubdomainResult(
                            subdomain=name, source="crt.sh",
                        ))
    except requests.exceptions.Timeout:
        pass
    except (requests.RequestException, json.JSONDecodeError, KeyError):
        pass
    return results


# ---------------------------------------------------------------------------
# Subdomain enumeration (DNS brute-force + crt.sh merge)
# ---------------------------------------------------------------------------

def enumerate_subdomains(
    domain: str,
    timeout_sec: Optional[float] = None,
    max_prefixes: Optional[int] = None,
) -> list[SubdomainResult]:
    results: list[SubdomainResult] = []
    seen: set[str] = set()
    start = time.time()

    # Phase 1: passive via crt.sh (fast, keep it)
    try:
        if timeout_sec and (time.time() - start) > timeout_sec:
            return results
        crt_results = _crtsh_subdomains(domain)
        for r in crt_results:
            if r.subdomain not in seen:
                seen.add(r.subdomain)
                results.append(r)
    except Exception:
        pass

    # Phase 2: active DNS brute-force (cap by time and count to avoid timeout)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 1.5

    wordlist = stealth.randomize_order(SUBDOMAIN_WORDLIST)
    eff_cap = max_prefixes
    if eff_cap is not None and _diverg_recon_path():
        eff_cap = min(len(SUBDOMAIN_WORDLIST), eff_cap * 2)
    if eff_cap is not None:
        wordlist = wordlist[:eff_cap]

    remaining_ms = int((timeout_sec - (time.time() - start)) * 1000) if timeout_sec else 14_000
    remaining_ms = max(800, min(remaining_ms, 55_000))
    dns_native = _dns_brute_native(domain, wordlist, remaining_ms, max_in_flight=56)
    if dns_native is not None:
        for r in dns_native:
            if r.subdomain not in seen:
                seen.add(r.subdomain)
                results.append(r)
    else:
        for prefix in wordlist:
            if timeout_sec and (time.time() - start) > timeout_sec:
                break
            fqdn = f"{prefix}.{domain}"
            if fqdn in seen:
                continue
            try:
                answers = resolver.resolve(fqdn, "A")
                ip = str(answers[0]) if answers else None
                seen.add(fqdn)
                results.append(SubdomainResult(subdomain=fqdn, ip=ip, source="dns"))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                continue

    # Resolve IPs for crt.sh results that don't have one yet (quick pass)
    for r in results:
        if timeout_sec and (time.time() - start) > timeout_sec:
            break
        if r.ip is None:
            try:
                answers = resolver.resolve(r.subdomain, "A")
                r.ip = str(answers[0]) if answers else None
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Sensitive file / path discovery
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, severity, category)
    # --- VCS ---
    (".git/HEAD", "High", "VCS"),
    (".git/config", "High", "VCS"),
    (".git/logs/HEAD", "High", "VCS"),
    (".git/index", "High", "VCS"),
    (".gitignore", "Low", "VCS"),
    (".svn/entries", "High", "VCS"),
    (".svn/wc.db", "High", "VCS"),
    (".hg/requires", "High", "VCS"),
    (".hg/store/fncache", "High", "VCS"),
    (".bzr/README", "High", "VCS"),
    (".cvs/Entries", "High", "VCS"),

    # --- Environment / Config ---
    (".env", "Critical", "Config"),
    (".env.local", "Critical", "Config"),
    (".env.production", "Critical", "Config"),
    (".env.staging", "Critical", "Config"),
    (".env.development", "Critical", "Config"),
    (".env.backup", "Critical", "Config"),
    (".env.bak", "Critical", "Config"),
    (".env.old", "Critical", "Config"),
    (".env.save", "Critical", "Config"),
    ("wp-config.php", "Critical", "Config"),
    ("wp-config.php.bak", "Critical", "Config"),
    ("wp-config.php.old", "Critical", "Config"),
    ("wp-config.php.save", "Critical", "Config"),
    ("wp-config.php.swp", "Critical", "Config"),
    ("wp-config.php.txt", "Critical", "Config"),
    ("config.php", "High", "Config"),
    ("config.inc.php", "High", "Config"),
    ("config.yml", "High", "Config"),
    ("config.yaml", "High", "Config"),
    ("config.json", "High", "Config"),
    ("config.xml", "High", "Config"),
    ("config.ini", "High", "Config"),
    ("configuration.php", "High", "Config"),
    ("settings.py", "High", "Config"),
    ("settings.ini", "High", "Config"),
    ("local_settings.py", "High", "Config"),
    ("application.properties", "High", "Config"),
    ("application.yml", "High", "Config"),
    ("appsettings.json", "High", "Config"),
    ("appsettings.Development.json", "High", "Config"),
    ("web.config", "High", "Config"),
    ("web.config.bak", "Critical", "Config"),
    (".htaccess", "Medium", "Config"),
    (".htpasswd", "Critical", "Config"),
    ("nginx.conf", "High", "Config"),

    # --- Database ---
    ("backup.sql", "Critical", "Database"),
    ("dump.sql", "Critical", "Database"),
    ("database.sql", "Critical", "Database"),
    ("db.sql", "Critical", "Database"),
    ("data.sql", "Critical", "Database"),
    ("mysql.sql", "Critical", "Database"),
    ("db.sqlite3", "Critical", "Database"),
    ("database.sqlite", "Critical", "Database"),
    ("db.sqlite", "Critical", "Database"),

    # --- DevOps ---
    ("Dockerfile", "Medium", "DevOps"),
    ("docker-compose.yml", "Medium", "DevOps"),
    ("docker-compose.yaml", "Medium", "DevOps"),
    (".dockerenv", "Medium", "DevOps"),
    ("Vagrantfile", "Medium", "DevOps"),
    ("ansible.cfg", "Medium", "DevOps"),
    (".travis.yml", "Medium", "DevOps"),
    ("Jenkinsfile", "Medium", "DevOps"),
    (".gitlab-ci.yml", "Medium", "DevOps"),
    (".github/workflows/main.yml", "Medium", "DevOps"),
    (".github/workflows/ci.yml", "Medium", "DevOps"),
    ("Procfile", "Low", "DevOps"),
    ("Makefile", "Low", "DevOps"),
    (".circleci/config.yml", "Medium", "DevOps"),

    # --- Diagnostics ---
    ("phpinfo.php", "High", "Diagnostics"),
    ("info.php", "High", "Diagnostics"),
    ("test.php", "Medium", "Diagnostics"),
    ("pi.php", "High", "Diagnostics"),
    ("i.php", "High", "Diagnostics"),
    ("server-status", "High", "Diagnostics"),
    ("server-info", "High", "Diagnostics"),
    ("elmah.axd", "High", "Diagnostics"),
    ("trace.axd", "High", "Diagnostics"),
    ("health", "Low", "Diagnostics"),
    ("healthz", "Low", "Diagnostics"),
    ("readyz", "Low", "Diagnostics"),
    ("metrics", "Medium", "Diagnostics"),

    # --- Logs ---
    ("error.log", "Medium", "Logs"),
    ("debug.log", "Medium", "Logs"),
    ("access.log", "Medium", "Logs"),
    ("app.log", "Medium", "Logs"),
    ("application.log", "Medium", "Logs"),
    ("error_log", "Medium", "Logs"),
    ("wp-content/debug.log", "Medium", "Logs"),
    ("logs/error.log", "Medium", "Logs"),
    ("logs/access.log", "Medium", "Logs"),
    ("log/production.log", "Medium", "Logs"),
    ("log/development.log", "Medium", "Logs"),

    # --- Backups ---
    ("backup.zip", "Critical", "Backups"),
    ("backup.tar.gz", "Critical", "Backups"),
    ("backup.tar", "Critical", "Backups"),
    ("site.zip", "Critical", "Backups"),
    ("www.zip", "Critical", "Backups"),
    ("public.zip", "Critical", "Backups"),
    ("html.zip", "Critical", "Backups"),
    ("web.zip", "Critical", "Backups"),
    ("htdocs.zip", "Critical", "Backups"),
    ("archive.zip", "Critical", "Backups"),
    ("backup.rar", "Critical", "Backups"),
    ("db-backup.tar.gz", "Critical", "Backups"),

    # --- Cloud credentials ---
    (".aws/credentials", "Critical", "Cloud"),
    (".aws/config", "High", "Cloud"),
    (".gcloud/credentials", "Critical", "Cloud"),
    (".azure/credentials", "Critical", "Cloud"),
    (".kube/config", "Critical", "Cloud"),

    # --- PHP ---
    ("composer.json", "Low", "PHP"),
    ("composer.lock", "Low", "PHP"),
    ("vendor/autoload.php", "Medium", "PHP"),

    # --- Node.js ---
    ("package.json", "Low", "Node"),
    ("package-lock.json", "Low", "Node"),
    ("yarn.lock", "Low", "Node"),
    ("node_modules/.package-lock.json", "Medium", "Node"),
    (".npmrc", "High", "Node"),
    (".yarnrc", "Medium", "Node"),

    # --- Python ---
    ("requirements.txt", "Low", "Python"),
    ("Pipfile", "Low", "Python"),
    ("Pipfile.lock", "Low", "Python"),
    ("setup.py", "Low", "Python"),
    ("setup.cfg", "Low", "Python"),
    ("pyproject.toml", "Low", "Python"),

    # --- Ruby ---
    ("Gemfile", "Low", "Ruby"),
    ("Gemfile.lock", "Low", "Ruby"),

    # --- API docs ---
    ("swagger.json", "Medium", "APIDocs"),
    ("swagger.yaml", "Medium", "APIDocs"),
    ("swagger/", "Medium", "APIDocs"),
    ("openapi.json", "Medium", "APIDocs"),
    ("openapi.yaml", "Medium", "APIDocs"),
    ("api-docs", "Medium", "APIDocs"),
    ("api-docs/", "Medium", "APIDocs"),
    ("graphql", "Medium", "APIDocs"),
    ("graphiql", "Medium", "APIDocs"),
    ("_graphql", "Medium", "APIDocs"),
    ("altair", "Medium", "APIDocs"),
    ("playground", "Medium", "APIDocs"),
    ("api/v1/docs", "Medium", "APIDocs"),
    ("redoc", "Medium", "APIDocs"),

    # --- Security files ---
    ("security.txt", "Low", "Security"),
    (".well-known/security.txt", "Low", "Security"),
    ("crossdomain.xml", "Medium", "Security"),
    ("clientaccesspolicy.xml", "Medium", "Security"),
    ("robots.txt", "Low", "Security"),
    ("sitemap.xml", "Low", "Security"),
    ("humans.txt", "Low", "Security"),

    # --- Admin panels ---
    ("admin", "Medium", "Admin"),
    ("admin/", "Medium", "Admin"),
    ("administrator", "Medium", "Admin"),
    ("administrator/", "Medium", "Admin"),
    ("wp-admin", "Medium", "Admin"),
    ("wp-admin/", "Medium", "Admin"),
    ("wp-login.php", "Medium", "Admin"),
    ("manager", "Medium", "Admin"),
    ("manager/html", "Medium", "Admin"),
    ("phpmyadmin", "High", "Admin"),
    ("phpmyadmin/", "High", "Admin"),
    ("pma", "High", "Admin"),
    ("adminer", "High", "Admin"),
    ("adminer.php", "High", "Admin"),
    ("_admin", "Medium", "Admin"),
    ("cp", "Medium", "Admin"),
    ("controlpanel", "Medium", "Admin"),
    ("backend", "Medium", "Admin"),

    # --- Miscellaneous ---
    (".DS_Store", "Medium", "Misc"),
    ("Thumbs.db", "Low", "Misc"),
    (".idea/workspace.xml", "Medium", "Misc"),
    (".vscode/settings.json", "Medium", "Misc"),
    ("debug/", "Medium", "Misc"),
    ("temp/", "Medium", "Misc"),
    ("tmp/", "Medium", "Misc"),
    ("test/", "Medium", "Misc"),
    (".well-known/openid-configuration", "Low", "Misc"),
    ("actuator", "High", "Misc"),
    ("actuator/env", "Critical", "Misc"),
    ("actuator/health", "Low", "Misc"),
    ("actuator/configprops", "Critical", "Misc"),
    ("actuator/mappings", "Medium", "Misc"),
    ("jolokia", "High", "Misc"),
    ("jolokia/list", "High", "Misc"),
]


def discover_sensitive_files(
    target: str,
    max_paths: Optional[int] = None,
    timeout_sec: Optional[float] = None,
    _baseline: Optional[Baseline] = None,
) -> list[SensitiveFileResult]:
    """Probe for sensitive files and paths that shouldn't be publicly accessible."""
    base_url = target if target.startswith("http") else f"https://{target}"
    base_url = base_url.rstrip("/")
    results: list[SensitiveFileResult] = []
    started = time.time()

    paths_to_check = stealth.randomize_order(SENSITIVE_PATHS)
    if max_paths is not None:
        paths_to_check = paths_to_check[:max_paths]

    for path_entry, severity, category in paths_to_check:
        if timeout_sec and (time.time() - started) > timeout_sec:
            break
        url = f"{base_url}/{path_entry}"
        try:
            resp = SESSION.get(url, timeout=6, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                evidence_parts: list[str] = []
                if resp.status_code == 200:
                    if _baseline and is_soft_404(resp, _baseline):
                        continue

                    content_type = resp.headers.get("Content-Type", "")
                    content_length = resp.headers.get("Content-Length", "")
                    body_preview = resp.text[:200].strip() if resp.text else ""

                    lower_body = body_preview.lower()
                    if any(marker in lower_body for marker in
                           ["not found", "404", "page not found", "does not exist"]):
                        continue

                    evidence_parts.append(f"Status: {resp.status_code}")
                    if content_type:
                        evidence_parts.append(f"Content-Type: {content_type}")
                    if content_length:
                        evidence_parts.append(f"Content-Length: {content_length}")
                    if body_preview:
                        evidence_parts.append(f"Body: {body_preview}")
                elif resp.status_code == 403:
                    evidence_parts.append("Status: 403 Forbidden (exists but protected)")
                    severity = "Low"
                elif resp.status_code in (301, 302):
                    location = resp.headers.get("Location", "")
                    evidence_parts.append(
                        f"Status: {resp.status_code} -> {location}"
                    )
                    severity = "Low"

                results.append(SensitiveFileResult(
                    path=f"/{path_entry}",
                    status_code=resp.status_code,
                    severity=severity,
                    category=category,
                    evidence=" | ".join(evidence_parts),
                ))
        except requests.RequestException:
            continue

    return results


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------

WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (waf_name, header_or_field, pattern)
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "cf-ray", ""),
    ("Cloudflare", "cf-cache-status", ""),
    ("AWS WAF", "x-amzn-requestid", ""),
    ("AWS WAF", "x-amz-cf-id", ""),
    ("AWS CloudFront", "x-amz-cf-pop", ""),
    ("AWS CloudFront", "via", "cloudfront"),
    ("Akamai", "x-akamai-transformed", ""),
    ("Akamai", "server", "akamaighost"),
    ("Akamai", "server", "akamai"),
    ("Sucuri", "server", "sucuri"),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "x-sucuri-cache", ""),
    ("ModSecurity", "server", "mod_security"),
    ("ModSecurity", "server", "modsecurity"),
    ("Imperva", "x-iinfo", ""),
    ("Imperva", "x-cdn", "imperva"),
    ("Incapsula", "x-cdn", "incapsula"),
    ("Incapsula", "x-iinfo", ""),
    ("F5 BIG-IP", "server", "big-ip"),
    ("F5 BIG-IP", "x-wa-info", ""),
    ("F5 BIG-IP ASM", "server", "bigip"),
    ("Barracuda", "server", "barracuda"),
    ("Barracuda", "barra_counter_session", ""),
    ("Fortinet FortiWeb", "server", "fortiweb"),
    ("Fortinet", "fortiwafsid", ""),
    ("DenyAll", "server", "denyall"),
    ("Wallarm", "server", "wallarm"),
    ("Citrix NetScaler", "via", "ns-cache"),
    ("Citrix NetScaler", "set-cookie", "ns_af"),
    ("Edgecast", "server", "ecacc"),
    ("StackPath", "x-sp-url", ""),
    ("Fastly", "x-fastly-request-id", ""),
    ("Fastly", "via", "varnish"),
    ("Varnish", "x-varnish", ""),
    ("KeyCDN", "server", "keycdn"),
    ("Reblaze", "server", "reblaze"),
    ("DDoS-Guard", "server", "ddos-guard"),
    ("Qrator", "server", "qrator"),
]

WAF_BODY_SIGNATURES: list[tuple[str, str]] = [
    ("Cloudflare", "attention required! | cloudflare"),
    ("Cloudflare", "cloudflare ray id"),
    ("Sucuri", "access denied - sucuri website firewall"),
    ("Sucuri", "sucuri websitefirewall"),
    ("ModSecurity", "mod_security"),
    ("ModSecurity", "this error was generated by mod_security"),
    ("Imperva", "incapsula incident id"),
    ("Imperva", "powered by incapsula"),
    ("Wordfence", "generated by wordfence"),
    ("Wordfence", "a potentially unsafe operation has been detected"),
    ("AWS WAF", "aws waf"),
    ("F5 BIG-IP", "the requested url was rejected"),
    ("Barracuda", "barracuda networks"),
    ("DDoS-Guard", "ddos protection by ddos-guard"),
    ("Comodo", "protected by comodo waf"),
]


def detect_waf(target: str) -> WAFResult:
    """Detect Web Application Firewalls via header inspection and probe requests."""
    base_url = target if target.startswith("http") else f"https://{target}"
    detected_wafs: dict[str, list[str]] = {}

    # Phase 1: normal request — check headers
    try:
        resp = SESSION.get(base_url, timeout=10, allow_redirects=True)
        _check_waf_headers(resp, detected_wafs)
        _check_waf_body(resp, detected_wafs)
    except requests.RequestException:
        pass

    # Phase 2: suspicious request — trigger WAF if present
    probe_paths = [
        f"{base_url}/?id=1' OR '1'='1",
        f"{base_url}/<script>alert(1)</script>",
        f"{base_url}/../../etc/passwd",
    ]
    for probe_url in stealth.randomize_order(probe_paths):
        try:
            resp = SESSION.get(probe_url, timeout=10, allow_redirects=True)
            _check_waf_headers(resp, detected_wafs)
            _check_waf_body(resp, detected_wafs)
            if resp.status_code in (403, 406, 429, 501, 503):
                detected_wafs.setdefault("Unknown WAF", []).append(
                    f"Blocked probe with {resp.status_code}"
                )
        except requests.RequestException:
            pass

    if not detected_wafs:
        return WAFResult(detected=False)

    best_waf = max(detected_wafs, key=lambda w: len(detected_wafs[w]))
    evidence_list = detected_wafs[best_waf]
    n_signals = len(evidence_list)
    if n_signals >= 3:
        confidence = "High"
    elif n_signals >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"

    return WAFResult(
        detected=True,
        name=best_waf,
        confidence=confidence,
        evidence="; ".join(evidence_list[:5]),
    )


def _check_waf_headers(resp: requests.Response, found: dict[str, list[str]]) -> None:
    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    for waf_name, header_key, pattern in WAF_SIGNATURES:
        header_val = headers_lower.get(header_key, "")
        if header_val and (not pattern or pattern in header_val):
            found.setdefault(waf_name, []).append(
                f"Header {header_key}: {resp.headers.get(header_key, '')}"
            )


def _check_waf_body(resp: requests.Response, found: dict[str, list[str]]) -> None:
    body_lower = (resp.text or "")[:4000].lower()
    if not body_lower:
        return
    for waf_name, signature in WAF_BODY_SIGNATURES:
        if signature in body_lower:
            found.setdefault(waf_name, []).append(f"Body contains '{signature}'")


# ---------------------------------------------------------------------------
# Technology fingerprinting (enhanced)
# ---------------------------------------------------------------------------

TECH_HEADERS = [
    ("Server", "web-server"),
    ("X-Powered-By", "framework"),
    ("X-Generator", "cms"),
    ("X-Drupal-Cache", "cms"),
    ("X-Varnish", "cache"),
    ("X-Cache", "cache"),
    ("X-Served-By", "cdn"),
    ("X-AspNet-Version", "framework"),
    ("X-AspNetMvc-Version", "framework"),
    ("X-Runtime", "framework"),
    ("X-Request-Id", "framework"),
    ("X-Shopify-Stage", "ecommerce"),
    ("X-GitHub-Request-Id", "hosting"),
    ("X-Vercel-Id", "hosting"),
    ("X-Netlify-Request-Id", "hosting"),
    ("X-Amz-Cf-Pop", "cdn"),
    ("X-Fastly-Request-Id", "cdn"),
]

FRAMEWORK_PATHS: list[tuple[str, str, list[str], list[str]]] = [
    ("/wp-content/", "WordPress", ["cms"], ["wp-content", "wordpress", "wp-includes"]),
    ("/wp-includes/", "WordPress", ["cms"], ["wp-includes", "wordpress"]),
    ("/wp-json/wp/v2/", "WordPress REST API", ["cms", "api"], ["wp/v2", "namespace", "routes"]),
    ("/drupal/", "Drupal", ["cms"], ["drupal", "sites/default"]),
    ("/sites/default/files/", "Drupal", ["cms"], ["drupal", "sites/default"]),
    ("/misc/drupal.js", "Drupal", ["cms"], ["drupal", "Drupal"]),
    ("/static/admin/", "Django", ["framework"], ["django", "csrfmiddlewaretoken", "admin"]),
    ("/django-admin/", "Django", ["framework"], ["django", "csrfmiddlewaretoken", "login"]),
    ("/rails/info", "Ruby on Rails", ["framework"], ["rails", "ruby", "routes"]),
    ("/rails/info/routes", "Ruby on Rails", ["framework"], ["rails", "routes", "controller"]),
    ("/assets/application.js", "Ruby on Rails", ["framework"], ["application", "turbo", "stimulus"]),
    ("/laravel/", "Laravel", ["framework"], ["laravel", "blade"]),
    ("/vendor/laravel/", "Laravel", ["framework"], ["laravel", "illuminate"]),
    ("/yii/", "Yii", ["framework"], ["yii", "Yii"]),
    ("/symphony/", "Symfony", ["framework"], ["symfony", "Symfony"]),
    ("/craft/", "Craft CMS", ["cms"], ["craft", "Craft"]),
    ("/umbraco/", "Umbraco", ["cms"], ["umbraco", "Umbraco"]),
    ("/sitecore/", "Sitecore", ["cms"], ["sitecore", "Sitecore"]),
    ("/typo3/", "TYPO3", ["cms"], ["typo3", "TYPO3"]),
    ("/ghost/api/", "Ghost", ["cms"], ["ghost", "Ghost"]),
    ("/strapi/", "Strapi", ["cms"], ["strapi", "Strapi"]),
    ("/_next/", "Next.js", ["framework", "javascript"], ["_next", "__next", "next"]),
    ("/_nuxt/", "Nuxt.js", ["framework", "javascript"], ["_nuxt", "__nuxt", "nuxt"]),
    ("/remix-build/", "Remix", ["framework", "javascript"], ["remix", "Remix"]),
    ("/astro/", "Astro", ["framework"], ["astro", "Astro"]),
]

JS_FRAMEWORK_MARKERS: list[tuple[str, str, list[str]]] = [
    ("__NEXT_DATA__", "Next.js", ["framework", "javascript"]),
    ("__NUXT__", "Nuxt.js", ["framework", "javascript"]),
    ("window.__remixContext", "Remix", ["framework", "javascript"]),
    ("ng-version=", "Angular", ["framework", "javascript"]),
    ("ng-app", "AngularJS", ["framework", "javascript"]),
    ('data-reactroot', "React", ["framework", "javascript"]),
    ("_react", "React", ["framework", "javascript"]),
    ("__vue__", "Vue.js", ["framework", "javascript"]),
    ("data-v-", "Vue.js", ["framework", "javascript"]),
    ("id=\"__svelte\"", "Svelte", ["framework", "javascript"]),
    ("svelte-", "SvelteKit", ["framework", "javascript"]),
    ("data-gatsby", "Gatsby", ["framework", "javascript"]),
    ("___gatsby", "Gatsby", ["framework", "javascript"]),
    ("__ember__", "Ember.js", ["framework", "javascript"]),
    ("data-turbo", "Hotwire/Turbo", ["framework", "javascript"]),
    ("Blazor", "Blazor", ["framework"]),
    ("_blazor", "Blazor", ["framework"]),
    ("window.__APOLLO_STATE__", "Apollo GraphQL", ["framework", "javascript"]),
    ("__RELAY_STORE__", "Relay", ["framework", "javascript"]),
    ("Astro.glob", "Astro", ["framework"]),
]

META_GENERATOR_MAP: list[tuple[str, str, list[str]]] = [
    ("wordpress", "WordPress", ["cms"]),
    ("drupal", "Drupal", ["cms"]),
    ("joomla", "Joomla", ["cms"]),
    ("typo3", "TYPO3", ["cms"]),
    ("hugo", "Hugo", ["static-site"]),
    ("jekyll", "Jekyll", ["static-site"]),
    ("ghost", "Ghost", ["cms"]),
    ("wix.com", "Wix", ["cms"]),
    ("squarespace", "Squarespace", ["cms"]),
    ("weebly", "Weebly", ["cms"]),
    ("shopify", "Shopify", ["ecommerce"]),
    ("magento", "Magento", ["ecommerce"]),
    ("prestashop", "PrestaShop", ["ecommerce"]),
    ("blogger", "Blogger", ["cms"]),
    ("medium", "Medium", ["cms"]),
    ("gatsby", "Gatsby", ["static-site"]),
    ("hexo", "Hexo", ["static-site"]),
    ("pelican", "Pelican", ["static-site"]),
    ("eleventy", "Eleventy", ["static-site"]),
    ("mkdocs", "MkDocs", ["documentation"]),
    ("docusaurus", "Docusaurus", ["documentation"]),
    ("vuepress", "VuePress", ["documentation"]),
]


def fingerprint_tech(
    target: str,
    timeout_sec: Optional[float] = None,
    max_paths: int = 14,
    _baseline: Optional[Baseline] = None,
) -> list[TechResult]:
    results: list[TechResult] = []
    seen: set[str] = set()
    url = target if target.startswith("http") else f"https://{target}"
    started = time.time()

    def _over() -> bool:
        return timeout_sec is not None and (time.time() - started) > timeout_sec

    def _add(name: str, categories: list[str], version: str = "") -> None:
        if name.lower() not in seen:
            seen.add(name.lower())
            results.append(TechResult(name=name, categories=categories, version=version))

    # Wappalyzer detection (can be slow)
    if not _over() and Wappalyzer and WebPage:
        try:
            wappalyzer = Wappalyzer.latest()
            resp = SESSION.get(url, timeout=8, allow_redirects=True)
            webpage = WebPage.new_from_response(resp)
            detected = wappalyzer.analyze_with_categories(webpage)
            for tech_name, details in detected.items():
                _add(tech_name, details.get("categories", []))
        except Exception:
            pass

    # Header-based detection
    if not _over():
        try:
            resp = SESSION.get(url, timeout=8, allow_redirects=True)
            for header_name, category in TECH_HEADERS:
                if _over():
                    break
                val = resp.headers.get(header_name, "")
                if val:
                    _add(val, [category])
            body = resp.text or ""
            generator_matches = re.findall(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                body, re.IGNORECASE,
            )
            for gen in generator_matches[:5]:
                if _over():
                    break
                matched = False
                for keyword, tech_name, cats in META_GENERATOR_MAP:
                    if keyword in gen.lower():
                        version = gen.replace(tech_name, "").strip().strip("/").strip()
                        _add(tech_name, cats, version)
                        matched = True
                        break
                if not matched:
                    _add(gen.strip(), ["cms"])
            body_sample = body[:50000]
            for marker, framework_name, cats in JS_FRAMEWORK_MARKERS:
                if _over():
                    break
                if marker in body_sample:
                    _add(framework_name, cats)
        except requests.RequestException:
            pass

    # Framework-specific paths (cap count and time) — require body evidence
    paths_to_check = stealth.randomize_order(FRAMEWORK_PATHS)[:max_paths]
    for path, framework_name, cats, body_markers in paths_to_check:
        if _over():
            break
        check_url = f"{url.rstrip('/')}{path}"
        try:
            resp = SESSION.get(check_url, timeout=4, allow_redirects=False)
            if resp.status_code == 200:
                if _baseline and is_soft_404(resp, _baseline):
                    continue
                body_lower = (resp.text or "")[:8000].lower()
                if any(m.lower() in body_lower for m in body_markers):
                    _add(framework_name, cats)
        except requests.RequestException:
            continue

    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    target: str,
    scan_type: str = "full",
    port_range: str = "top100",
) -> str:
    report = ReconReport(target=target)
    base_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    run_start = time.time()

    stealth.set_scan_seed(target)

    baseline: Optional[Baseline] = None
    try:
        url_for_baseline = target if target.startswith("http") else f"https://{target}"
        baseline = capture_baseline(SESSION, url_for_baseline)
    except Exception:
        pass

    def _over_budget() -> bool:
        return (time.time() - run_start) > RUN_BUDGET_SEC

    if scan_type in ("full", "techstack", "quick") and not _over_budget():
        try:
            remaining = max(2, RUN_BUDGET_SEC - (time.time() - run_start))
            tech_timeout = min(remaining - 1, 28)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    fingerprint_tech,
                    target,
                    timeout_sec=tech_timeout,
                    max_paths=14,
                    _baseline=baseline,
                )
                report.technologies = future.result(timeout=tech_timeout + 5)
        except concurrent.futures.TimeoutError:
            report.technologies = []
            report.errors.append("Tech fingerprint skipped (over time budget)")
        except Exception as exc:
            report.errors.append(f"Tech fingerprint error: {exc}")

    if scan_type in ("full", "waf", "quick") and not _over_budget():
        try:
            report.waf = detect_waf(target)
        except Exception as exc:
            report.errors.append(f"WAF detection error: {exc}")

    if scan_type in ("full", "favicon") and not _over_budget():
        try:
            report.favicon_hash = get_favicon_hash(target)
        except Exception as exc:
            report.errors.append(f"Favicon hash error: {exc}")

    if scan_type in ("full", "sensitive") and not _over_budget():
        try:
            remaining = max(2, RUN_BUDGET_SEC - (time.time() - run_start))
            report.sensitive_files = discover_sensitive_files(
                target, max_paths=20, timeout_sec=min(remaining - 1, 14),
                _baseline=baseline,
            )
        except Exception as exc:
            report.errors.append(f"Sensitive file scan error: {exc}")

    if scan_type in ("full", "subdomains") and not _over_budget():
        try:
            remaining = max(2, RUN_BUDGET_SEC - (time.time() - run_start))
            report.subdomains = enumerate_subdomains(
                base_domain,
                timeout_sec=min(remaining - 1, 16),
                max_prefixes=40,
            )
        except Exception as exc:
            report.errors.append(f"Subdomain enum error: {exc}")

    # Port scan last with hard cap so it never blows the budget
    if scan_type in ("full", "ports", "quick") and not _over_budget():
        try:
            pr_key = (port_range or "top100").strip().lower()
            port_wait = (
                PORT_SCAN_MAX_SEC_TOP1000_NATIVE
                if pr_key == "top1000" and _diverg_recon_path()
                else PORT_SCAN_MAX_SEC
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(scan_ports, target, port_range, host_timeout=12)
                report.ports = future.result(timeout=port_wait)
        except concurrent.futures.TimeoutError:
            report.ports = []
            report.errors.append("Port scan skipped (over time budget)")
        except Exception as exc:
            report.errors.append(f"Port scan error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
