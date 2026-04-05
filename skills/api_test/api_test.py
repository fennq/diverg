"""
API endpoint discovery and security testing skill — finds API endpoints,
tests HTTP method handling, and probes for authentication bypass.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from stealth import get_session, randomize_order, set_scan_seed
SESSION = get_session()


def _S():
    try:
        from scan_context import get_active_http_session

        s = get_active_http_session()
        if s is not None:
            return s
    except Exception:
        pass
    return SESSION


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    url: str
    status_code: int
    methods: list[str] = field(default_factory=list)
    content_type: Optional[str] = None
    auth_required: bool = True


@dataclass
class Finding:
    title: str
    severity: str
    url: str
    category: str
    evidence: str
    impact: str
    remediation: str


@dataclass
class APIReport:
    target_url: str
    endpoints_found: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoint wordlists — organized by category, 500+ paths
# ---------------------------------------------------------------------------

# -- Core API paths --
_API_CORE = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/rest", "/rest/v1", "/rest/v2",
    "/v1", "/v2", "/v3",
    "/jsonrpc", "/xmlrpc", "/rpc",
]

# -- API resource endpoints --
_API_RESOURCES = [
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/customers", "/api/customer",
    "/api/profiles", "/api/profile", "/api/me", "/api/self",
    "/api/orders", "/api/order", "/api/invoices", "/api/invoice",
    "/api/products", "/api/product", "/api/items", "/api/item",
    "/api/categories", "/api/tags",
    "/api/posts", "/api/post", "/api/articles", "/api/article",
    "/api/comments", "/api/comment",
    "/api/files", "/api/file", "/api/uploads", "/api/upload",
    "/api/images", "/api/image", "/api/media",
    "/api/notifications", "/api/notification",
    "/api/messages", "/api/message", "/api/emails", "/api/email",
    "/api/payments", "/api/payment", "/api/billing",
    "/api/subscriptions", "/api/subscription",
    "/api/transactions", "/api/transaction",
    "/api/roles", "/api/role", "/api/permissions", "/api/permission",
    "/api/groups", "/api/group", "/api/teams", "/api/team",
    "/api/organizations", "/api/organization", "/api/org",
    "/api/projects", "/api/project",
    "/api/tasks", "/api/task", "/api/jobs", "/api/job",
    "/api/events", "/api/event",
    "/api/reports", "/api/report",
    "/api/dashboards", "/api/dashboard",
    "/api/widgets", "/api/widget",
    "/api/settings", "/api/config", "/api/configuration",
    "/api/preferences", "/api/options",
    "/api/trades", "/api/positions", "/api/portfolio", "/api/wallet", "/api/wallet/balance",
    "/api/orderbook", "/api/fills", "/api/swap", "/api/solana", "/api/rpc",
    "/api/history", "/api/activity", "/api/export", "/api/trades/history", "/api/orders/history",
    "/api/webhooks", "/api/notifications", "/api/market", "/api/quote", "/api/referral", "/api/affiliate",
    "/api/v1/me", "/api/v2/me", "/api/v1/wallet", "/api/v2/orders", "/api/account/delete", "/api/revoke",
    "/api/invite", "/api/invites", "/api/team", "/api/members", "/api/consent", "/api/data-export",
    "/api/health", "/api/ready", "/api/version", "/ws", "/socket.io", "/api/ws",
]

# -- Common REST collection endpoints (no /api prefix) --
_REST_COLLECTIONS = [
    "/users", "/customers", "/orders", "/products", "/items",
    "/posts", "/comments", "/categories", "/tags",
    "/files", "/uploads", "/images", "/media",
    "/notifications", "/messages", "/emails",
    "/accounts", "/profiles", "/groups", "/teams",
    "/roles", "/permissions", "/events", "/tasks", "/jobs",
    "/invoices", "/payments", "/subscriptions", "/transactions",
    "/reports", "/dashboards", "/projects", "/organizations",
]

# -- Auth & session --
_AUTH = [
    "/api/auth", "/api/auth/login", "/api/auth/logout",
    "/api/auth/register", "/api/auth/signup",
    "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/auth/verify", "/api/auth/confirm",
    "/api/auth/refresh", "/api/auth/token",
    "/api/auth/oauth", "/api/auth/sso", "/api/auth/saml",
    "/api/auth/2fa", "/api/auth/mfa",
    "/api/login", "/api/logout", "/api/register", "/api/signup",
    "/api/token", "/api/tokens", "/api/refresh",
    "/api/oauth/token", "/api/oauth/authorize",
    "/api/session", "/api/sessions",
    "/auth", "/auth/login", "/auth/logout",
    "/auth/register", "/auth/signup",
    "/login", "/logout", "/register", "/signup",
    "/oauth/token", "/oauth/authorize",
    "/sso", "/saml", "/cas",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]

# -- Admin & management --
_ADMIN = [
    "/admin", "/admin/", "/admin/api",
    "/admin/users", "/admin/config", "/admin/settings",
    "/admin/dashboard", "/admin/panel", "/admin/console",
    "/admin/login", "/admin/auth",
    "/admin/logs", "/admin/audit",
    "/admin/reports", "/admin/stats",
    "/admin/database", "/admin/db",
    "/admin/backup", "/admin/backups",
    "/admin/plugins", "/admin/modules",
    "/admin/cache", "/admin/queue",
    "/administrator", "/administrator/",
    "/management", "/manage",
    "/console", "/dashboard", "/panel",
    "/monitor", "/monitoring",
    "/control", "/controlpanel",
    "/cpanel", "/webadmin",
    "/sysadmin", "/supervisor",
    "/backstage", "/backoffice",
    "/internal", "/internal/api",
    "/private", "/private/api",
]

# -- Debug & diagnostics --
_DEBUG = [
    "/debug", "/debug/", "/debug/vars", "/debug/pprof",
    "/debug/pprof/goroutine", "/debug/pprof/heap",
    "/debug/pprof/threadcreate", "/debug/pprof/block",
    "/debug/pprof/mutex", "/debug/pprof/profile",
    "/debug/pprof/trace",
    "/_debug", "/_debug/",
    "/__debug__", "/__debug__/",
    "/api/debug", "/api/test",
    "/api/internal", "/api/private",
    "/trace", "/trace.axd",
    "/elmah.axd",
    "/test", "/testing",
    "/dev", "/development",
    "/staging",
    "/status", "/health", "/healthz", "/healthcheck",
    "/ready", "/readyz", "/readiness",
    "/live", "/livez", "/liveness",
    "/ping", "/pong",
    "/info", "/version", "/about",
    "/api/status", "/api/health", "/api/info",
    "/api/version", "/api/ping",
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.development", "/.env.backup",
    "/config", "/configuration",
    "/config.json", "/config.yaml", "/config.yml",
    "/config.xml", "/config.php", "/config.ini",
    "/app.config", "/web.config",
]

# -- API keys, secrets, sensitive data --
_SENSITIVE = [
    "/api/keys", "/api/key", "/api/apikeys", "/api/apikey",
    "/api/tokens", "/api/secrets", "/api/credentials",
    "/api/export", "/api/import",
    "/api/backup", "/api/backups",
    "/api/download", "/api/dump",
    "/api/database", "/api/db", "/api/sql",
    "/api/cache", "/api/redis",
    "/api/logs", "/api/log", "/api/audit",
    "/api/metrics", "/api/analytics",
    "/api/search", "/api/query",
    "/api/cron", "/api/scheduler",
    "/api/webhook", "/api/webhooks", "/api/hooks",
    "/api/callback", "/api/callbacks",
    "/api/notify", "/api/notifications",
    "/api/batch", "/api/bulk",
]

# -- Documentation & spec --
_DOCS = [
    "/docs", "/doc", "/documentation",
    "/api-docs", "/apidocs", "/api/docs",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui.html", "/swagger-ui/index.html",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/swagger.json", "/api/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/openapi.json", "/api/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/redoc/",
    "/rapidoc", "/rapidoc/",
    "/api/schema", "/api/spec",
    "/graphql/schema",
    "/wsdl", "/api.wsdl",
    "/wadl",
]

# -- GraphQL --
_GRAPHQL = [
    "/graphql", "/graphiql",
    "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/graphiql",
    "/graphql/console", "/graphql/playground",
    "/altair",
    "/explorer",
    "/graphql/explorer",
    "/gql",
]

# -- Framework-specific: Spring Boot Actuator --
_ACTUATOR = [
    "/actuator", "/actuator/",
    "/actuator/health", "/actuator/health/liveness",
    "/actuator/health/readiness",
    "/actuator/info", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/configprops", "/actuator/conditions",
    "/actuator/loggers", "/actuator/logfile",
    "/actuator/threaddump", "/actuator/heapdump",
    "/actuator/metrics", "/actuator/prometheus",
    "/actuator/scheduledtasks", "/actuator/httptrace",
    "/actuator/trace", "/actuator/auditevents",
    "/actuator/caches", "/actuator/flyway",
    "/actuator/liquibase", "/actuator/sessions",
    "/actuator/shutdown",
    "/manage/health", "/manage/info", "/manage/env",
]

# -- Framework-specific: Django --
_DJANGO = [
    "/__debug__/", "/__debug__/sql/",
    "/django-admin/", "/django-admin",
    "/admin/doc/", "/admin/jsi18n/",
    "/__reload__/",
    "/silk/", "/silk/requests/",
    "/api-auth/", "/api-auth/login/",
]

# -- Framework-specific: Rails --
_RAILS = [
    "/rails/info", "/rails/info/properties",
    "/rails/info/routes",
    "/rails/mailers",
    "/rails/conductor/",
    "/sidekiq", "/sidekiq/",
    "/resque", "/resque/",
    "/letter_opener", "/letter_opener/",
]

# -- Framework-specific: PHP --
_PHP = [
    "/phpinfo.php", "/info.php", "/test.php",
    "/phpMyAdmin", "/phpMyAdmin/", "/phpmyadmin",
    "/pma", "/pma/",
    "/adminer", "/adminer.php",
    "/wp-json", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/wp-admin", "/wp-login.php",
    "/xmlrpc.php",
    "/wp-cron.php", "/wp-config.php.bak",
    "/server-status", "/server-info",
    "/user/login", "/node/1",
]

# -- Framework-specific: .NET --
_DOTNET = [
    "/elmah.axd", "/trace.axd",
    "/web.config", "/applicationhost.config",
    "/_blazor", "/_framework/",
    "/Telerik.Web.UI.WebResource.axd",
    "/api/values",
]

# -- Framework-specific: Node.js/Express --
_NODE = [
    "/api/debug/request",
    "/api/__coverage__",
    "/__coverage__",
    "/socket.io/", "/socket.io/socket.io.js",
    "/engine.io/",
    "/_next/", "/_next/data/",
    "/api/trpc",
]

# -- Elasticsearch / Solr / Search --
_SEARCH_ENGINES = [
    "/_cat/indices", "/_cat/health", "/_cat/nodes",
    "/_cluster/health", "/_cluster/settings", "/_cluster/stats",
    "/_nodes", "/_nodes/stats",
    "/_mapping", "/_aliases", "/_settings",
    "/_search", "/_all/_search",
    "/_template", "/_ingest/pipeline",
    "/solr/", "/solr/admin", "/solr/admin/cores",
    "/solr/admin/info/system",
]

# -- DevOps / CI / CD --
_DEVOPS = [
    "/jenkins", "/jenkins/", "/jenkins/login",
    "/travis", "/ci", "/cd",
    "/gitlab", "/-/health", "/-/readiness",
    "/api/v4/projects",
    "/drone", "/drone/",
    "/concourse", "/concourse/",
    "/argo", "/argocd",
    "/harbor", "/harbor/",
    "/.github/", "/.gitlab-ci.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
]

# -- Source code / VCS exposure --
_VCS = [
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.git/logs/HEAD", "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.gitignore", "/.gitattributes",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/", "/.hg/hgrc",
    "/.bzr/", "/.bzr/README",
    "/CVS/Root", "/CVS/Entries",
    "/.DS_Store",
]

# -- Backup & dump files --
_BACKUPS = [
    "/backup", "/backup/", "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/backup.sql.gz", "/backup.bak",
    "/db.sql", "/dump.sql", "/database.sql",
    "/data.json", "/data.xml", "/data.csv",
    "/export.json", "/export.csv", "/export.xml",
    "/site.zip", "/www.zip", "/archive.zip",
    "/db_backup.sql", "/mysql.sql",
    "/error.log", "/errors.log", "/debug.log", "/access.log",
    "/app.log", "/application.log",
]

# -- Miscellaneous --
_MISC = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.htaccess", "/.htpasswd",
    "/favicon.ico",
    "/humans.txt",
    "/security.txt",
    "/manifest.json", "/browserconfig.xml",
    "/package.json", "/composer.json", "/Gemfile",
    "/requirements.txt", "/Pipfile", "/yarn.lock",
    "/package-lock.json",
    "/Makefile", "/Dockerfile", "/docker-compose.yml",
    "/Procfile",
    "/WEB-INF/web.xml", "/WEB-INF/classes/",
    "/META-INF/MANIFEST.MF",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/server-status", "/server-info",
    "/kibana", "/kibana/",
    "/grafana", "/grafana/",
    "/prometheus", "/prometheus/",
    "/jaeger", "/zipkin",
    "/manager/html", "/jmx-console",
    "/haproxy?stats",
    "/nginx_status",
]

# Path substrings that indicate critical admin/database/debug surfaces (solanafunded-style).
# When these paths allow dangerous HTTP methods without auth, we emit a first-class high-impact finding.
CRITICAL_ADMIN_DEBUG_PATH_SUBSTRINGS = (
    "/phpMyAdmin",
    "/phpmyadmin",
    "/admin/",
    "/__debug__",
)

# -- Versioned API resource combos --
_VERSIONED = [
    f"/api/v{v}/{r}"
    for v in ("1", "2", "3")
    for r in (
        "users", "admin", "auth", "token", "config", "settings",
        "accounts", "orders", "products", "customers", "profiles",
        "roles", "permissions", "search", "export", "import",
        "upload", "download", "files", "logs", "metrics",
        "webhooks", "notifications", "payments", "health", "status",
    )
]


def _build_wordlists() -> dict[str, list[str]]:
    small = list(dict.fromkeys(
        _API_CORE + _AUTH[:15] + _ADMIN[:10] + _DEBUG[:15]
        + _DOCS[:10] + _GRAPHQL[:4] + _ACTUATOR[:5] + _MISC[:5]
    ))
    medium = list(dict.fromkeys(
        _API_CORE + _API_RESOURCES + _AUTH + _ADMIN
        + _DEBUG + _DOCS + _GRAPHQL + _ACTUATOR[:12]
        + _PHP[:6] + _VCS[:6] + _BACKUPS[:6] + _MISC[:15]
    ))
    large = list(dict.fromkeys(
        _API_CORE + _API_RESOURCES + _REST_COLLECTIONS
        + _AUTH + _ADMIN + _DEBUG + _SENSITIVE
        + _DOCS + _GRAPHQL
        + _ACTUATOR + _DJANGO + _RAILS + _PHP + _DOTNET + _NODE
        + _SEARCH_ENGINES + _DEVOPS + _VCS + _BACKUPS + _MISC
        + _VERSIONED
    ))
    return {"small": small, "medium": medium, "large": large}


WORDLISTS = _build_wordlists()

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

ENDPOINT_TIME_BUDGET = 40


def _urls_from_client_surface(client_surface_json: str | None, base_url: str) -> list[str]:
    """Resolve client_surface.extracted_endpoints to same-origin absolute URLs."""
    if not client_surface_json or not str(client_surface_json).strip():
        return []
    try:
        data = json.loads(client_surface_json)
    except (json.JSONDecodeError, TypeError):
        return []
    eps = data.get("extracted_endpoints")
    if not isinstance(eps, list):
        return []
    parsed_base = urlparse(base_url)
    scheme = parsed_base.scheme or "https"
    host = parsed_base.netloc
    if not host:
        return []
    root = f"{scheme}://{host}"
    out: list[str] = []
    for e in eps[:80]:
        if not isinstance(e, str):
            continue
        e = e.strip()
        if not e or e.startswith("#"):
            continue
        if e.startswith("http://") or e.startswith("https://"):
            u = e
        elif e.startswith("//"):
            u = f"{scheme}:{e}"
        elif e.startswith("/"):
            u = urljoin(root, e)
        else:
            u = urljoin(base_url.rstrip("/") + "/", e)
        if urlparse(u).netloc == host:
            out.append(u)
    return list(dict.fromkeys(out))[:40]


def discover_endpoints(
    base_url: str,
    wordlist: str = "medium",
    extra_seed_urls: list[str] | None = None,
) -> list[Endpoint]:
    paths = randomize_order(WORDLISTS.get(wordlist, WORDLISTS["medium"]))
    found: list[Endpoint] = []
    seen: set[str] = set()
    _t0 = time.time()

    def _probe(url: str) -> None:
        if url in seen or (time.time() - _t0) > ENDPOINT_TIME_BUDGET:
            return
        seen.add(url)
        try:
            resp = _S().get(url, timeout=6, allow_redirects=False)
            if resp.status_code not in (404, 410, 502, 503):
                found.append(Endpoint(
                    url=url,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("Content-Type", ""),
                    auth_required=resp.status_code in (401, 403),
                ))
        except requests.RequestException:
            pass

    for u in list(dict.fromkeys(extra_seed_urls or [])):
        if (time.time() - _t0) > ENDPOINT_TIME_BUDGET:
            break
        _probe(u)

    for path in paths:
        if (time.time() - _t0) > ENDPOINT_TIME_BUDGET:
            break
        _probe(urljoin(base_url, path))

    return found


# ---------------------------------------------------------------------------
# HTTP method testing
# ---------------------------------------------------------------------------

def _is_critical_admin_debug_path(url: str) -> bool:
    """True if URL path is a critical admin/database/debug surface (solanafunded-style)."""
    path = urlparse(url).path
    path_lower = path.lower()
    return (
        "phpmyadmin" in path_lower
        or path_lower.rstrip("/").endswith("/admin")
        or "/admin/" in path_lower
        or "__debug__" in path_lower
    )


def test_methods(endpoints: list[Endpoint]) -> tuple[list[Endpoint], list[Finding]]:
    findings: list[Finding] = []

    for ep in endpoints:
        allowed: list[str] = []
        for method in HTTP_METHODS:
            try:
                resp = _S().request(method, ep.url, timeout=8, allow_redirects=False)
                if resp.status_code not in (404, 405, 501):
                    allowed.append(method)
            except requests.RequestException:
                continue
        ep.methods = allowed

        dangerous = {"PUT", "DELETE", "PATCH"}
        exposed = dangerous.intersection(set(allowed))
        if exposed and not ep.auth_required:
            is_critical = _is_critical_admin_debug_path(ep.url)
            if is_critical:
                findings.append(Finding(
                    title=f"Exposed admin or database interface with dangerous HTTP methods: {ep.url}",
                    severity="High",
                    url=ep.url,
                    category="OWASP-A01 Broken Access Control",
                    evidence=f"Critical path (phpMyAdmin/admin/__debug__) allows unauthenticated modification. Allowed methods: {', '.join(allowed)}. Dangerous without auth: {', '.join(exposed)}.",
                    impact="Database or admin panel is reachable and accepts PUT/PATCH/DELETE without authentication. Data loss or takeover risk.",
                    remediation="Remove from public internet or enforce strong auth. Restrict PUT, PATCH, DELETE to authenticated users; disable unused HTTP methods.",
                ))
            else:
                findings.append(Finding(
                    title=f"Dangerous HTTP methods enabled without auth on {ep.url}",
                    severity="High",
                    url=ep.url,
                    category="OWASP-A01 Broken Access Control",
                    evidence=f"Allowed methods: {', '.join(allowed)}\nDangerous methods without auth: {', '.join(exposed)}",
                    impact="Unauthenticated users could modify or delete resources.",
                    remediation="Restrict PUT, PATCH, DELETE to authenticated users. Disable unused HTTP methods.",
                ))

    return endpoints, findings


# ---------------------------------------------------------------------------
# CORS misconfiguration testing (enhanced)
# ---------------------------------------------------------------------------

def test_cors(endpoints: list[Endpoint]) -> list[Finding]:
    findings: list[Finding] = []

    for ep in endpoints:
        parsed = urlparse(ep.url)
        test_origins = [
            "https://attacker.com",
            "null",
            f"https://evil.{parsed.netloc}",
            f"https://{parsed.netloc}.attacker.com",
            f"https://sub.{parsed.netloc}",
        ]

        for origin in randomize_order(test_origins):
            try:
                resp = _S().options(
                    ep.url,
                    headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                    timeout=8,
                    allow_redirects=False,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*" and acac == "true":
                    findings.append(Finding(
                        title=f"Critical CORS: wildcard origin with credentials on {ep.url}",
                        severity="Critical",
                        url=ep.url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=(
                            f"Access-Control-Allow-Origin: *\n"
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        impact="Any website can make credentialed cross-origin requests, enabling full account takeover.",
                        remediation="Never combine wildcard origin with credentials. Whitelist specific trusted origins.",
                    ))
                    break
                elif acao == origin and origin not in ("null", f"https://sub.{parsed.netloc}"):
                    sev = "Critical" if acac == "true" else "High"
                    findings.append(Finding(
                        title=f"CORS reflects arbitrary origin on {ep.url}",
                        severity=sev,
                        url=ep.url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=(
                            f"Origin sent: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        impact="Attacker-controlled origins can read API responses"
                               + (", including authenticated data." if acac == "true" else "."),
                        remediation="Validate Origin against a strict whitelist. Do not reflect arbitrary origins.",
                    ))
                    break
                elif acao == "null":
                    findings.append(Finding(
                        title=f"CORS allows null origin on {ep.url}",
                        severity="High",
                        url=ep.url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=f"Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: {acac}",
                        impact="Sandboxed iframes and data: URIs send Origin: null, enabling cross-origin reads.",
                        remediation="Do not allow 'null' as a valid origin in CORS configuration.",
                    ))
                    break
                elif acao == "*":
                    findings.append(Finding(
                        title=f"Wildcard CORS origin on {ep.url}",
                        severity="Medium",
                        url=ep.url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=f"Access-Control-Allow-Origin: *",
                        impact="Any website can read responses from this API (no credentials).",
                        remediation="Restrict CORS to specific trusted origins.",
                    ))
                    break
            except requests.RequestException:
                continue

        # Preflight method check
        try:
            resp = _S().options(
                ep.url,
                headers={
                    "Origin": "https://attacker.com",
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "Authorization",
                },
                timeout=8,
                allow_redirects=False,
            )
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            if "DELETE" in acam or "PUT" in acam:
                acah = resp.headers.get("Access-Control-Allow-Headers", "")
                if "authorization" in acah.lower() or "*" in acah:
                    findings.append(Finding(
                        title=f"CORS preflight allows dangerous methods with auth on {ep.url}",
                        severity="High",
                        url=ep.url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=(
                            f"Access-Control-Allow-Methods: {acam}\n"
                            f"Access-Control-Allow-Headers: {acah}"
                        ),
                        impact="Cross-origin sites can make authenticated DELETE/PUT requests.",
                        remediation="Restrict preflight allowed methods and headers to what is strictly necessary.",
                    ))
        except requests.RequestException:
            pass

    return findings


# ---------------------------------------------------------------------------
# Host header injection (reflection / poisoning)
# ---------------------------------------------------------------------------

HOST_INJECTION_MARKER = "evil.host.header.injection"

def test_host_header_injection(endpoints: list[Endpoint]) -> list[Finding]:
    """Send Host / X-Forwarded-Host with a distinct value; if reflected in response, report Host header injection."""
    findings: list[Finding] = []
    for ep in endpoints[:10]:
        try:
            for header_name, header_val in [
                ("Host", HOST_INJECTION_MARKER),
                ("X-Forwarded-Host", HOST_INJECTION_MARKER),
                ("X-Host", HOST_INJECTION_MARKER),
            ]:
                resp = _S().get(
                    ep.url,
                    headers={header_name: header_val},
                    timeout=8,
                    allow_redirects=False,
                )
                text = (resp.text or "").lower()
                location = (resp.headers.get("Location") or "").lower()
                link = (resp.headers.get("Link") or "").lower()
                if HOST_INJECTION_MARKER.lower() in text or HOST_INJECTION_MARKER.lower() in location or HOST_INJECTION_MARKER.lower() in link:
                    findings.append(Finding(
                        title=f"Host header injection — {header_name} reflected in response",
                        severity="Medium",
                        url=ep.url,
                        category="OWASP-A01 Broken Access Control (Host injection)",
                        evidence=f"Sent {header_name}: {header_val}; value appears in response body, Location, or Link.",
                        impact="Attacker can poison cache or trigger redirects to a controlled host (phishing, SSRF).",
                        remediation="Do not use Host / X-Forwarded-Host for redirects or links. Use a configured canonical host.",
                    ))
                    return findings
        except requests.RequestException:
            continue
    return findings


# ---------------------------------------------------------------------------
# Authentication bypass checks (enhanced)
# ---------------------------------------------------------------------------

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Proto": "https"},
    {"X-Original-Host": "localhost"},
    {"X-Backend-Host": "localhost"},
    {"X-Forwarded-By": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
]


def _path_bypass_variants(path: str) -> list[str]:
    """Generate path-based bypass variants for a URL path."""
    if not path or path == "/":
        return []
    clean = path.rstrip("/")
    parts = clean.rsplit("/", 1)
    last_seg = parts[-1] if len(parts) > 1 else clean.lstrip("/")

    variants = [
        clean + "/",
        clean + "/.",
        clean + "/./",
        "/" + last_seg.capitalize(),
        "/" + last_seg.upper(),
        "//" + last_seg,
        "/./" + last_seg,
        clean + ";/",
        clean + "..;/",
        clean + "%00",
        clean + "%20",
        clean + "%09",
        "/%2f" + last_seg,
        clean + "?",
        clean + "??",
        clean + "#",
        clean + "/..",
    ]
    return variants


def _body_is_different(body_a: str, body_b: str, threshold: float = 0.15) -> bool:
    """Return True only when the two bodies differ substantially (>threshold ratio)."""
    if not body_a and not body_b:
        return False
    len_a, len_b = len(body_a), len(body_b)
    if len_a == 0 or len_b == 0:
        return bool(len_a + len_b > 100)
    ratio = abs(len_a - len_b) / max(len_a, len_b)
    if ratio > threshold:
        return True
    import hashlib
    return hashlib.md5(body_a.encode(errors="replace")).digest() != hashlib.md5(body_b.encode(errors="replace")).digest()


def test_auth_bypass(endpoints: list[Endpoint]) -> list[Finding]:
    findings: list[Finding] = []
    protected = [ep for ep in endpoints if ep.auth_required]

    try:
        base_parsed = urlparse(protected[0].url if protected else "")
        home_url = f"{base_parsed.scheme}://{base_parsed.netloc}/"
        home_resp = _S().get(home_url, timeout=8, allow_redirects=True)
        home_body = home_resp.text
    except Exception:
        home_body = ""

    for ep in protected:
        # Header-based bypass
        for bypass_headers in randomize_order(AUTH_BYPASS_HEADERS):
            try:
                resp = _S().get(ep.url, headers=bypass_headers, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and _body_is_different(resp.text, home_body):
                    header_name = list(bypass_headers.keys())[0]
                    findings.append(Finding(
                        title=f"Authentication bypass via {header_name}",
                        severity="Critical",
                        url=ep.url,
                        category="OWASP-A01 Broken Access Control",
                        evidence=(
                            f"Bypass header: {header_name}: {bypass_headers[header_name]}\n"
                            f"Original status: {ep.status_code}\n"
                            f"Bypassed status: {resp.status_code}\n"
                            f"Response body differs from home page ({len(resp.text)} vs {len(home_body)} bytes)"
                        ),
                        impact="Attackers can bypass authentication and access protected resources.",
                        remediation=f"Do not trust {header_name} for access control decisions. Implement proper authentication.",
                    ))
                    break
            except requests.RequestException:
                continue

        # Path-based bypass
        parsed = urlparse(ep.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for variant_path in _path_bypass_variants(parsed.path):
            variant_url = base + variant_path
            try:
                resp = _S().get(variant_url, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and _body_is_different(resp.text, home_body):
                    findings.append(Finding(
                        title=f"Authentication bypass via path manipulation",
                        severity="Critical",
                        url=variant_url,
                        category="OWASP-A01 Broken Access Control",
                        evidence=(
                            f"Original: {ep.url} → {ep.status_code}\n"
                            f"Bypass: {variant_url} → {resp.status_code}\n"
                            f"Response body differs from home page"
                        ),
                        impact="Path normalization differences allow bypassing access controls.",
                        remediation="Normalize URL paths before applying access control. Use framework-level route matching.",
                    ))
                    break
            except requests.RequestException:
                continue

        # HTTP verb tampering
        if ep.status_code in (401, 403):
            for method in randomize_order(["POST", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS", "HEAD"]):
                try:
                    resp = _S().request(method, ep.url, timeout=8, allow_redirects=False)
                    if resp.status_code == 200 and _body_is_different(resp.text, home_body):
                        findings.append(Finding(
                            title=f"Authentication bypass via HTTP verb tampering ({method})",
                            severity="High",
                            url=ep.url,
                            category="OWASP-A01 Broken Access Control",
                            evidence=(
                                f"GET {ep.url} → {ep.status_code}\n"
                                f"{method} {ep.url} → {resp.status_code}\n"
                                f"Response body differs from home page"
                            ),
                            impact="Access controls only apply to specific HTTP methods, allowing bypass with alternate verbs.",
                            remediation="Apply authentication/authorization checks regardless of HTTP method.",
                        ))
                        break
                except requests.RequestException:
                    continue

        # IDOR pattern check
        if "/api/" in ep.url and not ep.url.endswith("/"):
            for test_id in ["1", "2", "0", "999"]:
                test_url = ep.url.rstrip("/") + f"/{test_id}"
                try:
                    resp = _S().get(test_url, timeout=8, allow_redirects=False)
                    if resp.status_code == 200 and _body_is_different(resp.text, home_body):
                        try:
                            data = resp.json()
                            if isinstance(data, dict) and len(data) > 0:
                                findings.append(Finding(
                                    title=f"Potential IDOR — resource accessible without auth",
                                    severity="High",
                                    url=test_url,
                                    category="OWASP-A01 Broken Access Control (IDOR)",
                                    evidence=f"GET {test_url} returned 200 with JSON data ({len(data)} keys), body differs from home page",
                                    impact="Attackers may enumerate and access other users' resources by changing IDs.",
                                    remediation="Enforce authorization checks on every resource access. Use UUIDs instead of sequential IDs.",
                                ))
                                break
                        except ValueError:
                            pass
                except requests.RequestException:
                    continue

    return findings


# ---------------------------------------------------------------------------
# Sensitive information disclosure
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: dict[str, str] = {
    "/.env": "Environment variables may contain API keys and database credentials",
    "/.env.local": "Local env file may contain development secrets",
    "/.env.production": "Production env file may contain production secrets",
    "/.git/config": "Git configuration may reveal repository and infrastructure details",
    "/.git/HEAD": "Git HEAD reference confirms exposed repository",
    "/.git/index": "Git index exposes full file listing of the repository",
    "/.svn/entries": "SVN entries file exposes repository structure",
    "/swagger.json": "API specification may reveal internal endpoints and data models",
    "/swagger.yaml": "API spec in YAML may reveal internal endpoints and data models",
    "/openapi.json": "OpenAPI spec may reveal internal endpoints and data models",
    "/openapi.yaml": "OpenAPI spec may reveal internal endpoints and data models",
    "/server-status": "Apache server-status exposes request data and server internals",
    "/server-info": "Apache server-info exposes full module and configuration details",
    "/phpinfo.php": "PHP info page reveals full server configuration",
    "/info.php": "PHP info page reveals full server configuration",
    "/actuator/env": "Spring Actuator env endpoint may reveal secrets",
    "/actuator/heapdump": "Spring Actuator heapdump may contain in-memory secrets",
    "/actuator/configprops": "Spring Actuator configprops may reveal configuration secrets",
    "/actuator/trace": "Spring Actuator trace reveals recent HTTP request details",
    "/wp-json/wp/v2/users": "WordPress REST API exposes user enumeration",
    "/.DS_Store": "macOS metadata file may reveal directory structure",
    "/WEB-INF/web.xml": "Java web descriptor reveals application structure and servlets",
    "/config.json": "Application config may contain credentials",
    "/config.yaml": "Application config may contain credentials",
    "/package.json": "Node.js manifest reveals dependencies and potential vulnerabilities",
    "/composer.json": "PHP Composer manifest reveals dependencies",
    "/Dockerfile": "Dockerfile may reveal build secrets and internal architecture",
    "/docker-compose.yml": "Docker Compose may reveal service topology and credentials",
    "/.htpasswd": "Apache password file may contain crackable hashes",
    "/backup.sql": "Database backup may contain all application data",
    "/dump.sql": "Database dump may contain all application data",
    "/debug/vars": "Go debug variables may expose internal state and secrets",
    "/debug/pprof": "Go profiling endpoint exposes runtime internals",
    "/elmah.axd": ".NET error log may contain stack traces and sensitive data",
    "/trace.axd": ".NET request trace reveals detailed request/response data",
    "/_cat/indices": "Elasticsearch indices listing exposes data structure",
    "/_cluster/health": "Elasticsearch cluster health reveals infrastructure details",
    "/error.log": "Error log may contain stack traces with sensitive data",
    "/access.log": "Access log may reveal request patterns and user data",
    "/web.config": ".NET config may contain connection strings and secrets",
}


_API_SENS_CONTENT_MARKERS: dict[str, re.Pattern] = {
    "/.env": re.compile(r"^\w+=.+", re.MULTILINE),
    "/.env.local": re.compile(r"^\w+=.+", re.MULTILINE),
    "/.env.production": re.compile(r"^\w+=.+", re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|\[remote", re.IGNORECASE),
    "/.git/HEAD": re.compile(r"ref:\s+refs/"),
    "/.git/index": re.compile(r"DIRC"),
    "/.svn/entries": re.compile(r"^\d+$", re.MULTILINE),
    "/swagger.json": re.compile(r'"swagger"\s*:\s*"2|"openapi"\s*:', re.IGNORECASE),
    "/swagger.yaml": re.compile(r"swagger:\s|openapi:", re.IGNORECASE),
    "/openapi.json": re.compile(r'"openapi"\s*:', re.IGNORECASE),
    "/openapi.yaml": re.compile(r"openapi:", re.IGNORECASE),
    "/server-status": re.compile(r"Apache Server Status|Scoreboard", re.IGNORECASE),
    "/server-info": re.compile(r"Apache Server Information|Module Name", re.IGNORECASE),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE),
    "/info.php": re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE),
    "/actuator/env": re.compile(r'"activeProfiles"|"propertySources"', re.IGNORECASE),
    "/actuator/heapdump": re.compile(r"^\x1f\x8b|^JAVA PROFILE"),
    "/graphql": re.compile(r'"__schema"|"queryType"', re.IGNORECASE),
    "/debug/vars": re.compile(r'"cmdline"|"memstats"', re.IGNORECASE),
    "/debug/pprof": re.compile(r"Types of profiles available|heap|goroutine"),
    "/elmah.axd": re.compile(r"Error Log|ELMAH", re.IGNORECASE),
    "/_cat/indices": re.compile(r"(green|yellow|red)\s+open\s+\w+"),
    "/_cluster/health": re.compile(r'"cluster_name"|"status"'),
    "/web.config": re.compile(r"<configuration|connectionString", re.IGNORECASE),
}


def check_info_disclosure(endpoints: list[Endpoint]) -> list[Finding]:
    findings: list[Finding] = []

    for ep in endpoints:
        for sens_path, description in SENSITIVE_PATHS.items():
            if ep.url.endswith(sens_path) and ep.status_code == 200:
                marker = _API_SENS_CONTENT_MARKERS.get(sens_path)
                if marker:
                    try:
                        resp = _S().get(ep.url, timeout=8, allow_redirects=False)
                        if not marker.search(resp.text[:4000]):
                            continue
                    except requests.RequestException:
                        continue
                findings.append(Finding(
                    title=f"Sensitive resource exposed: {sens_path}",
                    severity="High",
                    url=ep.url,
                    category="OWASP-A05 Security Misconfiguration",
                    evidence=f"GET {ep.url} returned HTTP {ep.status_code}\nContent-Type: {ep.content_type}\nContent verified with format-specific marker",
                    impact=description,
                    remediation=f"Block access to {sens_path} in your web server configuration.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Contract vs reality (API schema drift)
# ---------------------------------------------------------------------------

OPENAPI_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/openapi/v1.json", "/swagger/v1/swagger.json",
]


def _fetch_openapi_spec(base_url: str, timeout: int = 8) -> Optional[dict]:
    """Fetch OpenAPI/Swagger spec from common paths. Returns parsed JSON or None."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    for path in OPENAPI_SPEC_PATHS:
        try:
            url = urljoin(base, path)
            r = _S().get(url, timeout=timeout, allow_redirects=False)
            if r.status_code != 200:
                continue
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" in ct or "javascript" in ct or r.text.strip().startswith("{"):
                return r.json()
        except (requests.RequestException, ValueError):
            continue
    return None


def _openapi_parameter_names_for_fuzz(base_url: str) -> list[str]:
    """Collect query/header/path parameter names from OpenAPI for guided fuzzing."""
    spec = _fetch_openapi_spec(base_url)
    if not spec or not isinstance(spec, dict):
        return []
    names: list[str] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return []
    for _path_key, path_item in list(paths.items())[:35]:
        if not isinstance(path_item, dict):
            continue
        for param in path_item.get("parameters") or []:
            if isinstance(param, dict) and param.get("name"):
                names.append(str(param["name"]))
        for m in ("get", "post", "put", "patch", "delete", "head"):
            op = path_item.get(m)
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters") or []:
                if isinstance(param, dict) and param.get("name"):
                    names.append(str(param["name"]))
    return list(dict.fromkeys(names))[:50]


def _parse_openapi_paths(spec: dict, base_url: str) -> list[tuple[str, str, list[str], bool, list[str]]]:
    """
    Parse spec into (full_url, path, declared_methods, requires_auth, read_only_fields).
    Supports OpenAPI 3.x and Swagger 2.
    """
    paths = spec.get("paths") or {}
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    out: list[tuple[str, str, list[str], bool, list[str]]] = []
    method_keys = ("get", "post", "put", "patch", "delete", "head", "options")

    for path_str, path_item in list(paths.items())[:25]:
        if not isinstance(path_item, dict):
            continue
        declared = [m.upper() for m in method_keys if path_item.get(m)]
        if not declared:
            continue
        # Resolve path (OpenAPI 3 servers may override basePath; Swagger 2 has basePath)
        base_path = (spec.get("basePath") or "").rstrip("/")
        full_path = (base_path + "/" + path_str.lstrip("/")).replace("//", "/")
        full_url = base + full_path

        # Security: if any operation has non-empty security, treat as requires_auth for that path
        requires_auth = False
        for m in method_keys:
            op = path_item.get(m)
            if isinstance(op, dict) and op.get("security"):
                requires_auth = True
                break
        if not requires_auth and path_item.get("security"):
            requires_auth = True

        # ReadOnly fields from requestBody (OpenAPI 3) or parameters (Swagger 2)
        read_only_fields: list[str] = []
        for m in ("put", "patch", "post"):
            op = path_item.get(m)
            if not isinstance(op, dict):
                continue
            # OpenAPI 3: requestBody.content.schema.properties with readOnly: true
            req = op.get("requestBody") or {}
            content = (req.get("content") or {}).get("application/json") or {}
            schema = content.get("schema") or {}
            props = schema.get("properties") or {}
            for name, prop in props.items():
                if isinstance(prop, dict) and prop.get("readOnly"):
                    read_only_fields.append(name)
            # Also check refs if simple
            ref = schema.get("$ref")
            if ref and "#/components/schemas/" in str(ref):
                comp_name = ref.split("/")[-1]
                comp = (spec.get("components") or {}).get("schemas") or {}
                comp_schema = comp.get(comp_name) or {}
                for name, prop in (comp_schema.get("properties") or {}).items():
                    if isinstance(prop, dict) and prop.get("readOnly"):
                        read_only_fields.append(name)

        out.append((full_url, path_str, declared, requires_auth, read_only_fields[:5]))

    return out


def test_contract_drift(
    base_url: str,
    run_start: float,
    _over_budget,
) -> list[Finding]:
    """
    Compare OpenAPI/Swagger contract to actual server behavior.
    Reports: (1) methods not in schema accepted by server, (2) 200 when contract implies 401,
    (3) read-only field accepted in request body.
    """
    findings: list[Finding] = []
    spec = _fetch_openapi_spec(base_url)
    if not spec or _over_budget():
        return findings

    paths_parsed = _parse_openapi_paths(spec, base_url)
    for full_url, path_str, declared_methods, requires_auth, read_only_fields in paths_parsed[:10]:
        if _over_budget():
            break

        # (1) Try methods NOT in schema — if server accepts (2xx), contract drift
        all_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        for method in all_methods:
            if method in declared_methods:
                continue
            try:
                r = _S().request(method, full_url, timeout=6, allow_redirects=False)
                if r.status_code in (200, 201, 204):
                    findings.append(Finding(
                        title="Contract drift: server accepts method not in schema [CONFIRMED]",
                        severity="Medium",
                        url=full_url,
                        category="API Contract vs Reality",
                        evidence=f"Schema declares only {', '.join(declared_methods)} for {path_str}; server returned {r.status_code} for {method}.",
                        impact="Shadow API or outdated docs. Undocumented methods can bypass access controls or expose unintended behavior.",
                        remediation="Align server behavior with API contract, or document all accepted methods. Reject methods not in contract.",
                    ))
                    break
            except requests.RequestException:
                continue

        # (2) If schema implies auth required, GET without auth — 200 = drift
        if requires_auth:
            try:
                r = _S().get(full_url, timeout=6, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    try:
                        r.json()
                        findings.append(Finding(
                            title="Contract drift: unauthenticated access returns 200 [CONFIRMED]",
                            severity="High",
                            url=full_url,
                            category="API Contract vs Reality",
                            evidence=f"Schema indicates authentication required for {path_str}; GET without auth returned 200 with body.",
                            impact="Access control bypass: data or actions that should be protected are accessible without authentication.",
                            remediation="Enforce authentication and return 401 for unauthenticated requests on protected paths.",
                        ))
                    except ValueError:
                        pass
            except requests.RequestException:
                pass

        # (3) If schema marks field readOnly, send it in PATCH/PUT — 2xx = drift
        if read_only_fields and ("PATCH" in declared_methods or "PUT" in declared_methods):
            method = "PATCH" if "PATCH" in declared_methods else "PUT"
            payload = {f: "contract_drift_test_value" for f in read_only_fields[:3]}
            try:
                r = _S().request(method, full_url, json=payload, timeout=6, allow_redirects=False)
                if r.status_code in (200, 201, 204):
                    findings.append(Finding(
                        title="Contract drift: declared read-only field accepted in request [CONFIRMED]",
                        severity="High",
                        url=full_url,
                        category="API Contract vs Reality",
                        evidence=f"Schema marks {', '.join(read_only_fields[:3])} as readOnly; {method} with these fields returned {r.status_code}. Server may have applied them.",
                        impact="Privilege escalation or data tampering if server mutates read-only fields (e.g. role, id, owner).",
                        remediation="Reject read-only fields in request body or ignore them. Enforce server-side that only writable fields are updated.",
                    ))
            except requests.RequestException:
                pass

    return findings


# ---------------------------------------------------------------------------
# GraphQL introspection testing
# ---------------------------------------------------------------------------

_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}"""

_SENSITIVE_TYPE_NAMES = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "accesstoken", "access_token", "refreshtoken", "refresh_token",
    "creditcard", "credit_card", "ccnumber", "cvv", "ssn",
    "social_security", "bankaccount", "bank_account",
    "privatekey", "private_key", "secret_key", "secretkey",
    "otp", "pin", "mfa_secret",
}

_SENSITIVE_FIELD_PATTERNS = {
    "password", "hash", "salt", "secret", "token", "key",
    "credit_card", "creditcard", "card_number", "cvv", "cvc",
    "ssn", "social_security", "bank", "routing_number",
    "private", "internal", "admin", "superuser", "role",
    "permission", "balance", "salary",
}

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/graphiql", "/gql",
    "/graphql/console", "/graphql/playground",
]


def test_graphql(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    detected_endpoints: list[str] = []

    # Phase 1: detect GraphQL endpoints
    for path in randomize_order(GRAPHQL_ENDPOINTS):
        url = urljoin(base_url, path)
        try:
            resp = _S().post(
                url,
                json={"query": "{__typename}"},
                timeout=8,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if "data" in body or "errors" in body:
                        detected_endpoints.append(url)
                except ValueError:
                    pass
        except requests.RequestException:
            continue

    for gql_url in detected_endpoints:
        # Phase 2: introspection query
        try:
            resp = _S().post(
                gql_url,
                json={"query": _INTROSPECTION_QUERY},
                timeout=15,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                body = resp.json()
                schema = body.get("data", {}).get("__schema")
                if schema:
                    types = schema.get("types", [])
                    type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
                    query_type = (schema.get("queryType") or {}).get("name", "")
                    mutation_type = (schema.get("mutationType") or {}).get("name", "")
                    subscription_type = (schema.get("subscriptionType") or {}).get("name", "")

                    findings.append(Finding(
                        title=f"GraphQL introspection enabled on {gql_url}",
                        severity="High",
                        url=gql_url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=(
                            f"Introspection query returned full schema.\n"
                            f"Types: {len(type_names)} | Queries: {query_type} | "
                            f"Mutations: {mutation_type} | Subscriptions: {subscription_type}\n"
                            f"Sample types: {', '.join(type_names[:20])}"
                        ),
                        impact="Full API schema exposed. Attackers can map every query, mutation, and data type.",
                        remediation="Disable introspection in production. Use allowlisting for permitted queries.",
                    ))

                    # Check for sensitive types/fields
                    sensitive_found: list[str] = []
                    for t in types:
                        tname = (t.get("name") or "").lower()
                        if tname in _SENSITIVE_TYPE_NAMES:
                            sensitive_found.append(f"Type: {t.get('name')}")
                        for f_obj in (t.get("fields") or []):
                            fname = (f_obj.get("name") or "").lower()
                            if fname in _SENSITIVE_FIELD_PATTERNS:
                                sensitive_found.append(f"{t.get('name')}.{f_obj.get('name')}")

                    if sensitive_found:
                        findings.append(Finding(
                            title=f"Sensitive fields exposed in GraphQL schema on {gql_url}",
                            severity="High",
                            url=gql_url,
                            category="OWASP-A01 Broken Access Control",
                            evidence=f"Sensitive schema elements:\n" + "\n".join(sensitive_found[:30]),
                            impact="Schema reveals sensitive data types/fields that may be queryable without authorization.",
                            remediation="Remove sensitive fields from public schema. Implement field-level authorization.",
                        ))

                elif "errors" in body:
                    error_msgs = [e.get("message", "") for e in body.get("errors", [])]
                    if not any("introspection" in m.lower() for m in error_msgs):
                        findings.append(Finding(
                            title=f"GraphQL endpoint found with partial introspection on {gql_url}",
                            severity="Medium",
                            url=gql_url,
                            category="OWASP-A05 Security Misconfiguration",
                            evidence=f"Introspection returned errors: {'; '.join(error_msgs[:3])}",
                            impact="GraphQL endpoint is accessible; introspection may be partially restricted.",
                            remediation="Verify introspection is fully disabled. Apply query depth and complexity limits.",
                        ))
        except requests.RequestException:
            continue

        # Phase 3: query depth limit bypass
        try:
            deep_query = '{ __typename ' + ''.join([f'a{i}: __typename ' for i in range(50)]) + '}'
            resp = _S().post(gql_url, json={"query": deep_query}, timeout=10)
            if resp.status_code == 200:
                body = resp.json()
                if "data" in body and not body.get("errors"):
                    findings.append(Finding(
                        title=f"No GraphQL query complexity/depth limit on {gql_url}",
                        severity="Medium",
                        url=gql_url,
                        category="OWASP-A05 Security Misconfiguration",
                        evidence=f"Server processed a query with 50+ fields without rejection.",
                        impact="Attackers can craft expensive queries to cause denial of service.",
                        remediation="Implement query depth limits, complexity analysis, and query cost budgeting.",
                    ))
        except requests.RequestException:
            pass

        # Phase 4: batching attack
        try:
            batch_payload = [
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"},
            ]
            resp = _S().post(gql_url, json=batch_payload, timeout=10)
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if isinstance(body, list) and len(body) >= 5:
                        findings.append(Finding(
                            title=f"GraphQL batching attack possible on {gql_url}",
                            severity="Medium",
                            url=gql_url,
                            category="OWASP-A04 Insecure Design",
                            evidence=f"Sent batch of 5 queries, received {len(body)} responses.",
                            impact="Batching enables brute-force attacks (e.g., OTP, password) in a single request, bypassing rate limits.",
                            remediation="Limit or disable query batching. Apply per-query rate limiting.",
                        ))
                except ValueError:
                    pass
        except requests.RequestException:
            pass

    return findings


# ---------------------------------------------------------------------------
# Parameter fuzzing
# ---------------------------------------------------------------------------

FUZZ_PARAM_NAMES = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "username", "user", "login", "name",
    "email", "mail",
    "password", "passwd", "pass", "pwd",
    "token", "auth_token", "authToken", "access_token", "accessToken",
    "key", "api_key", "apiKey", "apikey", "secret", "app_secret",
    "admin", "is_admin", "isAdmin", "role", "roles",
    "debug", "test", "verbose", "trace",
    "page", "limit", "offset", "per_page", "perPage", "size",
    "sort", "order", "orderBy", "order_by", "direction",
    "filter", "filters", "where", "query",
    "q", "search", "keyword", "term",
    "callback", "jsonp", "cb",
    "redirect", "redirect_uri", "redirectUri", "redirect_url", "return_to", "next", "url", "ref",
    "file", "filename", "path", "filepath", "dir", "directory",
    "cmd", "exec", "command", "run",
    "action", "do", "func", "function", "method",
    "type", "format", "output", "response_type", "content_type",
    "include", "fields", "select", "expand", "embed",
    "lang", "language", "locale", "timezone",
    "version", "v", "ver",
    "cursor", "after", "before", "start", "end",
    "status", "state", "active", "enabled", "deleted",
    "category", "tag", "group", "org", "team",
    "from", "to", "date", "start_date", "end_date",
    "count", "total", "max", "min",
]

FUZZ_VALUES: list[tuple[str, str]] = [
    ("0", "zero integer"),
    ("1", "valid integer"),
    ("-1", "negative integer"),
    ("999999", "large integer"),
    ("9999999999", "very large integer"),
    ("true", "boolean true"),
    ("false", "boolean false"),
    ("null", "null string"),
    ("undefined", "undefined string"),
    ("admin", "admin string"),
    ("root", "root string"),
    ("*", "wildcard"),
    ("../../../etc/passwd", "path traversal"),
    ("{{7*7}}", "SSTI probe"),
    ("${7*7}", "expression injection"),
    ("' OR '1'='1", "SQL injection"),
    ("<script>alert(1)</script>", "XSS probe"),
    ("", "empty string"),
]

_INFO_LEAK_KEYWORDS = [
    "stack", "trace", "exception", "error", "debug",
    "password", "secret", "token", "key", "credential",
    "database", "mysql", "postgres", "mongodb", "redis",
    "internal", "private", "root", "admin",
    "sql", "query", "select", "insert", "update",
    "file", "/etc/", "/var/", "c:\\",
]


def test_parameter_fuzzing(endpoints: list[Endpoint], base_url: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    openapi_names = _openapi_parameter_names_for_fuzz(base_url) if base_url else []
    merged_param_names = list(dict.fromkeys(openapi_names + FUZZ_PARAM_NAMES))
    accessible = [ep for ep in endpoints if ep.status_code == 200 and ep.content_type and "json" in ep.content_type.lower()]

    if not accessible:
        accessible = [ep for ep in endpoints if ep.status_code == 200][:10]

    fuzz_targets = accessible[:15]

    for ep in fuzz_targets:
        try:
            baseline_resp = _S().get(ep.url, timeout=8)
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except requests.RequestException:
            continue

        for param in randomize_order(merged_param_names[:45]):
            for value, desc in FUZZ_VALUES[:8]:
                try:
                    resp = _S().get(
                        ep.url,
                        params={param: value},
                        timeout=8,
                        allow_redirects=False,
                    )

                    resp_text_lower = resp.text.lower()
                    if resp.status_code == 500 and baseline_status != 500:
                        leaked = [kw for kw in _INFO_LEAK_KEYWORDS if kw in resp_text_lower]
                        if leaked:
                            findings.append(Finding(
                                title=f"Parameter causes server error with info leak on {ep.url}",
                                severity="High",
                                url=ep.url,
                                category="OWASP-A05 Security Misconfiguration",
                                evidence=(
                                    f"Parameter: {param}={value} ({desc})\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Leaked keywords: {', '.join(leaked[:5])}"
                                ),
                                impact="Detailed error messages reveal internal implementation details to attackers.",
                                remediation="Implement generic error pages. Never expose stack traces or internal details in responses.",
                            ))
                            break

                    if resp.status_code == 200 and baseline_status == 200:
                        response_diff = abs(len(resp.text) - baseline_len)
                        if response_diff > 500 and len(resp.text) > baseline_len:
                            if any(kw in resp_text_lower for kw in _INFO_LEAK_KEYWORDS[:8]):
                                findings.append(Finding(
                                    title=f"Parameter '{param}' causes extra data disclosure on {ep.url}",
                                    severity="Medium",
                                    url=ep.url,
                                    category="OWASP-A01 Broken Access Control",
                                    evidence=(
                                        f"Parameter: {param}={value} ({desc})\n"
                                        f"Baseline response: {baseline_len} bytes\n"
                                        f"Fuzzed response: {len(resp.text)} bytes (+{response_diff})"
                                    ),
                                    impact="Certain parameters trigger disclosure of additional data not intended for the user.",
                                    remediation="Validate and sanitize all query parameters. Apply authorization to data access.",
                                ))
                                break

                except requests.RequestException:
                    continue

    return findings


# ---------------------------------------------------------------------------
# Mass assignment testing
# ---------------------------------------------------------------------------

MASS_ASSIGN_FIELDS = {
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin"],
    "user_role": "administrator",
    "userRole": "administrator",
    "status": "active",
    "verified": True,
    "email_verified": True,
    "emailVerified": True,
    "is_verified": True,
    "active": True,
    "enabled": True,
    "deleted": False,
    "banned": False,
    "suspended": False,
    "balance": 999999,
    "credits": 999999,
    "price": 0,
    "amount": 0,
    "discount": 100,
    "permissions": ["*"],
    "scope": "admin",
    "level": 99,
    "tier": "enterprise",
    "is_staff": True,
    "isStaff": True,
    "is_superuser": True,
    "isSuperuser": True,
    "approved": True,
    "confirmed": True,
}


def test_mass_assignment(endpoints: list[Endpoint]) -> list[Finding]:
    findings: list[Finding] = []

    writable = [
        ep for ep in endpoints
        if not ep.auth_required and any(m in ep.methods for m in ("POST", "PUT", "PATCH"))
    ]

    for ep in writable[:10]:
        # Get baseline response for POST/PUT
        for method in ("POST", "PUT", "PATCH"):
            if method not in ep.methods:
                continue

            try:
                baseline_resp = _S().request(
                    method, ep.url,
                    json={"test_field": "test_value"},
                    timeout=8,
                    allow_redirects=False,
                )
                baseline_status = baseline_resp.status_code
                try:
                    baseline_body = baseline_resp.json()
                except ValueError:
                    baseline_body = {}

                extra_payload = {"test_field": "test_value"}
                extra_payload.update(MASS_ASSIGN_FIELDS)

                test_resp = _S().request(
                    method, ep.url,
                    json=extra_payload,
                    timeout=8,
                    allow_redirects=False,
                )

                if test_resp.status_code in (200, 201):
                    try:
                        test_body = test_resp.json()
                    except ValueError:
                        test_body = {}

                    if isinstance(test_body, dict) and isinstance(baseline_body, dict):
                        accepted_fields = []
                        for f_name in MASS_ASSIGN_FIELDS:
                            if f_name in test_body and f_name not in baseline_body:
                                accepted_fields.append(f_name)
                            elif f_name in test_body and test_body.get(f_name) == MASS_ASSIGN_FIELDS[f_name]:
                                accepted_fields.append(f_name)

                        if accepted_fields:
                            findings.append(Finding(
                                title=f"Mass assignment vulnerability on {ep.url}",
                                severity="Critical",
                                url=ep.url,
                                category="OWASP-A04 Insecure Design",
                                evidence=(
                                    f"Method: {method}\n"
                                    f"Accepted privileged fields: {', '.join(accepted_fields)}\n"
                                    f"Response status: {test_resp.status_code}"
                                ),
                                impact="Attackers can escalate privileges or modify protected fields by injecting extra parameters.",
                                remediation="Use explicit allowlists for accepted fields. Never bind request data directly to models.",
                            ))
                            break

                    if test_resp.status_code != baseline_status and test_resp.status_code in (200, 201):
                        findings.append(Finding(
                            title=f"Potential mass assignment — server accepts extra fields on {ep.url}",
                            severity="High",
                            url=ep.url,
                            category="OWASP-A04 Insecure Design",
                            evidence=(
                                f"Method: {method}\n"
                                f"Baseline (minimal payload): {baseline_status}\n"
                                f"With extra fields: {test_resp.status_code}\n"
                                f"Extra fields sent: {', '.join(list(MASS_ASSIGN_FIELDS.keys())[:10])}..."
                            ),
                            impact="Server processes unexpected fields, potentially allowing privilege escalation.",
                            remediation="Validate and whitelist all accepted request body fields.",
                        ))
                        break

            except requests.RequestException:
                continue

    return findings


# ---------------------------------------------------------------------------
# Rate limiting & throttle testing
# ---------------------------------------------------------------------------

RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit", "X-Ratelimit-Limit",
    "X-RateLimit-Remaining", "X-Ratelimit-Remaining",
    "X-RateLimit-Reset", "X-Ratelimit-Reset",
    "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset",
    "Retry-After",
    "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
]

RATE_LIMIT_BURST = 20
RATE_LIMIT_INTERVAL = 0.05


def test_rate_limiting(endpoints: list[Endpoint]) -> list[Finding]:
    findings: list[Finding] = []

    sensitive_keywords = {"login", "auth", "token", "register", "signup", "password", "reset", "verify", "otp"}
    sensitive_eps = [
        ep for ep in endpoints
        if any(kw in ep.url.lower() for kw in sensitive_keywords)
        and ep.status_code not in (404, 502, 503)
    ]

    other_eps = [
        ep for ep in endpoints
        if ep not in sensitive_eps
        and ep.status_code == 200
    ][:5]

    test_targets = sensitive_eps + other_eps

    for ep in test_targets[:10]:
        rate_limited = False
        has_rate_headers = False
        statuses: list[int] = []

        for i in range(RATE_LIMIT_BURST):
            try:
                resp = _S().get(ep.url, timeout=5, allow_redirects=False)
                statuses.append(resp.status_code)

                if resp.status_code == 429:
                    rate_limited = True
                    break

                for hdr in RATE_LIMIT_HEADERS:
                    if hdr.lower() in {k.lower() for k in resp.headers}:
                        has_rate_headers = True

                time.sleep(RATE_LIMIT_INTERVAL)

            except requests.RequestException:
                break

        is_sensitive = any(kw in ep.url.lower() for kw in sensitive_keywords)

        if not rate_limited and not has_rate_headers and is_sensitive:
            findings.append(Finding(
                title=f"No rate limiting on sensitive endpoint {ep.url}",
                severity="High",
                url=ep.url,
                category="OWASP-A04 Insecure Design",
                evidence=(
                    f"Sent {len(statuses)} rapid requests with no rate limiting.\n"
                    f"Status codes: {', '.join(str(s) for s in statuses[:10])}\n"
                    f"No rate-limit response headers detected."
                ),
                impact="Brute-force and credential stuffing attacks are not throttled on authentication endpoints.",
                remediation="Implement rate limiting on authentication endpoints. Return 429 with Retry-After header.",
            ))
        elif not rate_limited and not has_rate_headers and not is_sensitive:
            findings.append(Finding(
                title=f"No rate limiting detected on {ep.url}",
                severity="Medium",
                url=ep.url,
                category="OWASP-A04 Insecure Design",
                evidence=(
                    f"Sent {len(statuses)} rapid requests with no rate limiting.\n"
                    f"Status codes: {', '.join(str(s) for s in statuses[:10])}"
                ),
                impact="API endpoints can be abused at high volume without throttling.",
                remediation="Implement rate limiting. Consider using X-RateLimit-* headers for client guidance.",
            ))
        elif has_rate_headers and not rate_limited:
            findings.append(Finding(
                title=f"Rate limit headers present but not enforced on {ep.url}",
                severity="Low",
                url=ep.url,
                category="OWASP-A04 Insecure Design",
                evidence=f"Rate limit headers found but {RATE_LIMIT_BURST} requests completed without 429.",
                impact="Rate limiting may be configured too loosely or not properly enforced.",
                remediation="Verify rate limit thresholds are appropriate for the endpoint's sensitivity.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

RUN_BUDGET_SEC = 25  # finish before bot 120s timeout


def run(
    target_url: str,
    scan_type: str = "full",
    wordlist: str = "medium",
    client_surface_json: str | None = None,
) -> str:
    set_scan_seed(target_url)
    report = APIReport(target_url=target_url)
    run_start = time.time()
    extra_seeds = _urls_from_client_surface(client_surface_json, target_url)

    def _over_budget() -> bool:
        return (time.time() - run_start) > RUN_BUDGET_SEC

    if scan_type in ("full", "discovery") and not _over_budget():
        try:
            report.endpoints_found = discover_endpoints(
                target_url, wordlist, extra_seed_urls=extra_seeds,
            )
            if _over_budget():
                report.endpoints_found = report.endpoints_found[:15]  # cap under budget
        except Exception as exc:
            report.errors.append(f"Endpoint discovery error: {exc}")

    if scan_type in ("full", "methods") and not _over_budget():
        try:
            report.endpoints_found, method_findings = test_methods(report.endpoints_found)
            report.findings.extend(method_findings)
        except Exception as exc:
            report.errors.append(f"Method testing error: {exc}")

    if scan_type in ("full", "cors") and not _over_budget():
        try:
            report.findings.extend(test_cors(report.endpoints_found[:20]))
        except Exception as exc:
            report.errors.append(f"CORS testing error: {exc}")

    if scan_type in ("full", "host_header") and not _over_budget():
        try:
            report.findings.extend(test_host_header_injection(report.endpoints_found[:15]))
        except Exception as exc:
            report.errors.append(f"Host header injection testing error: {exc}")

    if scan_type in ("full", "auth_bypass") and not _over_budget():
        try:
            report.findings.extend(test_auth_bypass(report.endpoints_found[:20]))
        except Exception as exc:
            report.errors.append(f"Auth bypass testing error: {exc}")

    if scan_type in ("full", "info_disclosure") and not _over_budget():
        try:
            report.findings.extend(check_info_disclosure(report.endpoints_found[:20]))
        except Exception as exc:
            report.errors.append(f"Info disclosure check error: {exc}")

    if scan_type in ("full", "graphql") and not _over_budget():
        try:
            report.findings.extend(test_graphql(target_url))
        except Exception as exc:
            report.errors.append(f"GraphQL testing error: {exc}")

    if scan_type in ("full", "param_fuzz") and not _over_budget():
        try:
            report.findings.extend(
                test_parameter_fuzzing(report.endpoints_found[:15], base_url=target_url),
            )
        except Exception as exc:
            report.errors.append(f"Parameter fuzzing error: {exc}")

    if scan_type in ("full", "mass_assign") and not _over_budget():
        try:
            report.findings.extend(test_mass_assignment(report.endpoints_found[:15]))
        except Exception as exc:
            report.errors.append(f"Mass assignment testing error: {exc}")

    if scan_type in ("full", "rate_limit") and not _over_budget():
        try:
            report.findings.extend(test_rate_limiting(report.endpoints_found[:15]))
        except Exception as exc:
            report.errors.append(f"Rate limit testing error: {exc}")

    if scan_type in ("full", "contract_drift") and not _over_budget():
        try:
            report.findings.extend(test_contract_drift(target_url, run_start, _over_budget))
        except Exception as exc:
            report.errors.append(f"Contract drift testing error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    wl = sys.argv[3] if len(sys.argv) > 3 else "medium"
    print(run(target, st, wl))
