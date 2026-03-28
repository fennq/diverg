"""
Authentication and session testing skill — analyses login forms, cookie
security flags, session management, and common auth weaknesses.

Expanded modules:
  - Login form analysis (GET method, HTTP submission, CSRF, autocomplete)
  - Default credential testing (100+ pairs against discovered forms)
  - JWT attack testing (none alg, algo confusion, weak secrets, payload analysis)
  - Session security testing (fixation, invalidation, entropy, concurrent, cookie scope)
  - Password policy testing (registration form strength requirements)
  - Account enumeration (error messages, timing, registration/reset endpoints)
  - Rate limiting detection (rapid-fire login attempts)
  - Cookie security analysis
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import string
import sys
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent.parent))
from stealth import get_session, jitter, heavy_jitter
SESSION = get_session()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

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
class AuthReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Login form analysis
# ---------------------------------------------------------------------------

LOGIN_KEYWORDS = ["login", "signin", "sign-in", "log-in", "auth", "account", "session"]
PASSWORD_FIELD_NAMES = ["password", "passwd", "pass", "pwd", "secret"]
USERNAME_FIELD_NAMES = [
    "username", "user", "email", "login", "uid", "account",
    "user_login", "log", "user_name", "email_address", "signin",
]

REGISTRATION_PATHS = [
    "/register", "/signup", "/sign-up", "/join", "/create-account",
    "/registration", "/auth/register", "/user/register", "/accounts/signup",
    "/wp-login.php?action=register",
]

PASSWORD_RESET_PATHS = [
    "/forgot-password", "/forgot", "/password-reset", "/reset-password",
    "/auth/forgot", "/user/forgot", "/accounts/password/reset",
    "/wp-login.php?action=lostpassword",
]


def find_login_pages(base_url: str) -> list[str]:
    """Discover login pages by crawling common paths."""
    login_paths = [
        "/login", "/signin", "/sign-in", "/auth", "/auth/login",
        "/user/login", "/account/login", "/admin", "/admin/login",
        "/wp-login.php", "/wp-admin", "/administrator",
        "/accounts/login", "/session/new", "/api/auth/login",
    ]
    found: list[str] = []
    for path in login_paths:
        url = urljoin(base_url, path)
        try:
            resp = SESSION.get(url, timeout=4, allow_redirects=True)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in PASSWORD_FIELD_NAMES):
                    found.append(url)
        except requests.RequestException:
            continue
    return found


def _extract_form_fields(form, inputs):
    """Extract field name mappings from a login form."""
    username_field = None
    password_field = None
    hidden_fields: dict[str, str] = {}

    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        inp_type = inp.get("type", "text").lower()
        name_lower = name.lower()

        if inp_type == "password":
            password_field = name
        elif inp_type == "hidden":
            hidden_fields[name] = inp.get("value", "")
        elif inp_type in ("text", "email", "tel", ""):
            if any(kw in name_lower for kw in USERNAME_FIELD_NAMES):
                username_field = name
            elif username_field is None:
                username_field = name

    if username_field is None:
        for inp in inputs:
            inp_type = inp.get("type", "text").lower()
            if inp_type in ("text", "email", "tel") and inp.get("name"):
                username_field = inp.get("name")
                break

    return username_field, password_field, hidden_fields


def analyse_login_form(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = SESSION.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        login_forms = []
        for form in forms:
            inputs = form.find_all("input")
            input_types = [inp.get("type", "").lower() for inp in inputs]
            if "password" in input_types:
                login_forms.append((form, inputs))

        if not login_forms:
            return findings

        for form, inputs in login_forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            abs_action = urljoin(url, action) if action else url

            if method == "GET":
                findings.append(Finding(
                    title="Login form uses GET method",
                    severity="High",
                    url=url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Form action: {abs_action}\nMethod: GET",
                    impact="Credentials are sent as URL parameters and may be logged in browser history, proxy logs, and server access logs.",
                    remediation="Change form method to POST.",
                ))

            if urlparse(abs_action).scheme == "http":
                findings.append(Finding(
                    title="Login form submits credentials over HTTP",
                    severity="Critical",
                    url=url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Form action: {abs_action} (unencrypted HTTP)",
                    impact="Credentials are transmitted in plaintext and can be intercepted via MITM.",
                    remediation="Serve login forms and submit credentials exclusively over HTTPS.",
                ))

            input_names = [inp.get("name", "").lower() for inp in inputs]
            has_csrf = any(
                tok in name
                for name in input_names
                for tok in ("csrf", "token", "_token", "xsrf", "nonce", "authenticity")
            )
            if not has_csrf:
                findings.append(Finding(
                    title="Login form missing CSRF protection",
                    severity="Medium",
                    url=url,
                    category="OWASP-A01 Broken Access Control",
                    evidence=f"Form inputs: {', '.join(input_names)}\nNo CSRF token detected",
                    impact="Login CSRF: attacker could log the victim into their own account.",
                    remediation="Add CSRF token to login forms.",
                ))

            for inp in inputs:
                if inp.get("type", "").lower() == "password":
                    autocomplete = inp.get("autocomplete", "").lower()
                    if autocomplete not in ("off", "new-password", "current-password"):
                        findings.append(Finding(
                            title="Password field allows autocomplete",
                            severity="Low",
                            url=url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=f"Password input autocomplete='{autocomplete or 'not set'}'",
                            impact="Browsers may cache passwords, increasing risk on shared machines.",
                            remediation="Set autocomplete='off' or autocomplete='current-password' on password fields.",
                        ))

    except requests.RequestException as exc:
        findings.append(Finding(
            title="Connection error during login form analysis",
            severity="Info",
            url=url,
            category="Connectivity",
            evidence=str(exc),
            impact="Could not analyse target.",
            remediation="Verify target is reachable.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Default credential testing
# ---------------------------------------------------------------------------

DEFAULT_CREDENTIALS = [
    # Generic admin
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "12345678"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456789"), ("admin", "1234567890"),
    ("admin", "pass"), ("admin", "pass123"), ("admin", "admin1"),
    ("admin", "admin@123"), ("admin", "admin#123"), ("admin", "P@ssw0rd"),
    ("admin", "changeme"), ("admin", "welcome"), ("admin", "letmein"),
    ("admin", "master"), ("admin", "abc123"), ("admin", "qwerty"),
    ("admin", "password1"), ("admin", "iloveyou"), ("admin", "trustno1"),
    ("admin", "monkey"), ("admin", "dragon"), ("admin", "baseball"),
    # Root
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "123456"), ("root", "changeme"), ("root", "rootroot"),
    ("root", "pass"), ("root", "admin"), ("root", "default"),
    # Test / demo / guest
    ("test", "test"), ("test", "test123"), ("test", "password"),
    ("guest", "guest"), ("guest", "password"), ("guest", "123456"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("demo", "demo"), ("demo", "password"), ("demo", "demo123"),
    # Administrator
    ("administrator", "administrator"), ("administrator", "password"),
    ("administrator", "admin"), ("administrator", "123456"),
    # CMS defaults
    ("admin", "admin"), ("wp-admin", "wp-admin"),
    ("joomla", "joomla"), ("drupal", "drupal"),
    ("admin", "joomla"), ("admin", "drupal"), ("admin", "wordpress"),
    # Network / device defaults
    ("cisco", "cisco"), ("cisco", "password"), ("cisco", "class"),
    ("ubnt", "ubnt"), ("admin", "ubnt"),
    ("admin", "motorola"), ("admin", "1234"), ("admin", "default"),
    ("admin", "admin1234"), ("admin", "setup"),
    ("support", "support"), ("tech", "tech"),
    # Database defaults
    ("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "1234"),
    ("postgres", "postgres"), ("postgres", "password"), ("postgres", "admin"),
    ("root", ""), ("root", "mysql"),
    ("mysql", "mysql"), ("oracle", "oracle"), ("scott", "tiger"),
    ("dbadmin", "dbadmin"), ("mongo", "mongo"),
    # Application defaults
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("tomcat", "password"),
    ("manager", "manager"), ("manager", "password"),
    ("jenkins", "jenkins"), ("jenkins", "password"),
    ("nagios", "nagios"), ("nagiosadmin", "nagiosadmin"),
    ("weblogic", "weblogic"), ("weblogic", "welcome1"),
    ("glassfish", "glassfish"), ("admin", "glassfish"),
    # Service accounts
    ("operator", "operator"), ("supervisor", "supervisor"),
    ("sysadmin", "sysadmin"), ("service", "service"),
    ("info", "info"), ("support", "password"),
    ("webmaster", "webmaster"), ("postmaster", "postmaster"),
    ("ftp", "ftp"), ("backup", "backup"),
    # More common combos
    ("pi", "raspberry"), ("vagrant", "vagrant"),
    ("ansible", "ansible"), ("deploy", "deploy"),
    ("ubuntu", "ubuntu"), ("admin", "nimda"),
]


LOGIN_FAILURE_PATTERNS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "denied", "unauthorized", "bad credentials", "try again",
    "authentication failed", "login failed", "not recognized",
    "does not match", "please check", "cannot be found",
    "unable to log", "account locked", "too many attempts",
]

LOGIN_SUCCESS_PATTERNS = [
    "dashboard", "welcome", "my account", "profile", "logout",
    "sign out", "log out", "settings", "preferences", "home",
    "control panel", "admin panel", "overview",
]


def _detect_login_result(
    pre_cookies: dict,
    post_resp: requests.Response,
    login_url: str,
) -> bool:
    """Heuristically detect whether a login attempt succeeded."""
    body_lower = post_resp.text.lower()

    if any(pat in body_lower for pat in LOGIN_FAILURE_PATTERNS):
        return False

    redirected_away = post_resp.url != login_url and urlparse(post_resp.url).path != urlparse(login_url).path
    has_success_text = any(pat in body_lower for pat in LOGIN_SUCCESS_PATTERNS)
    cookie_changed = dict(post_resp.cookies) != pre_cookies
    new_auth_cookie = any(
        kw in name.lower()
        for name in post_resp.cookies.keys()
        for kw in ("session", "token", "auth", "jwt", "sid", "logged")
    )

    signals = sum([redirected_away, has_success_text, cookie_changed and new_auth_cookie])
    return signals >= 1


CRED_TIME_BUDGET = 35


def test_default_credentials(login_pages: list[str]) -> list[Finding]:
    """Test 100+ default credential pairs against discovered login forms."""
    findings: list[Finding] = []
    _t0 = time.time()

    for page_url in login_pages:
        if (time.time() - _t0) > CRED_TIME_BUDGET:
            return findings
        try:
            resp = SESSION.get(page_url, timeout=10)
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            inputs = form.find_all("input")
            input_types = [inp.get("type", "").lower() for inp in inputs]
            if "password" not in input_types:
                continue

            username_field, password_field, hidden_fields = _extract_form_fields(form, inputs)
            if not password_field:
                continue

            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            abs_action = urljoin(page_url, action) if action else page_url

            successful_creds: list[tuple[str, str]] = []

            seen_pairs: set[tuple[str, str]] = set()
            for user, passwd in DEFAULT_CREDENTIALS:
                if (time.time() - _t0) > CRED_TIME_BUDGET:
                    return findings
                pair = (user, passwd)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                form_data = dict(hidden_fields)
                if username_field:
                    form_data[username_field] = user
                form_data[password_field] = passwd

                try:
                    # Re-fetch form page to get fresh CSRF tokens
                    pre_resp = SESSION.get(page_url, timeout=8)
                    pre_soup = BeautifulSoup(pre_resp.text, "html.parser")
                    fresh_form = None
                    for f in pre_soup.find_all("form"):
                        if any(i.get("type", "").lower() == "password" for i in f.find_all("input")):
                            fresh_form = f
                            break
                    if fresh_form:
                        for inp in fresh_form.find_all("input"):
                            if inp.get("type", "").lower() == "hidden" and inp.get("name"):
                                form_data[inp["name"]] = inp.get("value", "")

                    pre_cookies = dict(SESSION.cookies)

                    if method == "POST":
                        cred_resp = SESSION.post(
                            abs_action, data=form_data, timeout=10, allow_redirects=True,
                        )
                    else:
                        cred_resp = SESSION.get(
                            abs_action, params=form_data, timeout=10, allow_redirects=True,
                        )

                    if _detect_login_result(pre_cookies, cred_resp, page_url):
                        successful_creds.append(pair)
                        findings.append(Finding(
                            title=f"Default credentials accepted: {user}/{passwd}",
                            severity="Critical",
                            url=page_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=(
                                f"Login form at {page_url}\n"
                                f"Username field: {username_field}\n"
                                f"Password field: {password_field}\n"
                                f"Credentials: {user} / {passwd}\n"
                                f"Response URL: {cred_resp.url}\n"
                                f"Status: {cred_resp.status_code}"
                            ),
                            impact="Attacker can gain immediate access using well-known default credentials.",
                            remediation="Change all default credentials immediately. Enforce strong passwords. Implement account lockout.",
                        ))
                        # Try to logout for next attempt
                        SESSION.cookies.clear()

                    jitter(0.3, 1.0)

                except requests.RequestException:
                    jitter(0.5, 1.5)
                    continue

            if not successful_creds:
                findings.append(Finding(
                    title="Default credentials rejected",
                    severity="Info",
                    url=page_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Tested {len(seen_pairs)} credential pairs against {page_url}. None succeeded.",
                    impact="No impact — default credentials are not accepted.",
                    remediation="No action required.",
                ))

    return findings


# ---------------------------------------------------------------------------
# JWT attack testing
# ---------------------------------------------------------------------------

def _b64_decode(data: str) -> bytes:
    """Base64url decode with padding fix."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    """Decode a JWT into (header, payload, signature) without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None


def _find_jwts(resp: requests.Response) -> list[tuple[str, str]]:
    """Find JWT tokens in cookies, headers, and response body. Returns (source, token) pairs."""
    jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    for cookie in resp.cookies:
        val = cookie.value
        if jwt_pattern.match(val) and val not in seen:
            found.append((f"cookie:{cookie.name}", val))
            seen.add(val)

    auth_header = resp.request.headers.get("Authorization", "") if resp.request else ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if jwt_pattern.match(token) and token not in seen:
            found.append(("header:Authorization", token))
            seen.add(token)

    for match in jwt_pattern.finditer(resp.text):
        token = match.group(0)
        if token not in seen:
            found.append(("body", token))
            seen.add(token)

    return found


def _analyse_jwt_payload(payload: dict, source: str, url: str) -> list[Finding]:
    """Check JWT payload for sensitive data and weak configuration."""
    findings: list[Finding] = []

    sensitive_keys = {
        "email": "Email address", "mail": "Email address",
        "phone": "Phone number", "ssn": "Social security number",
        "password": "Password", "passwd": "Password", "secret": "Secret",
        "credit_card": "Credit card", "cc_number": "Credit card",
        "address": "Physical address", "ip": "IP address",
        "internal_ip": "Internal IP", "private_ip": "Private IP",
    }

    exposed: list[str] = []
    for key in payload:
        key_lower = key.lower()
        for sens_key, label in sensitive_keys.items():
            if sens_key in key_lower:
                exposed.append(f"{key}={payload[key]} ({label})")

    if exposed:
        findings.append(Finding(
            title="JWT contains sensitive data",
            severity="Medium",
            url=url,
            category="OWASP-A02 Cryptographic Failures",
            evidence=f"Source: {source}\nExposed fields:\n" + "\n".join(f"  - {e}" for e in exposed),
            impact="JWTs are base64-encoded (not encrypted). Sensitive data is readable by anyone with the token.",
            remediation="Remove sensitive data from JWT payloads. Store only references (user IDs) and lookup details server-side.",
        ))

    ip_pattern = re.compile(r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b")
    payload_str = json.dumps(payload)
    ip_matches = ip_pattern.findall(payload_str)
    if ip_matches:
        findings.append(Finding(
            title="JWT exposes internal IP addresses",
            severity="Low",
            url=url,
            category="OWASP-A01 Broken Access Control",
            evidence=f"Source: {source}\nInternal IPs: {', '.join(m[0] if isinstance(m, tuple) else m for m in ip_matches)}",
            impact="Internal network topology disclosure aids targeted attacks.",
            remediation="Remove internal infrastructure details from JWT payloads.",
        ))

    exp = payload.get("exp")
    iat = payload.get("iat")
    now = time.time()

    if exp is None:
        findings.append(Finding(
            title="JWT has no expiration claim",
            severity="High",
            url=url,
            category="OWASP-A07 Identification and Authentication Failures",
            evidence=f"Source: {source}\nPayload has no 'exp' claim. Token never expires.",
            impact="Stolen tokens remain valid indefinitely.",
            remediation="Set a reasonable 'exp' claim (e.g., 15 minutes for access tokens, 7 days for refresh).",
        ))
    elif isinstance(exp, (int, float)):
        if iat and isinstance(iat, (int, float)):
            lifetime_hours = (exp - iat) / 3600
            if lifetime_hours > 24:
                findings.append(Finding(
                    title=f"JWT has very long lifetime ({lifetime_hours:.0f} hours)",
                    severity="Medium",
                    url=url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Source: {source}\nLifetime: {lifetime_hours:.1f} hours ({lifetime_hours/24:.1f} days)",
                    impact="Long-lived tokens increase the window for token theft and replay attacks.",
                    remediation="Reduce token lifetime. Use refresh tokens for long sessions.",
                ))

    role_keys = ("role", "roles", "scope", "scopes", "permissions", "is_admin", "admin", "group", "groups")
    role_info = {k: payload[k] for k in payload if k.lower() in role_keys}
    if role_info:
        findings.append(Finding(
            title="JWT contains authorization claims",
            severity="Info",
            url=url,
            category="OWASP-A01 Broken Access Control",
            evidence=f"Source: {source}\nAuthorization claims: {json.dumps(role_info)}",
            impact="If the server trusts JWT claims without validation, privilege escalation is possible via token tampering.",
            remediation="Always verify JWT signatures server-side. Do not rely solely on JWT claims for authorization.",
        ))

    return findings


def test_jwt_attacks(target_url: str, login_pages: list[str]) -> list[Finding]:
    """Detect JWT tokens and test for common JWT vulnerabilities."""
    findings: list[Finding] = []
    all_jwts: list[tuple[str, str, str]] = []  # (source, token, origin_url)

    urls_to_check = list(set([target_url] + login_pages))
    for url in urls_to_check:
        try:
            resp = SESSION.get(url, timeout=10, allow_redirects=True)
            for source, token in _find_jwts(resp):
                all_jwts.append((source, token, url))
        except requests.RequestException:
            continue

    if not all_jwts:
        return findings

    for source, token, origin_url in all_jwts:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue

        header, payload, signature = decoded

        findings.append(Finding(
            title=f"JWT token found ({source})",
            severity="Info",
            url=origin_url,
            category="OWASP-A07 Identification and Authentication Failures",
            evidence=(
                f"Source: {source}\n"
                f"Algorithm: {header.get('alg', 'unknown')}\n"
                f"Header: {json.dumps(header)}\n"
                f"Payload keys: {', '.join(payload.keys())}\n"
                f"Token (first 80 chars): {token[:80]}..."
            ),
            impact="JWT token detected — further analysis performed.",
            remediation="Ensure JWTs are properly secured with strong algorithms and secrets.",
        ))

        findings.extend(_analyse_jwt_payload(payload, source, origin_url))

        # Attack: "none" algorithm bypass
        try:
            none_header = {"alg": "none", "typ": "JWT"}
            none_token = (
                _b64_encode(json.dumps(none_header).encode())
                + "."
                + _b64_encode(json.dumps(payload).encode())
                + "."
            )

            test_headers_none = {"Authorization": f"Bearer {none_token}"}
            none_resp = SESSION.get(origin_url, timeout=10, headers=test_headers_none)

            if none_resp.status_code == 200 and not any(
                err in none_resp.text.lower() for err in ("invalid", "unauthorized", "error", "denied", "forbidden")
            ):
                findings.append(Finding(
                    title="JWT 'none' algorithm bypass may be accepted",
                    severity="Critical",
                    url=origin_url,
                    category="OWASP-A02 Cryptographic Failures",
                    evidence=(
                        f"Original alg: {header.get('alg')}\n"
                        f"Forged token with alg=none returned HTTP {none_resp.status_code}\n"
                        f"No obvious rejection in response body"
                    ),
                    impact="Attacker can forge arbitrary tokens without knowing the signing key.",
                    remediation="Explicitly reject 'none' algorithm. Use an allowlist of accepted algorithms.",
                ))
        except requests.RequestException:
            pass

        # Attack: Algorithm confusion (RS256 -> HS256)
        orig_alg = header.get("alg", "")
        if orig_alg.upper().startswith("RS"):
            try:
                confused_header = dict(header)
                confused_header["alg"] = "HS256"
                confused_token = (
                    _b64_encode(json.dumps(confused_header).encode())
                    + "."
                    + _b64_encode(json.dumps(payload).encode())
                    + "."
                    + _b64_encode(b"fakesig")
                )

                test_headers_confused = {"Authorization": f"Bearer {confused_token}"}
                confused_resp = SESSION.get(origin_url, timeout=10, headers=test_headers_confused)

                if confused_resp.status_code == 200 and not any(
                    err in confused_resp.text.lower()
                    for err in ("invalid", "unauthorized", "error", "denied", "forbidden")
                ):
                    findings.append(Finding(
                        title="JWT algorithm confusion vulnerability (RS256 -> HS256)",
                        severity="Critical",
                        url=origin_url,
                        category="OWASP-A02 Cryptographic Failures",
                        evidence=(
                            f"Original alg: {orig_alg}\n"
                            f"Changed to HS256, server returned HTTP {confused_resp.status_code}\n"
                            f"No obvious rejection"
                        ),
                        impact="Attacker can sign tokens with the public key (used as HMAC secret), forging arbitrary identity.",
                        remediation="Enforce expected algorithm server-side. Never allow the client to dictate the algorithm.",
                    ))
            except requests.RequestException:
                pass

        # Attack: Weak signing secrets
        domain = urlparse(origin_url).hostname or ""
        weak_secrets = [
            "secret", "password", "key", "123456", "", "jwt_secret",
            "changeme", "test", "admin", "HS256", "your-256-bit-secret",
            domain, domain.split(".")[0] if "." in domain else domain,
        ]

        for weak in weak_secrets:
            try:
                import hmac as _hmac
                signing_input = token.rsplit(".", 1)[0].encode("ascii")
                test_sig = _b64_encode(
                    _hmac.new(weak.encode("utf-8"), signing_input, hashlib.sha256).digest()
                )
                if test_sig == signature:
                    findings.append(Finding(
                        title=f"JWT signed with weak secret: '{weak}'",
                        severity="Critical",
                        url=origin_url,
                        category="OWASP-A02 Cryptographic Failures",
                        evidence=(
                            f"Source: {source}\n"
                            f"Secret: '{weak}'\n"
                            f"Algorithm: {header.get('alg')}\n"
                            f"HMAC-SHA256 signature matches"
                        ),
                        impact="Attacker can forge tokens with arbitrary claims (admin access, identity spoofing).",
                        remediation="Use a cryptographically random secret of at least 256 bits. Rotate secrets regularly.",
                    ))
                    break
            except Exception:
                continue

        jitter(0.2, 0.6)

    return findings


# ---------------------------------------------------------------------------
# Cookie security analysis
# ---------------------------------------------------------------------------

def analyse_cookies(target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = SESSION.get(target_url, timeout=10, allow_redirects=True)
        cookies = resp.cookies

        for cookie in cookies:
            issues: list[str] = []

            if not cookie.secure:
                issues.append("Missing 'Secure' flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("Missing 'HttpOnly' flag")

            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite or samesite.lower() == "none":
                issues.append(f"SameSite={samesite or 'not set'}")

            if not cookie.expires and not cookie.has_nonstandard_attr("Max-Age"):
                issues.append("No expiry set (session cookie)")

            for issue in issues:
                severity = "Medium" if "Secure" in issue or "HttpOnly" in issue else "Low"
                is_session = any(kw in cookie.name.lower() for kw in
                                 ("session", "sess", "sid", "token", "jwt", "auth"))
                if is_session:
                    severity = "High" if "Secure" in issue or "HttpOnly" in issue else "Medium"

                findings.append(Finding(
                    title=f"Cookie '{cookie.name}': {issue}",
                    severity=severity,
                    url=target_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...\nDomain: {cookie.domain}\nPath: {cookie.path}",
                    impact="Weak cookie flags increase risk of session hijacking or CSRF.",
                    remediation=f"Set {issue.split('Missing ')[-1] if 'Missing' in issue else 'SameSite=Strict'} on cookie '{cookie.name}'.",
                ))

            # Cookie scope analysis
            if cookie.domain and cookie.domain.startswith("."):
                parent_domain = cookie.domain.lstrip(".")
                if parent_domain.count(".") >= 1:
                    findings.append(Finding(
                        title=f"Cookie '{cookie.name}' scoped to broad domain",
                        severity="Low",
                        url=target_url,
                        category="OWASP-A07 Identification and Authentication Failures",
                        evidence=f"Cookie domain: {cookie.domain}\nPath: {cookie.path}",
                        impact="Cookie is shared with all subdomains, increasing exposure to subdomain takeover attacks.",
                        remediation="Scope cookies to the specific subdomain unless cross-subdomain access is required.",
                    ))

            if cookie.path == "/" or not cookie.path:
                is_session = any(kw in cookie.name.lower() for kw in
                                 ("session", "sess", "sid", "token", "auth"))
                if is_session:
                    findings.append(Finding(
                        title=f"Session cookie '{cookie.name}' scoped to root path",
                        severity="Low",
                        url=target_url,
                        category="OWASP-A07 Identification and Authentication Failures",
                        evidence=f"Cookie: {cookie.name}\nPath: {cookie.path or '/'}",
                        impact="Cookie is sent with every request to the domain, including non-sensitive paths.",
                        remediation="Restrict cookie path to the application root if possible.",
                    ))

    except requests.RequestException as exc:
        findings.append(Finding(
            title="Connection error during cookie analysis",
            severity="Info",
            url=target_url,
            category="Connectivity",
            evidence=str(exc),
            impact="Could not analyse cookies.",
            remediation="Verify target is reachable.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Session management checks (enhanced)
# ---------------------------------------------------------------------------

def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not value:
        return 0.0
    freq = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def analyse_session(target_url: str, login_pages: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []

    # Check if session IDs appear in URLs
    try:
        resp = SESSION.get(target_url, timeout=10, allow_redirects=True)
        final_url = resp.url
        session_url_patterns = re.compile(
            r"[?&;](jsessionid|phpsessid|sid|session_id|token)=",
            re.IGNORECASE,
        )
        if session_url_patterns.search(final_url):
            findings.append(Finding(
                title="Session ID exposed in URL",
                severity="High",
                url=final_url,
                category="OWASP-A07 Identification and Authentication Failures",
                evidence=f"URL contains session parameter: {final_url}",
                impact="Session IDs in URLs can leak via Referer headers, browser history, and logs.",
                remediation="Store session identifiers in cookies, not URL parameters.",
            ))

        # Session entropy analysis
        session_cookies = [
            c for c in resp.cookies
            if any(kw in c.name.lower() for kw in ("session", "sess", "sid", "token", "auth", "jsessionid", "phpsessid"))
        ]

        for cookie in session_cookies:
            sid_value = cookie.value
            entropy = _calculate_entropy(sid_value)
            sid_len = len(sid_value)

            if sid_len < 16:
                findings.append(Finding(
                    title=f"Session ID '{cookie.name}' is too short ({sid_len} chars)",
                    severity="High",
                    url=target_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.name}\nLength: {sid_len}\nValue: {sid_value[:30]}...",
                    impact="Short session IDs are vulnerable to brute-force guessing.",
                    remediation="Use session IDs of at least 128 bits (32 hex chars or 22 base64 chars).",
                ))

            if entropy < 3.0:
                findings.append(Finding(
                    title=f"Session ID '{cookie.name}' has low entropy ({entropy:.2f} bits/char)",
                    severity="High",
                    url=target_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.name}\nEntropy: {entropy:.2f} bits/char\nLength: {sid_len}\nValue sample: {sid_value[:30]}...",
                    impact="Low entropy session IDs can be predicted, enabling session hijacking.",
                    remediation="Use a cryptographically secure random number generator for session IDs.",
                ))

            # Check for sequential/predictable patterns
            if sid_value.isdigit():
                findings.append(Finding(
                    title=f"Session ID '{cookie.name}' is purely numeric",
                    severity="Medium",
                    url=target_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.name}\nValue: {sid_value[:30]}...\nAll characters are digits.",
                    impact="Numeric-only session IDs have reduced keyspace and may be sequential.",
                    remediation="Use alphanumeric session IDs generated with a CSPRNG.",
                ))

        # Session fixation: check if requesting a page with a known session ID is accepted
        if session_cookies:
            test_cookie = session_cookies[0]
            fixed_session = SESSION.__class__()
            fixed_session.cookies.set(test_cookie.name, "fixated_session_test_value_12345")
            try:
                fix_resp = fixed_session.get(target_url, timeout=10, allow_redirects=True)
                returned_sid = fix_resp.cookies.get(test_cookie.name)
                if returned_sid == "fixated_session_test_value_12345":
                    findings.append(Finding(
                        title="Possible session fixation vulnerability",
                        severity="High",
                        url=target_url,
                        category="OWASP-A07 Identification and Authentication Failures",
                        evidence=f"Server accepted client-supplied session ID '{test_cookie.name}' without regeneration.",
                        impact="Attacker can fix a victim's session ID and hijack their session after login.",
                        remediation="Always regenerate session IDs after authentication. Reject unknown session IDs.",
                    ))
            except requests.RequestException:
                pass

        # Concurrent sessions: fetch two sessions and verify both are distinct
        try:
            sess_a = SESSION.__class__()
            sess_b = SESSION.__class__()
            resp_a = sess_a.get(target_url, timeout=10)
            resp_b = sess_b.get(target_url, timeout=10)
            sids_a = {c.name: c.value for c in resp_a.cookies if any(kw in c.name.lower() for kw in ("session", "sid", "sess"))}
            sids_b = {c.name: c.value for c in resp_b.cookies if any(kw in c.name.lower() for kw in ("session", "sid", "sess"))}
            if sids_a and sids_b and sids_a == sids_b:
                findings.append(Finding(
                    title="Multiple requests receive identical session IDs",
                    severity="Medium",
                    url=target_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Session IDs from two separate clients are identical: {sids_a}",
                    impact="Static or reused session IDs indicate broken session management.",
                    remediation="Generate unique session IDs per client using a CSPRNG.",
                ))
        except requests.RequestException:
            pass

        # Check for generic error messages (username enumeration) — kept from original
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            input_types = [inp.get("type", "").lower() for inp in inputs]
            if "password" not in input_types:
                continue
            action = urljoin(target_url, form.get("action", ""))
            method = form.get("method", "POST").upper()

            form_data = {}
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                if inp.get("type", "").lower() == "password":
                    form_data[name] = "InvalidP@ss123!"
                elif inp.get("type", "").lower() in ("hidden",):
                    form_data[name] = inp.get("value", "")
                else:
                    form_data[name] = "nonexistent_user_sectester_probe"

            if method == "POST":
                try:
                    err_resp = SESSION.post(action, data=form_data, timeout=10, allow_redirects=True)
                    body_lower = err_resp.text.lower()
                    enum_phrases = [
                        "user not found", "no account", "username not found",
                        "email not found", "invalid username", "account does not exist",
                    ]
                    if any(phrase in body_lower for phrase in enum_phrases):
                        findings.append(Finding(
                            title="User enumeration via login error message",
                            severity="Medium",
                            url=action,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence="Login response distinguishes between invalid username and invalid password.",
                            impact="Attackers can enumerate valid usernames for targeted password attacks.",
                            remediation="Use generic error messages: 'Invalid credentials' regardless of which field is wrong.",
                        ))
                except requests.RequestException:
                    pass
    except requests.RequestException:
        pass

    return findings


# ---------------------------------------------------------------------------
# Account enumeration (enhanced)
# ---------------------------------------------------------------------------

COMMON_USERNAMES = [
    "admin", "administrator", "root", "test", "user", "guest",
    "info", "support", "webmaster", "postmaster", "sales",
    "contact", "helpdesk", "operator", "manager", "demo",
    "service", "sysadmin", "backup", "ftp",
]


def test_account_enumeration(target_url: str, login_pages: list[str]) -> list[Finding]:
    """Detect account enumeration via error messages, timing, registration, and password reset."""
    findings: list[Finding] = []

    # --- Login form enumeration with expanded patterns and timing ---
    for page_url in login_pages:
        try:
            resp = SESSION.get(page_url, timeout=10)
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            if not any(inp.get("type", "").lower() == "password" for inp in inputs):
                continue

            username_field, password_field, hidden_fields = _extract_form_fields(form, inputs)
            if not username_field or not password_field:
                continue

            action = urljoin(page_url, form.get("action", "") or "")
            method = form.get("method", "POST").upper()
            if method != "POST":
                continue

            enum_phrases = [
                "user not found", "no account", "username not found",
                "email not found", "invalid username", "account does not exist",
                "unknown user", "no user", "user does not exist",
                "not registered", "no such user", "not a valid user",
                "username is incorrect", "username doesn't exist",
                "username is not registered", "we couldn't find",
                "this account doesn't exist", "email is not registered",
                "invalid email address", "the email you entered",
            ]

            timings: dict[str, float] = {}
            responses: dict[str, str] = {}

            probe_users = ["nonexistent_xyzzy_9182", "admin", "root", "test"]
            for probe in probe_users:
                form_data = dict(hidden_fields)
                form_data[username_field] = probe
                form_data[password_field] = "InvalidP@ss123!_probe"

                try:
                    # Refresh CSRF
                    pre = SESSION.get(page_url, timeout=8)
                    pre_soup = BeautifulSoup(pre.text, "html.parser")
                    for f in pre_soup.find_all("form"):
                        for inp in f.find_all("input"):
                            if inp.get("type", "").lower() == "hidden" and inp.get("name"):
                                form_data[inp["name"]] = inp.get("value", "")

                    t0 = time.time()
                    err_resp = SESSION.post(action, data=form_data, timeout=15, allow_redirects=True)
                    elapsed = time.time() - t0

                    timings[probe] = elapsed
                    responses[probe] = err_resp.text.lower()

                    jitter(0.3, 0.8)
                except requests.RequestException:
                    continue

            # Check for specific enumeration messages
            if responses:
                nonexistent_body = responses.get("nonexistent_xyzzy_9182", "")
                for phrase in enum_phrases:
                    if phrase in nonexistent_body:
                        findings.append(Finding(
                            title="User enumeration via login error message",
                            severity="Medium",
                            url=page_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=f"Phrase detected: '{phrase}'\nEndpoint: {action}",
                            impact="Attackers can enumerate valid usernames for targeted password attacks.",
                            remediation="Use generic error messages like 'Invalid credentials' regardless of which field is wrong.",
                        ))
                        break

                # Compare responses for different usernames
                bodies = list(responses.values())
                if len(set(bodies)) > 1 and len(bodies) >= 2:
                    diffs = []
                    baseline = bodies[0]
                    for user, body in responses.items():
                        if body != baseline:
                            diffs.append(user)
                    if diffs:
                        findings.append(Finding(
                            title="Differing login error responses suggest user enumeration",
                            severity="Medium",
                            url=page_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=f"Response bodies differ between usernames: {', '.join(diffs)} vs baseline.\nEndpoint: {action}",
                            impact="Different error messages for valid vs invalid usernames enable enumeration.",
                            remediation="Return identical responses for all failed login attempts.",
                        ))

            # Timing-based enumeration
            if len(timings) >= 2:
                avg_time = sum(timings.values()) / len(timings)
                for user, t in timings.items():
                    if t > avg_time * 2 and abs(t - avg_time) > 0.5:
                        findings.append(Finding(
                            title="Timing-based user enumeration detected",
                            severity="Medium",
                            url=page_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=(
                                f"Username '{user}' took {t:.2f}s vs average {avg_time:.2f}s\n"
                                f"All timings: {json.dumps({k: round(v, 3) for k, v in timings.items()})}"
                            ),
                            impact="Response time differences between valid and invalid usernames enable enumeration.",
                            remediation="Ensure consistent response times regardless of username validity (e.g., always hash the password).",
                        ))
                        break

    # --- Registration endpoint enumeration ---
    base = target_url.rstrip("/")
    for reg_path in REGISTRATION_PATHS:
        reg_url = urljoin(base + "/", reg_path.lstrip("/"))
        try:
            resp = SESSION.get(reg_url, timeout=8, allow_redirects=True)
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                inputs = form.find_all("input")
                email_or_user_field = None
                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    inp_type = (inp.get("type") or "").lower()
                    if any(kw in name for kw in ("email", "username", "user", "login")):
                        email_or_user_field = inp.get("name")
                        break
                    if inp_type == "email":
                        email_or_user_field = inp.get("name")
                        break

                if not email_or_user_field:
                    continue

                reg_action = urljoin(reg_url, form.get("action", "") or "")
                form_data = {}
                for inp in inputs:
                    n = inp.get("name", "")
                    if not n:
                        continue
                    if inp.get("type", "").lower() == "hidden":
                        form_data[n] = inp.get("value", "")
                    else:
                        form_data[n] = "probe_test_value"

                form_data[email_or_user_field] = "admin"

                try:
                    reg_resp = SESSION.post(reg_action, data=form_data, timeout=10, allow_redirects=True)
                    body_lower = reg_resp.text.lower()
                    exists_phrases = [
                        "already exists", "already taken", "already registered",
                        "already in use", "is taken", "account exists",
                        "email exists", "username exists", "is unavailable",
                        "has been taken", "is already", "duplicate",
                    ]
                    if any(p in body_lower for p in exists_phrases):
                        findings.append(Finding(
                            title="User enumeration via registration endpoint",
                            severity="Medium",
                            url=reg_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=f"Registration at {reg_action} reveals existing accounts.\nField: {email_or_user_field}",
                            impact="Attackers can discover valid accounts by attempting registration with known usernames/emails.",
                            remediation="Use a generic message like 'If this email is available, you will receive a confirmation.' Send the real result only via email.",
                        ))
                        break
                except requests.RequestException:
                    pass
                break
        except requests.RequestException:
            continue

    # --- Password reset enumeration ---
    for reset_path in PASSWORD_RESET_PATHS:
        reset_url = urljoin(base + "/", reset_path.lstrip("/"))
        try:
            resp = SESSION.get(reset_url, timeout=8, allow_redirects=True)
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                email_field = None
                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    inp_type = (inp.get("type") or "").lower()
                    if "email" in name or "user" in name or inp_type == "email":
                        email_field = inp.get("name")
                        break

                if not email_field:
                    continue

                reset_action = urljoin(reset_url, form.get("action", "") or "")
                form_data = {}
                for inp in inputs:
                    n = inp.get("name", "")
                    if not n:
                        continue
                    if inp.get("type", "").lower() == "hidden":
                        form_data[n] = inp.get("value", "")

                # Test with a definitely-nonexistent email
                form_data[email_field] = "nonexistent_xyzzy_8271@fakefake.invalid"
                try:
                    reset_resp = SESSION.post(reset_action, data=form_data, timeout=10, allow_redirects=True)
                    body_lower = reset_resp.text.lower()
                    not_found_phrases = [
                        "not found", "no account", "doesn't exist",
                        "does not exist", "not registered", "unknown",
                        "no user", "invalid email", "could not find",
                    ]
                    if any(p in body_lower for p in not_found_phrases):
                        findings.append(Finding(
                            title="User enumeration via password reset",
                            severity="Medium",
                            url=reset_url,
                            category="OWASP-A07 Identification and Authentication Failures",
                            evidence=f"Password reset at {reset_action} reveals whether an account exists.\nField: {email_field}",
                            impact="Attackers can confirm valid accounts via the password reset flow.",
                            remediation="Always return a generic message like 'If an account exists, a reset email has been sent.'",
                        ))
                        break
                except requests.RequestException:
                    pass
                break
        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------------------------
# Password policy testing
# ---------------------------------------------------------------------------

TOP_COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
]


def test_password_policy(target_url: str) -> list[Finding]:
    """Test registration forms for weak password policies."""
    findings: list[Finding] = []
    base = target_url.rstrip("/")

    for reg_path in REGISTRATION_PATHS:
        reg_url = urljoin(base + "/", reg_path.lstrip("/"))
        try:
            resp = SESSION.get(reg_url, timeout=8, allow_redirects=True)
            if resp.status_code != 200:
                continue
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            if not any(inp.get("type", "").lower() == "password" for inp in inputs):
                continue

            username_field = None
            password_field = None
            email_field = None
            hidden_fields: dict[str, str] = {}

            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                inp_type = inp.get("type", "text").lower()
                name_lower = name.lower()

                if inp_type == "password" and not password_field:
                    password_field = name
                elif inp_type == "hidden":
                    hidden_fields[name] = inp.get("value", "")
                elif inp_type == "email" or "email" in name_lower:
                    email_field = name
                elif any(kw in name_lower for kw in USERNAME_FIELD_NAMES):
                    username_field = name

            if not password_field:
                continue

            reg_action = urljoin(reg_url, form.get("action", "") or "")
            accepted: list[str] = []
            rejected: list[str] = []

            rejection_phrases = [
                "too short", "too weak", "must contain", "at least",
                "minimum", "password requirements", "stronger password",
                "not strong enough", "password must", "complexity",
                "uppercase", "lowercase", "digit", "number", "special",
                "character", "invalid password", "password policy",
            ]

            test_passwords = [
                ("a", "1 char"),
                ("abc", "3 chars, lowercase only"),
                ("abcde", "5 chars, lowercase only"),
                ("abcdefg", "7 chars, lowercase only"),
                ("abcdefghij", "10 chars, lowercase only"),
                ("ABCDEFGH", "8 chars, uppercase only"),
                ("12345678", "8 chars, digits only"),
                ("abcd1234", "8 chars, lower + digits, no special"),
                ("Abcd1234", "8 chars, mixed case + digits, no special"),
                ("password", "common password"),
                ("123456", "common password"),
                ("qwerty", "common password"),
            ]

            random_user = f"sectester_probe_{int(time.time()) % 10000}"
            random_email = f"sectester_probe_{int(time.time()) % 10000}@fakefake.invalid"

            for test_pw, description in test_passwords:
                try:
                    # Refresh CSRF
                    pre = SESSION.get(reg_url, timeout=8)
                    pre_soup = BeautifulSoup(pre.text, "html.parser")
                    fresh_hidden = dict(hidden_fields)
                    for f in pre_soup.find_all("form"):
                        for inp in f.find_all("input"):
                            if inp.get("type", "").lower() == "hidden" and inp.get("name"):
                                fresh_hidden[inp["name"]] = inp.get("value", "")

                    form_data = dict(fresh_hidden)
                    form_data[password_field] = test_pw
                    if username_field:
                        form_data[username_field] = random_user
                    if email_field:
                        form_data[email_field] = random_email

                    # Fill any confirm-password fields
                    for inp in inputs:
                        n = inp.get("name", "")
                        if n and n not in form_data:
                            nl = n.lower()
                            if "confirm" in nl or "password2" in nl or "re_password" in nl or "retype" in nl:
                                form_data[n] = test_pw

                    pw_resp = SESSION.post(reg_action, data=form_data, timeout=10, allow_redirects=True)
                    body_lower = pw_resp.text.lower()

                    was_rejected = any(p in body_lower for p in rejection_phrases)

                    if was_rejected:
                        rejected.append(f"{test_pw} ({description})")
                    else:
                        accepted.append(f"{test_pw} ({description})")

                    jitter(0.5, 1.5)
                except requests.RequestException:
                    continue

            if accepted:
                weak_accepted = [p for p in accepted if any(kw in p for kw in ("1 char", "3 char", "common", "only"))]
                if weak_accepted:
                    findings.append(Finding(
                        title="Weak password policy: registration accepts weak passwords",
                        severity="High",
                        url=reg_url,
                        category="OWASP-A07 Identification and Authentication Failures",
                        evidence=(
                            f"Registration at {reg_action}\n"
                            f"Accepted weak passwords:\n" +
                            "\n".join(f"  - {p}" for p in weak_accepted) +
                            ("\n\nRejected:\n" + "\n".join(f"  - {p}" for p in rejected) if rejected else "\n\nNo passwords were rejected.")
                        ),
                        impact="Weak passwords enable brute-force and credential stuffing attacks.",
                        remediation="Enforce minimum 8 characters with complexity requirements. Block common passwords.",
                    ))

            if not rejected and accepted:
                findings.append(Finding(
                    title="No password policy detected on registration",
                    severity="High",
                    url=reg_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"Registration at {reg_action} accepted all test passwords including single-character passwords.",
                    impact="Users can set trivially weak passwords, making accounts vulnerable to brute-force.",
                    remediation="Implement password policy: minimum length 8+, complexity requirements, common password blocklist.",
                ))

            return findings  # Only test the first registration form found

    return findings


# ---------------------------------------------------------------------------
# Rate limiting detection
# ---------------------------------------------------------------------------

def test_rate_limiting(login_pages: list[str]) -> list[Finding]:
    """Send rapid login requests to detect absence of rate limiting."""
    findings: list[Finding] = []
    NUM_REQUESTS = 15

    for page_url in login_pages:
        try:
            resp = SESSION.get(page_url, timeout=10)
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            if not any(inp.get("type", "").lower() == "password" for inp in inputs):
                continue

            username_field, password_field, hidden_fields = _extract_form_fields(form, inputs)
            if not password_field:
                continue

            action = urljoin(page_url, form.get("action", "") or "")
            method = form.get("method", "POST").upper()
            if method != "POST":
                continue

            statuses: list[int] = []
            blocked = False
            lockout_detected = False
            captcha_detected = False

            lockout_phrases = [
                "locked", "too many", "rate limit", "slow down",
                "temporarily blocked", "try again later", "exceeded",
                "maximum attempts", "account locked", "temporarily disabled",
                "brute force", "please wait", "throttled",
            ]

            captcha_phrases = [
                "captcha", "recaptcha", "hcaptcha", "challenge",
                "verify you are human", "are you a robot", "bot detection",
            ]

            for i in range(NUM_REQUESTS):
                try:
                    # Refresh hidden fields
                    pre = SESSION.get(page_url, timeout=8)
                    pre_soup = BeautifulSoup(pre.text, "html.parser")
                    fresh_hidden = dict(hidden_fields)
                    for f in pre_soup.find_all("form"):
                        for inp in f.find_all("input"):
                            if inp.get("type", "").lower() == "hidden" and inp.get("name"):
                                fresh_hidden[inp["name"]] = inp.get("value", "")

                    form_data = dict(fresh_hidden)
                    if username_field:
                        form_data[username_field] = "admin"
                    form_data[password_field] = f"WrongPass_{i}!"

                    rapid_resp = SESSION.post(action, data=form_data, timeout=10, allow_redirects=True)
                    statuses.append(rapid_resp.status_code)
                    body_lower = rapid_resp.text.lower()

                    if rapid_resp.status_code == 429:
                        blocked = True
                        break

                    if any(p in body_lower for p in lockout_phrases):
                        lockout_detected = True
                        break

                    if any(p in body_lower for p in captcha_phrases):
                        captcha_detected = True
                        break

                    # Minimal delay to simulate rapid fire
                    time.sleep(0.1)
                except requests.RequestException:
                    continue

            if blocked:
                findings.append(Finding(
                    title="Rate limiting active: HTTP 429 returned",
                    severity="Info",
                    url=page_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"After {len(statuses)} rapid login attempts, server returned 429 Too Many Requests.",
                    impact="Rate limiting is in place — brute-force is mitigated.",
                    remediation="No action required. Consider also implementing account lockout.",
                ))
            elif lockout_detected:
                findings.append(Finding(
                    title="Account lockout mechanism detected",
                    severity="Info",
                    url=page_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"After {len(statuses)} rapid login attempts, lockout/throttle message appeared.",
                    impact="Account lockout protects against brute-force (but may enable denial-of-service against specific accounts).",
                    remediation="Consider temporary lockout (progressive delays) rather than permanent lockout to avoid DoS.",
                ))
            elif captcha_detected:
                findings.append(Finding(
                    title="CAPTCHA triggered after multiple login attempts",
                    severity="Info",
                    url=page_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=f"After {len(statuses)} rapid login attempts, CAPTCHA challenge appeared.",
                    impact="CAPTCHA mitigates automated brute-force attacks.",
                    remediation="Ensure CAPTCHA is not easily bypassed. Consider rate limiting in addition to CAPTCHA.",
                ))
            elif len(statuses) >= NUM_REQUESTS:
                findings.append(Finding(
                    title="No rate limiting on login endpoint",
                    severity="High",
                    url=page_url,
                    category="OWASP-A07 Identification and Authentication Failures",
                    evidence=(
                        f"Sent {NUM_REQUESTS} rapid login requests to {action}\n"
                        f"All returned HTTP 200 (or similar) with no blocking.\n"
                        f"Status codes: {statuses}"
                    ),
                    impact="Attacker can perform unlimited brute-force and credential stuffing attacks.",
                    remediation="Implement rate limiting (e.g., max 5 attempts per minute), progressive delays, account lockout, and/or CAPTCHA.",
                ))

            break  # Only test the first login form per page

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

RUN_BUDGET_SEC = 25  # finish before bot 120s timeout


def run(target_url: str, scan_type: str = "full") -> str:
    report = AuthReport(target_url=target_url)
    run_start = time.time()

    def _over_budget() -> bool:
        return (time.time() - run_start) > RUN_BUDGET_SEC

    login_pages = [target_url]

    def _run_forms_phase() -> None:
        nonlocal login_pages
        try:
            discovered = find_login_pages(target_url)
            if discovered:
                login_pages = discovered[:3]
        except Exception as exc:
            report.errors.append(f"Login page discovery error: {exc}")
        for page in login_pages:
            if (time.time() - run_start) > RUN_BUDGET_SEC:
                break
            try:
                report.findings.extend(analyse_login_form(page))
            except Exception as exc:
                report.errors.append(f"Login form analysis error on {page}: {exc}")

    if scan_type in ("full", "forms") and not _over_budget():
        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_run_forms_phase)
                future.result(timeout=min(RUN_BUDGET_SEC - 3, 52))
        except concurrent.futures.TimeoutError:
            report.errors.append("Forms phase skipped (over time budget)")
        except Exception as exc:
            report.errors.append(f"Login form error: {exc}")

    if scan_type in ("full", "cookies") and not _over_budget():
        for page in login_pages[:3]:
            if _over_budget():
                break
            try:
                report.findings.extend(analyse_cookies(page))
            except Exception as exc:
                report.errors.append(f"Cookie analysis error on {page}: {exc}")

    if scan_type in ("full", "session") and not _over_budget():
        for page in login_pages[:3]:
            if _over_budget():
                break
            try:
                report.findings.extend(analyse_session(page, login_pages))
            except Exception as exc:
                report.errors.append(f"Session analysis error on {page}: {exc}")

    if scan_type in ("full", "credentials") and not _over_budget():
        try:
            report.findings.extend(test_default_credentials(login_pages[:3]))
        except Exception as exc:
            report.errors.append(f"Default credential testing error: {exc}")

    if scan_type in ("full", "jwt") and not _over_budget():
        try:
            report.findings.extend(test_jwt_attacks(target_url, login_pages[:3]))
        except Exception as exc:
            report.errors.append(f"JWT attack testing error: {exc}")

    if scan_type in ("full", "enumeration") and not _over_budget():
        try:
            report.findings.extend(test_account_enumeration(target_url, login_pages[:3]))
        except Exception as exc:
            report.errors.append(f"Account enumeration testing error: {exc}")

    if scan_type in ("full", "password_policy") and not _over_budget():
        try:
            report.findings.extend(test_password_policy(target_url))
        except Exception as exc:
            report.errors.append(f"Password policy testing error: {exc}")

    if scan_type in ("full", "rate_limit") and not _over_budget():
        try:
            report.findings.extend(test_rate_limiting(login_pages[:3]))
        except Exception as exc:
            report.errors.append(f"Rate limiting testing error: {exc}")

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(target, st))
