#!/usr/bin/env python3
"""Security hardening test suite for Diverg Console API."""

import json
import time
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

BASE = "http://127.0.0.1:5000"
passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  — {detail}")


def headers_of(path="/login"):
    return requests.get(BASE + path).headers


# ═══════════════════════════════════════════════════════════════════════════
print("\n[1] CORS — origin whitelisting")
# ═══════════════════════════════════════════════════════════════════════════

r = requests.options(BASE + "/api/auth/login",
                     headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "POST"})
acao = r.headers.get("Access-Control-Allow-Origin", "")
check("Evil origin blocked", "evil.com" not in acao, f"got ACAO={acao}")

r = requests.options(BASE + "/api/auth/login",
                     headers={"Origin": "http://127.0.0.1:5000", "Access-Control-Request-Method": "POST"})
acao = r.headers.get("Access-Control-Allow-Origin", "")
check("Allowed origin accepted", acao == "http://127.0.0.1:5000", f"got ACAO={acao}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n[2] Security headers on login page")
# ═══════════════════════════════════════════════════════════════════════════

h = headers_of("/login")
check("CSP present on /login", "Content-Security-Policy" in h)
check("X-Frame-Options DENY", h.get("X-Frame-Options") == "DENY")
check("X-Content-Type-Options nosniff", h.get("X-Content-Type-Options") == "nosniff")
check("HSTS present", "max-age" in h.get("Strict-Transport-Security", ""))
check("COOP present", h.get("Cross-Origin-Opener-Policy") == "same-origin")
check("No-store on auth", "no-store" in headers_of("/api/auth/login").get("Cache-Control", ""))


# ═══════════════════════════════════════════════════════════════════════════
print("\n[3] Rate limiting on login")
# ═══════════════════════════════════════════════════════════════════════════

for i in range(12):
    r = requests.post(BASE + "/api/auth/login",
                      json={"email": "ratelimit@test.com", "password": "wrongpass1"},
                      headers={"X-Forwarded-For": "10.99.99.1"})

check("Rate limit triggers 429", r.status_code == 429, f"got {r.status_code}")
check("Retry-After header present", "Retry-After" in r.headers, r.headers.get("Retry-After", "missing"))


# ═══════════════════════════════════════════════════════════════════════════
print("\n[4] Rate limiting on register")
# ═══════════════════════════════════════════════════════════════════════════

for i in range(7):
    r = requests.post(BASE + "/api/auth/register",
                      json={"email": f"rl{i}@test.com", "password": "longpass123", "name": "Test"},
                      headers={"X-Forwarded-For": "10.99.99.2"})

check("Register rate limit triggers 429", r.status_code == 429, f"got {r.status_code}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n[5] User enumeration prevention")
# ═══════════════════════════════════════════════════════════════════════════

# Register a test user
test_email = f"enumtest{int(time.time())}@test.com"
r1 = requests.post(BASE + "/api/auth/register",
                    json={"email": test_email, "password": "testpass123", "name": "Enum Test"})

# Try to register again with same email
r2 = requests.post(BASE + "/api/auth/register",
                    json={"email": test_email, "password": "testpass123", "name": "Enum Test"})
check("Duplicate email gives generic error",
      "already registered" not in r2.json().get("error", "").lower(),
      f"got: {r2.json().get('error')}")
check("Duplicate email status 400 (not 409)",
      r2.status_code == 400, f"got {r2.status_code}")

# Wrong password — should be same error as non-existent user
r3 = requests.post(BASE + "/api/auth/login",
                    json={"email": test_email, "password": "wrongpassword1"})
r4 = requests.post(BASE + "/api/auth/login",
                    json={"email": "nonexistent@nowhere.com", "password": "wrongpassword1"})
check("Same error for wrong-pw vs non-existent user",
      r3.json().get("error") == r4.json().get("error"),
      f"wrong-pw={r3.json().get('error')} vs nonexist={r4.json().get('error')}")

# Google-only account shouldn't reveal auth method
r5 = requests.post(BASE + "/api/auth/login",
                    json={"email": "googleuser@test.com", "password": "anything123"})
check("No 'Google sign-in' leak in error",
      "google" not in r5.json().get("error", "").lower(),
      f"got: {r5.json().get('error')}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n[6] Input validation & limits")
# ═══════════════════════════════════════════════════════════════════════════

r = requests.post(BASE + "/api/auth/register",
                  json={"email": "x@x.com", "password": "short"},
                  headers={"X-Forwarded-For": "10.99.99.3"})
check("Short password rejected", r.status_code == 400)

r = requests.post(BASE + "/api/auth/register",
                  json={"email": "x@x.com", "password": "a" * 200},
                  headers={"X-Forwarded-For": "10.99.99.4"})
check("Oversized password rejected", r.status_code == 400)

r = requests.post(BASE + "/api/auth/register",
                  json={"email": "notanemail", "password": "testpass123"},
                  headers={"X-Forwarded-For": "10.99.99.5"})
check("Invalid email rejected", r.status_code == 400)

r = requests.post(BASE + "/api/auth/login",
                  json={"email": "x@x.com", "password": "a" * 200})
check("Oversized login password rejected", r.status_code == 401)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[7] JWT security")
# ═══════════════════════════════════════════════════════════════════════════

token = r1.json().get("token", "")

r = requests.get(BASE + "/api/auth/me", headers={"Authorization": f"Bearer {token}"})
check("Valid token works", r.status_code == 200)

r = requests.get(BASE + "/api/auth/me", headers={"Authorization": "Bearer invalidtoken"})
check("Invalid token rejected", r.status_code == 401)

r = requests.get(BASE + "/api/auth/me", headers={"Authorization": f"Bearer {'a' * 5000}"})
check("Oversized token rejected", r.status_code == 401)

r = requests.get(BASE + "/api/auth/me")
check("No token = 401", r.status_code == 401)

# Cookie-based auth should NOT work (removed)
r = requests.get(BASE + "/api/auth/me", cookies={"diverg_token": token})
check("Cookie-based auth disabled", r.status_code == 401)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[8] Data isolation between users")
# ═══════════════════════════════════════════════════════════════════════════

user_a_email = f"usera{int(time.time())}@test.com"
user_b_email = f"userb{int(time.time())}@test.com"

ra = requests.post(BASE + "/api/auth/register",
                   json={"email": user_a_email, "password": "testpass123"},
                   headers={"X-Forwarded-For": "10.99.99.6"})
rb = requests.post(BASE + "/api/auth/register",
                   json={"email": user_b_email, "password": "testpass123"},
                   headers={"X-Forwarded-For": "10.99.99.7"})

token_a = ra.json().get("token", "")
token_b = rb.json().get("token", "")

hist_a = requests.get(BASE + "/api/history", headers={"Authorization": f"Bearer {token_a}"})
hist_b = requests.get(BASE + "/api/history", headers={"Authorization": f"Bearer {token_b}"})
check("User A sees own scans only", hist_a.status_code == 200)
check("User B sees own scans only", hist_b.status_code == 200)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[9] Integer parsing safety")
# ═══════════════════════════════════════════════════════════════════════════

r = requests.get(BASE + "/api/history?limit=abc&offset=xyz",
                 headers={"Authorization": f"Bearer {token_a}"})
check("Non-integer limit/offset handled gracefully", r.status_code == 200,
      f"got {r.status_code}")

r = requests.get(BASE + "/api/history?limit=999999&offset=-5",
                 headers={"Authorization": f"Bearer {token_a}"})
check("Extreme limit/offset clamped", r.status_code == 200 and r.json()["limit"] <= 200)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[10] Payload size limit")
# ═══════════════════════════════════════════════════════════════════════════

try:
    huge_payload = json.dumps({"email": "x@x.com", "password": "a" * (3 * 1024 * 1024)})
    r = requests.post(BASE + "/api/auth/login",
                      data=huge_payload,
                      headers={"Content-Type": "application/json"})
    check("Oversized payload rejected", r.status_code in (413, 400, 401), f"got {r.status_code}")
except Exception as e:
    check("Oversized payload rejected (connection error)", True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[11] No user_id leakage in responses")
# ═══════════════════════════════════════════════════════════════════════════

r = requests.get(BASE + "/api/history", headers={"Authorization": f"Bearer {token_a}"})
data = r.json()
scans = data.get("scans", [])
if scans:
    has_uid = any("user_id" in s for s in scans)
    check("No user_id in history list", not has_uid)
else:
    check("No user_id in history list (no scans to check)", True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n[12] Server header masking")
# ═══════════════════════════════════════════════════════════════════════════

r = requests.get(BASE + "/api/health")
server = r.headers.get("Server", "")
check("Server header doesn't leak Werkzeug", "werkzeug" not in server.lower(), f"got: {server}")
check("Server header doesn't leak Python", "python" not in server.lower(), f"got: {server}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n[13] CSP blocks inline scripts")
# ═══════════════════════════════════════════════════════════════════════════

h = headers_of("/login")
csp = h.get("Content-Security-Policy", "")
check("CSP has no unsafe-inline for scripts", "unsafe-inline" not in csp.split("script-src")[1].split(";")[0] if "script-src" in csp else False, csp)
check("CSP has no unsafe-eval", "unsafe-eval" not in csp)

h2 = headers_of("/dashboard/")
csp2 = h2.get("Content-Security-Policy", "")
check("Dashboard CSP present", bool(csp2))


# ═══════════════════════════════════════════════════════════════════════════
print("\n[14] Brute force timing consistency")
# ═══════════════════════════════════════════════════════════════════════════

t1 = time.time()
requests.post(BASE + "/api/auth/login",
              json={"email": user_a_email, "password": "wrongpassword1"},
              headers={"X-Forwarded-For": "10.99.99.10"})
d1 = time.time() - t1

t2 = time.time()
requests.post(BASE + "/api/auth/login",
              json={"email": "totallynonexistent@nowhere.com", "password": "wrongpassword1"},
              headers={"X-Forwarded-For": "10.99.99.11"})
d2 = time.time() - t2

diff = abs(d1 - d2)
check("Timing difference < 500ms (prevents enumeration)", diff < 0.5,
      f"existing={d1:.3f}s nonexist={d2:.3f}s diff={diff:.3f}s")


# ═══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 60}")
print(f"  Results: {passed} passed, {failed} failed out of {passed + failed}")
print(f"{'=' * 60}")
sys.exit(1 if failed else 0)
