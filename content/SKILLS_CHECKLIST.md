# Diverg skills checklist — requested vs implemented

This maps the requested capabilities (click/type/scroll, CORS, SQLi, etc.) to what we have and what was added.

| Capability | Status | Where |
|------------|--------|--------|
| **Click, type, scroll, navigate, submit forms, go back, pause for manual login/MFA** | Partial | Operator-driven; auth_test covers login flows. MFA pause documented in runbook: operator completes MFA when prompted, then continues. |
| **CORS misconfiguration testing** | ✅ | `api_test`: `test_cors` — wildcard, null origin, reflection, preflight dangerous methods |
| **SQL injection (URL params)** | ✅ | `web_vulns`: error-based, UNION, boolean blind, time-based, WAF bypass, stacked queries (60+ payloads) |
| **NoSQL injection (URL/body params)** | ✅ | `web_vulns`: `test_nosqli` — MongoDB-style `$where`, `$gt`, `$ne`, operator injection |
| **IDOR — increment numeric IDs** | ✅ | `high_value_flaws`: `probe_idor` path/param; `api_test` resource-without-auth; `payment_financial` payment/order IDOR |
| **Security headers audit** | ✅ | `headers_ssl`, `web_vulns` `test_security_headers` — HSTS, CSP, X-Frame-Options, etc. |
| **Host header injection** | ✅ | `api_test`: `test_host_header_injection` — Host / X-Forwarded-Host to detect reflection/poisoning |
| **HTTP method tampering (PUT, DELETE, PATCH, TRACE)** | ✅ | `api_test`: method probe on every endpoint; auth bypass via verb tampering |
| **GraphQL introspection, batching, field suggestion/depth** | ✅ | `api_test`: `test_graphql` — introspection, depth limit, batching |
| **LFI and path traversal** | ✅ | `web_vulns`: `test_traversal` on file/path params; sensitive file discovery |
| **Open redirect (redirect/url/next/callback)** | ✅ | `web_vulns`: `test_open_redirect` — 19 payloads, 24 param names |
| **Mass assignment (role, isAdmin, admin in POST/PUT)** | ✅ | `api_test`: `test_mass_assignment` — isAdmin, role, roles, user_role, etc. |
| **SSRF (cloud metadata AWS, GCP, Azure, Alibaba)** | ✅ | `web_vulns`: `test_ssrf` — 169.254.169.254, GCP/Azure/Alibaba/ECS |
| **Subdomain enumeration** | ✅ | `recon`: DNS brute + crt.sh; `osint`: crt.sh harvest |
| **Favicon hash fingerprinting** | ✅ | `recon`: fetch `/favicon.ico`, compute MD5, report for Shodan/signature lookup |
| **SSL cert SAN extraction** | ✅ | `headers_ssl`: cert SAN (SubjectAlternativeName) for hidden subdomains/services |
| **Error page fingerprinting (Django, Laravel, Spring, PHP)** | ✅ | `recon`: `fingerprint_tech` — FRAMEWORK_PATHS, JS markers, headers (X-Powered-By, etc.) |
| **120+ backend path probes** | ✅ | `api_test`: small/medium/large wordlists (API, admin, debug, GraphQL, actuator, Django, Rails, PHP, .NET, Node, VCS, backups, 649+ paths) |
| **Source map detection** | ✅ | `client_surface`: `.map` detection, exposes original source paths |
| **Site classification / targeted attack hypotheses** | ✅ | `run_discover_surface`: infers site type, returns `recommended_skills` with reasons; `build_adaptive_attack_plan` |
| **JWT (algorithm weaknesses, weak secrets, missing expiry)** | ✅ | `auth_test`: `test_jwt_attacks` — alg:none, algo confusion, weak secret; payload (exp, sensitive data). `crypto_security`: JWT alg:none |
| **WAF and rate limit bypass testing** | ✅ | `recon`: `detect_waf`; `api_test`: `test_rate_limiting`, auth bypass headers/path; `web_vulns`: SQLi WAF bypass payloads; `stealth`: 429 backoff |
| **CVE lookup vs detected tech stack** | ✅ | `dependency_audit`: CVE watchlist vs detected versions (client_surface + recon) |
| **DDoS risk scoring** | Partial | WAF/rate-limit detection present; no single “DDoS risk score” — report notes “no rate limiting” on sensitive endpoints as risk |
| **Pre-scan attack planning** | ✅ | `build_adaptive_attack_plan` — phase1/2/3, site-type and profile driven |
| **Working memory across rounds** | ✅ | Brain: `knowledge`, `scan_history`, `learned_techniques`, `custom_tools` |
| **Mid-scan reflection every 2 rounds** | Partial | Bot uses `max_rounds` (e.g. 5); prompt advises using findings to refine. Explicit “every 2 rounds re-plan” can be added to agent loop. |
| **Early exit when leads exhausted** | Partial | Time/count bounds exist; prompt can instruct “if last N tool calls added no new findings, summarize and exit”. |

## Additions made in this pass

- **NoSQL injection**: `web_vulns` — `test_nosqli` for MongoDB-style operator injection.
- **Host header injection**: `api_test` — `test_host_header_injection` (Host / X-Forwarded-Host).
- **Favicon hash**: `recon` — fetch favicon, MD5 hash, report for Shodan/signature lookup.
- **MFA / manual login**: Documented in runbook and (optional) bot note: pause for operator to complete MFA when target requires it.

## Optional future improvements

- **DDoS risk score**: Single metric from “rate limit absent” + “sensitive endpoints” + “WAF absent”.
- **Mid-scan reflection**: After every 2 tool rounds, inject a “strategy update” step (re-plan from current findings).
- **Early exit**: In chat loop, if last 2 tool rounds added zero new findings, suggest summary and stop.
