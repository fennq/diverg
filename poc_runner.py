"""
Live PoC / Simulate — run a minimal proof-of-concept for a finding to confirm or refute it.

Supported types:
- idor: replay request with a different ID param; compare response.
- unauthenticated: replay request without auth headers; see if we get data.

Used by: POST /api/poc/simulate (extension calls this when user clicks "Simulate").
Authorized use only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

try:
    import requests
    from requests.exceptions import ConnectionError as ReqConnectionError, Timeout as ReqTimeout, RequestException
except ImportError:
    requests = None
    ReqConnectionError = ReqTimeout = RequestException = Exception

TIMEOUT = 10
MAX_BODY_PREVIEW = 500


@dataclass
class PoCResult:
    success: bool  # True if we could run the PoC (no network error)
    status_code: int | None = None
    body_preview: str = ""
    conclusion: str = ""
    error: str = ""
    poc_type: str = ""


def _preview(body: str | bytes) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            return "(binary)"
    s = (body or "").strip()
    if len(s) > MAX_BODY_PREVIEW:
        s = s[:MAX_BODY_PREVIEW] + "..."
    return s


def _norm_url(url: str) -> str:
    url = (url or "").strip()
    if url and not url.startswith("http"):
        url = "https://" + url
    return url


def run_idor_poc(
    url: str,
    method: str = "GET",
    params: dict | None = None,
    data: dict | str | None = None,
    headers: dict | None = None,
    param_to_change: str | None = None,
    new_value: str = "1",
    cookies: dict | None = None,
) -> PoCResult:
    """
    Send the same request twice: once with original param, once with new_value.
    If the second request returns 200 with a different/ non-empty body, likely IDOR.
    """
    if not requests:
        return PoCResult(success=False, error="requests not available", poc_type="idor")

    url = _norm_url(url)
    if not url:
        return PoCResult(success=False, error="Missing url", poc_type="idor")

    method = (method or "GET").upper()
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; Diverg-PoC/1.0)")

    # Determine param to change from URL or body
    param = param_to_change
    if not param and params:
        # Change first ID-like param
        for k in ("user_id", "userId", "id", "account_id", "order_id", "uid"):
            if k in params:
                param = k
                break
        if not param and params:
            param = next(iter(params))
    if not param and not data:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        for k in ("user_id", "userId", "id", "account_id", "order_id", "uid"):
            if k in q:
                param = k
                break
        if not param and q:
            param = next(iter(q))

    if not param:
        return PoCResult(
            success=False,
            error="Could not determine parameter to change for IDOR PoC (add param_to_change)",
            poc_type="idor",
        )

    try:
        if method == "GET":
            r1 = requests.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        else:
            r1 = requests.request(
                method,
                url,
                params=params if method == "GET" else None,
                data=data,
                json=None,
                headers=headers,
                cookies=cookies,
                timeout=TIMEOUT,
                allow_redirects=False,
            )
    except ReqTimeout:
        return PoCResult(success=False, error=f"Request timed out after {TIMEOUT}s", poc_type="idor")
    except ReqConnectionError:
        return PoCResult(success=False, error="Could not connect to target — host may be down or unreachable", poc_type="idor")
    except RequestException as e:
        return PoCResult(success=False, error=f"Request failed: {e}", poc_type="idor")
    except Exception as e:
        return PoCResult(success=False, error=str(e), poc_type="idor")

    # Request 2: with modified param
    params2 = dict(params or {})
    data2 = data
    if isinstance(data2, dict):
        data2 = dict(data2)
        data2[param] = new_value
    elif param in (params or {}):
        params2[param] = new_value
    else:
        # Param might be in URL query
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [new_value]
        new_query = urlencode(q, doseq=True)
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        params2 = None

    try:
        if method == "GET":
            r2 = requests.get(url, params=params2, headers=headers, cookies=cookies, timeout=TIMEOUT, allow_redirects=False)
        else:
            r2 = requests.request(
                method,
                url,
                params=params2 if method == "GET" else None,
                data=data2,
                json=None,
                headers=headers,
                cookies=cookies,
                timeout=TIMEOUT,
                allow_redirects=False,
            )
    except ReqTimeout:
        return PoCResult(
            success=True, status_code=r1.status_code, body_preview=_preview(r1.content),
            conclusion=f"First request succeeded ({r1.status_code}); second request timed out after {TIMEOUT}s. Manually try changing {param}.",
            poc_type="idor",
        )
    except (ReqConnectionError, RequestException, Exception) as e:
        return PoCResult(
            success=True, status_code=r1.status_code, body_preview=_preview(r1.content),
            conclusion=f"First request succeeded ({r1.status_code}); second request failed: {e}. Manually try changing {param}.",
            poc_type="idor",
        )

    body2 = _preview(r2.content)
    if r2.status_code == 200 and len(body2) > 0:
        if r2.status_code != r1.status_code or body2 != _preview(r1.content):
            conclusion = f"IDOR likely: request with {param}={new_value} returned {r2.status_code} with a different response. Verify manually that the data belongs to another user."
        else:
            conclusion = f"Same response as original request. Try a different value for {param} or confirm the endpoint is not IDOR."
    elif r2.status_code in (403, 401):
        conclusion = f"No IDOR: server returned {r2.status_code} when changing {param}. Access control may be enforced."
    else:
        conclusion = f"Request with {param}={new_value} returned {r2.status_code}. Review body_preview to confirm whether data was returned."

    return PoCResult(
        success=True,
        status_code=r2.status_code,
        body_preview=body2,
        conclusion=conclusion,
        poc_type="idor",
    )


def run_unauth_poc(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    cookies: dict | None = None,
) -> PoCResult:
    """Send request without auth; if 200 with body, endpoint may be unauthenticated."""
    if not requests:
        return PoCResult(success=False, error="requests not available", poc_type="unauthenticated")

    url = _norm_url(url)
    if not url:
        return PoCResult(success=False, error="Missing url", poc_type="unauthenticated")

    method = (method or "GET").upper()
    headers = dict(headers or {})
    # Strip common auth headers for the PoC
    for k in list(headers.keys()):
        if k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token"):
            del headers[k]
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; Diverg-PoC/1.0)")

    try:
        r = requests.request(
            method,
            url,
            headers=headers,
            cookies={},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except ReqTimeout:
        return PoCResult(success=False, error=f"Request timed out after {TIMEOUT}s", poc_type="unauthenticated")
    except ReqConnectionError:
        return PoCResult(success=False, error="Could not connect to target — host may be down or unreachable", poc_type="unauthenticated")
    except RequestException as e:
        return PoCResult(success=False, error=f"Request failed: {e}", poc_type="unauthenticated")
    except Exception as e:
        return PoCResult(success=False, error=str(e), poc_type="unauthenticated")

    body = _preview(r.content)
    if r.status_code == 200 and len(body) > 50:
        conclusion = "Endpoint returned 200 with body without auth. Likely unauthenticated or accepting anonymous access. Verify whether the data is sensitive."
    elif r.status_code in (401, 403):
        conclusion = "Server returned %s without auth. Authentication may be required." % r.status_code
    else:
        conclusion = "Request without auth returned %s. Review body_preview." % r.status_code

    return PoCResult(
        success=True,
        status_code=r.status_code,
        body_preview=body,
        conclusion=conclusion,
        poc_type="unauthenticated",
    )


def infer_poc_type_from_finding(finding: dict) -> str:
    """Return 'idor', 'unauthenticated', or '' from finding title/category."""
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    if "idor" in title or "insecure direct object" in title or "object reference" in title or "idor" in category:
        return "idor"
    if "unauthenticated" in title or "no auth" in title or "without auth" in title:
        return "unauthenticated"
    if "access control" in category and ("id" in title or "user" in title or "account" in title):
        return "idor"
    return ""


def run_poc_for_finding(
    finding: dict,
    param_to_change: str | None = None,
    new_value: str = "1",
    cookies: dict | None = None,
) -> PoCResult:
    """
    Run the appropriate PoC based on finding content.
    finding should have: url, title, category, and optionally evidence (for param hints).
    """
    url = (finding.get("url") or "").strip()
    if url and not url.startswith("http"):
        url = "https://" + url

    poc_type = finding.get("poc_type") or infer_poc_type_from_finding(finding)
    if not poc_type:
        return PoCResult(
            success=False,
            error="Could not determine PoC type from finding. Set poc_type to 'idor' or 'unauthenticated' or add a Simulate button only for those categories.",
            poc_type="",
        )

    if poc_type == "idor":
        # Try to get param from evidence or common names
        param = param_to_change
        if not param:
            ev = (finding.get("evidence") or "").lower()
            for p in ("user_id", "userId", "account_id", "order_id", "id", "uid"):
                if p in ev:
                    param = p
                    break
        return run_idor_poc(
            url=url,
            method="GET",
            params=None,
            data=None,
            headers=None,
            param_to_change=param,
            new_value=new_value,
            cookies=cookies,
        )
    if poc_type == "unauthenticated":
        return run_unauth_poc(url=url, method="GET", headers=None, cookies=cookies)

    return PoCResult(success=False, error=f"Unsupported poc_type: {poc_type}", poc_type=poc_type)
