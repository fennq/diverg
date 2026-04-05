"""
Crypto/DeFi site detector — quick analysis to decide if a target is crypto-related
so the orchestrator can run chain-validation and batch-vs-single scans in addition to main scans.

Used by: orchestrator, API, and AI to choose scan profile (main + crypto-specific routes).
Authorized use only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Optional: fetch page if no content provided
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Keywords and patterns that strongly indicate crypto/DeFi/chain
CRYPTO_KEYWORDS = [
    "wallet", "connect wallet", "metamask", "phantom", "walletconnect", "wallets",
    "web3", "web3.js", "ethereum", "solana", "cosmos", "chain",
    "swap", "dex", "defi", "decentralized", "token", "tokens", "nft", "nfts",
    "bridge", "cross-chain", "layerzero", "wormhole", "peggo",
    "stake", "staking", "unstake", "delegate", "validator",
    "rpc", "rpc endpoint", "solana rpc", "priority fee", "jito", "block engine",
    "liquidity", "pool", "lp ", "amm", "order book", "limit order", "market order",
    "subaccount", "subaccountid", "account id", "chain id", "contract address",
    "sign message", "sign transaction", "signature", "signer",
    "tokenfactory", "permissionless", "governance proposal", "dao",
    "blockchain", "on-chain", "explorer", "tx hash", "transaction",
]
# Domain/substring hints (generic DeFi/crypto patterns)
CRYPTO_DOMAIN_HINTS = [
    "uniswap", "sushiswap", "pancake", "raydium", "jupiter",
    "phantom", "metamask", "walletconnect", "opensea", "blur", "magiceden",
    "anchor", "aave", "compound", "lido", "wormhole", "layerzero",
    "cosmos", "osmosis", "sei", "sui", "aptos", "base.org", "zksync",
    "helius", "alchemy", "quicknode", "ankr", "moralis", "chainstack", "blockdaemon", "jito",
    "defi", "crypto", "token", "swap", "bridge", "staking",
]
# Script/API path hints
CRYPTO_PATH_PATTERNS = [
    r"/api/.*wallet", r"/api/.*token", r"/api/.*swap", r"/api/.*order",
    r"/api/.*account", r"/api/.*balance", r"/api/.*transfer",
    r"/api/.*batch", r"/api/.*submit", r"/api/.*sign",
    r"\.etherscan\.|\.solscan\.|\.explorer\.|blockscout",
]

@dataclass
class CryptoDetectionResult:
    is_crypto: bool
    confidence: float  # 0.0–1.0
    signals: list[str] = field(default_factory=list)
    suggested_scan_routes: list[str] = field(default_factory=list)


def _normalize_text(s: str) -> str:
    return " " + (s or "").lower() + " "


def detect_from_content(html_or_js: str, url: str = "") -> CryptoDetectionResult:
    """
    Analyze HTML/JS (and optionally URL) to determine if the site is crypto-related.
    Returns is_crypto, confidence, and list of signals.
    """
    text = _normalize_text(html_or_js)
    url_lower = (url or "").lower()
    domain = url_lower
    try:
        domain = urlparse(url or "").netloc.lower()
    except Exception:
        pass

    signals: list[str] = []
    score = 0.0

    # Domain hints
    for hint in CRYPTO_DOMAIN_HINTS:
        if hint in domain:
            signals.append(f"domain hint: {hint}")
            score += 0.2

    # Keyword hits in content
    for kw in CRYPTO_KEYWORDS:
        if kw in text:
            signals.append(f"content: {kw}")
            score += 0.04

    # Path patterns in content (e.g. API paths mentioned in JS)
    for pat in CRYPTO_PATH_PATTERNS:
        if re.search(pat, text):
            signals.append(f"path pattern: {pat}")
            score += 0.06

    # Strong signals (single hit can push to crypto)
    strong = [
        "connect wallet", "walletconnect", "metamask", "phantom",
        "subaccount", "msgbatch", "validatebasic", "chain id",
        "sign transaction", "sign message", "web3",
    ]
    for s in strong:
        if s in text:
            signals.append(f"strong: {s}")
            score += 0.2

    # Cap and normalize confidence
    confidence = min(1.0, score)
    if confidence < 0.12:
        confidence = 0.0
    is_crypto = confidence >= 0.2

    # Suggested scan routes from content/diverg-batch-validation-routes.md
    suggested_scan_routes: list[str] = []
    if is_crypto:
        suggested_scan_routes = [
            "batch_vs_single_validation",
            "account_subaccount_id_substitution",
            "parameter_trust_body_header",
            "payment_financial",
            "workflow_probe",
            "api_test",
            "high_value_flaws",
            "crypto_security",
        ]

    return CryptoDetectionResult(
        is_crypto=is_crypto,
        confidence=round(confidence, 2),
        signals=signals[:25],
        suggested_scan_routes=suggested_scan_routes,
    )


def detect_from_url(target_url: str, fetch: bool = True) -> CryptoDetectionResult:
    """
    Optionally fetch the page and run detection. If fetch is False or requests
    unavailable, only URL/domain is used.
    """
    url_lower = (target_url or "").lower()
    domain = url_lower
    try:
        domain = urlparse(target_url or "").netloc.lower()
    except Exception:
        pass

    content = ""
    if fetch and HAS_REQUESTS:
        try:
            r = requests.get(
                target_url if target_url.startswith("http") else "https://" + target_url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (compatible; Diverg/1.0)"},
            )
            if r.ok:
                content = r.text[:200000]  # cap size
        except Exception:
            pass

    return detect_from_content(content, target_url)


def is_crypto_site(target_url: str, min_confidence: float = 0.2) -> bool:
    """Convenience: True if site is classified as crypto with at least min_confidence."""
    result = detect_from_url(target_url, fetch=True)
    return result.is_crypto and result.confidence >= min_confidence
