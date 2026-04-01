"""
Heuristic Web3 / wallet-abuse signals for comment-stripped client JS.

These are intelligence hints, not verdicts: severity uses confidence=heuristic.
Correlates with crypto_security TRUST_RISK_PATTERNS where keys/signing appear.

Allowlist: extends client_surface.THIRD_PARTY_ALLOWLIST with common wallet SDK/CDN
hosts. Extend the frozenset when adding vetted vendors; substring match on host.
Authorized scanning only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from client_surface import THIRD_PARTY_ALLOWLIST, Finding

# Substring allowlist on normalized script host (same convention as client_surface).
WALLET_SDK_HOST_FRAGMENTS: frozenset[str] = frozenset(THIRD_PARTY_ALLOWLIST) | frozenset(
    (
        "walletconnect.com",
        "web3modal.com",
        "reown.com",
        "coinbase.com",
        "metamask.io",
        "infura.io",
        "alchemy.com",
        "ankr.com",
        "quicknode.com",
        "ethers.io",
        "rainbow.me",
        "ledger.com",
        "safe.global",
        "gnosis.io",
        "1inch.io",
        "uniswap.org",
    )
)

# RPC / signing (heavy — often legit on first-party; elevated on unknown third-party).
RE_RPC_HEAVY = re.compile(
    r"\beth_sendTransaction\b|\beth_sign\b|\bpersonal_sign\b|signTypedData|wallet_switchEthereumChain",
    re.I,
)
# Token / NFT approval surfaces.
RE_APPROVAL = re.compile(
    r"\.approve\s*\(|increaseAllowance|setApprovalForAll|\.permit\s*\(",
    re.I,
)

# Provider replacement / injection patterns (noisy; stronger off-domain).
RE_PROVIDER_HIJACK = re.compile(
    r"Object\.defineProperty\s*\(\s*window[\s,]|defineProperty\s*\(\s*\w+\s*,\s*['\"]ethereum['\"]|window\.ethereum\s*=",
    re.I,
)

RE_CLIPBOARD_WRITE = re.compile(r"navigator\.clipboard\.writeText", re.I)
RE_WALLET_NEAR_CTX = re.compile(
    r"0x[a-fA-F0-9]{8,}|\bethereum\b|\bsolana\b|\.approve\s*\(|eth_sendTransaction|signTypedData",
    re.I,
)

RE_OBFUSC = re.compile(r"\beval\s*\(|new\s+Function\s*\(", re.I)
RE_WALLET_STRING = re.compile(
    r"ethereum|web3|sendTransaction|signTypedData|\.approve\s*\(|wallet_switchEthereumChain",
    re.I,
)


def _norm_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().replace("www.", "").split(":")[0]
    except Exception:
        return ""


def _script_context(js_url: str, base_origin: str) -> tuple[str, bool, bool]:
    """
    Returns (script_host, is_first_party, is_allowlisted).
    Relative js_url is treated as first-party (same bundle as target).
    """
    base_h = _norm_host(base_origin)
    p = urlparse(js_url)
    if not p.netloc:
        return base_h or "", True, False
    sh = _norm_host(js_url)
    first = bool(base_h) and sh == base_h
    allowlisted = any(frag in sh for frag in WALLET_SDK_HOST_FRAGMENTS)
    return sh, first, allowlisted


def _window_has(haystack: str, pos: int, radius: int, pattern: re.Pattern[str]) -> bool:
    start = max(0, pos - radius)
    end = min(len(haystack), pos + radius)
    return bool(pattern.search(haystack[start:end]))


def analyze_wallet_abuse_js(
    content_stripped: str,
    js_url: str,
    base_origin: str,
    *,
    deep: bool = False,
) -> list[Finding]:
    """Return heuristic findings for wallet-drainer-related patterns in executable JS."""
    findings: list[Finding] = []
    if not content_stripped or not content_stripped.strip():
        return findings

    _host, first_party, allowlisted = _script_context(js_url, base_origin)
    if allowlisted and not first_party:
        return findings

    third_party = not first_party

    has_approval = bool(RE_APPROVAL.search(content_stripped))
    has_rpc_heavy = bool(RE_RPC_HEAVY.search(content_stripped))
    has_hijack = bool(RE_PROVIDER_HIJACK.search(content_stripped))

    # Third-party: approvals or signing cluster → high/medium heuristics.
    if third_party:
        if has_approval:
            findings.append(
                Finding(
                    title="Third-party script contains token approval / permit-style APIs [HEURISTIC]",
                    severity="High",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Matched .approve(, increaseAllowance, setApprovalForAll, or .permit( in "
                        "executable JS from a non-first-party origin. Common in drainers when loaded "
                        "from unknown CDNs or injected scripts."
                    ),
                    impact="Malicious third-party code may trick users into unlimited token approvals or NFT operator rights.",
                    remediation="Audit script supply chain; remove untrusted wallet code; verify approvals target expected contracts.",
                    confidence="heuristic",
                )
            )
        elif has_rpc_heavy:
            findings.append(
                Finding(
                    title="Third-party script contains Ethereum signing / tx RPC methods [HEURISTIC]",
                    severity="Medium",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Matched eth_sendTransaction, eth_sign, personal_sign, signTypedData, or "
                        "wallet_switchEthereumChain in third-party executable JS."
                    ),
                    impact="Off-domain code that drives signing or chain switches can support phishing or drainer flows.",
                    remediation="Load only vetted wallet SDKs from known origins; review why this host serves signing logic.",
                    confidence="heuristic",
                )
            )

        if has_hijack:
            findings.append(
                Finding(
                    title="Third-party script may replace or define window.ethereum [HEURISTIC]",
                    severity="High",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Matched Object.defineProperty on window or window.ethereum assignment pattern "
                        "in third-party JS — possible provider hijack."
                    ),
                    impact="A fake provider can intercept requests and drain funds or harvest approvals.",
                    remediation="Do not load untrusted scripts before wallet interaction; use CSP and integrity attributes.",
                    confidence="heuristic",
                )
            )

        # Noisy co-occurrence / obfuscation hints — deep scan only.
        if deep:
            for m in RE_CLIPBOARD_WRITE.finditer(content_stripped):
                if _window_has(content_stripped, m.start(), 400, RE_WALLET_NEAR_CTX):
                    findings.append(
                        Finding(
                            title="Third-party script: clipboard write near wallet-related strings [HEURISTIC]",
                            severity="Medium",
                            url=js_url,
                            category="Web3 / Wallet Abuse (Heuristic)",
                            evidence=(
                                "navigator.clipboard.writeText appears within ~400 chars of ethereum/solana/"
                                "address/approve/signing-like text in third-party JS."
                            ),
                            impact="Clipboard swapping is used to replace withdrawal addresses in phishing and drainer UIs.",
                            remediation="Verify clipboard usage is user-initiated and not swapping crypto addresses.",
                            confidence="heuristic",
                        )
                    )
                    break

            if RE_OBFUSC.search(content_stripped) and RE_WALLET_STRING.search(content_stripped):
                findings.append(
                    Finding(
                        title="Third-party script: eval/Function with Web3-like strings [HEURISTIC]",
                        severity="Medium",
                        url=js_url,
                        category="Web3 / Wallet Abuse (Heuristic)",
                        evidence=(
                            "Both dynamic code execution (eval/new Function) and Web3-related strings appear "
                            "in the same file — possible packed or obfuscated drainer."
                        ),
                        impact="Obfuscated third-party wallet code is harder to review and often malicious.",
                        remediation="Prefer readable, subresource-integrity–pinned vendor bundles from allowlisted hosts.",
                        confidence="heuristic",
                    )
                )

    # First-party: only deeper scans to reduce noise; never High for routine dApp RPC.
    if first_party and deep:
        if has_approval:
            findings.append(
                Finding(
                    title="App bundle contains token approval / permit-style calls [REVIEW]",
                    severity="Medium",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Matched approval/permit patterns in first-party JS (deep scan). Legitimate for many dApps; "
                        "correlate with product intent."
                    ),
                    impact="If combined with malicious flows elsewhere, approvals can enable draining.",
                    remediation="Ensure UX clearly shows spender and amounts; avoid infinite approvals where possible.",
                    confidence="heuristic",
                )
            )
        if has_rpc_heavy:
            findings.append(
                Finding(
                    title="App bundle contains signing / tx RPC usage [INFO]",
                    severity="Low",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Matched eth_sendTransaction / eth_sign / personal_sign / signTypedData / chain switch "
                        "in first-party JS (deep scan). Expected for many dApps."
                    ),
                    impact="Low alone; useful context when triaging with third-party or trust-risk findings.",
                    remediation="No action if intended; combine with client_surface crypto-trust and supply-chain review.",
                    confidence="heuristic",
                )
            )

        if has_hijack:
            findings.append(
                Finding(
                    title="App bundle defines or replaces ethereum provider [REVIEW]",
                    severity="Medium",
                    url=js_url,
                    category="Web3 / Wallet Abuse (Heuristic)",
                    evidence=(
                        "Provider defineProperty / window.ethereum assignment in first-party JS (deep scan). "
                        "Some wallets inject similarly — verify it is your code."
                    ),
                    impact="Unexpected provider wiring in your bundle could be supply-chain compromise.",
                    remediation="Compare with known-good build; verify no injected hijack in CI artifacts.",
                    confidence="heuristic",
                )
            )

        for m in RE_CLIPBOARD_WRITE.finditer(content_stripped):
            if _window_has(content_stripped, m.start(), 400, RE_WALLET_NEAR_CTX):
                findings.append(
                    Finding(
                        title="App bundle: clipboard write near wallet-related strings [HEURISTIC]",
                        severity="Low",
                        url=js_url,
                        category="Web3 / Wallet Abuse (Heuristic)",
                        evidence=(
                            "clipboard.writeText near wallet-like context in first-party JS (deep scan) — "
                            "verify legitimate copy-to-clipboard UX."
                        ),
                        impact="Same pattern can be abused for address swapping when malicious script is also present.",
                        remediation="Ensure only explicit user actions trigger clipboard writes of addresses.",
                        confidence="heuristic",
                    )
                )
                break

    return findings
