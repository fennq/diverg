"""
Blockchain investigation skill — detect potential crime on-chain and on launchpads.

Methodology aligned with Diverg blockchain standard (see content/diverg_blockchain_methodology.txt):
- Timestamps: transfers ordered by block_time; report dates (YYYY-MM-DD) for every key event.
- CEX/mixer tagging: label exchange/mixer counterparties; funds to CEX = compliance exposure.
- Multi-hop: primary wallet + counterparties (and optional 1-hop further) for full flow.
- Announcement vs on-chain: correlate launch/announcement date with first LP/buy/dump.
- Evidence links: Solscan/Arkham/Etherscan URLs for addresses and txs where possible.

For platforms like liquid.af (launchpad / token creation):
- Sniper detection: same wallet(s) buying at launch across many tokens (insider/front-running).
- Liquidity pull: LP removed or drained after launch (rug pull).
- Fee extraction: high or opaque fees per tx; stated vs on-chain comparison.
- Wallet / entity intel: Solscan (transfers, holders, defi activities), Arkham (labels).
- Multi-chain: Solana (Solscan), Ethereum (Etherscan stub).

Requires SOLSCAN_PRO_API_KEY (Solana) or ETHERSCAN_API_KEY (Ethereum) plus ARKHAM_API_KEY for on-chain checks.
FRONTRUNPRO_API_KEY + FRONTRUNPRO_BASE_URL optional for
FrontrunPro (linked wallets, KOL follow list, CA history — paid API; see investigation/frontrunpro_client.py).
Authorized use only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "investigation"))
from arkham_intel import evm_chain_slug_for_arkham, intel_batch, intel_counterparties, legacy_label
from stealth import get_session

SESSION = get_session()
TIMEOUT = 12
RUN_BUDGET_SEC = 55
SOLSCAN_BASE = "https://pro-api.solscan.io/v2.0"

# EVM explorer: prefer Etherscan API v2 multichain (single ETHERSCAN_API_KEY). Fallback BscScan for BSC.
EVM_CHAIN_META: dict[str, tuple[int, str]] = {
    "ethereum": (1, "https://etherscan.io"),
    "bsc": (56, "https://bscscan.com"),
    "polygon": (137, "https://polygonscan.com"),
    "base": (8453, "https://basescan.org"),
    "arbitrum": (42161, "https://arbiscan.io"),
    "optimism": (10, "https://optimistic.etherscan.io"),
    "avalanche": (43114, "https://snowtrace.io"),
}
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"
ETHERSCAN_BASE = "https://api.etherscan.io/api"  # legacy v1

# Known EVM bridge contract addresses (lowercase) → human-readable label.
# Used to detect when an address interacts with bridge protocols.
EVM_BRIDGE_CONTRACTS: dict[str, str] = {
    # Wormhole — Ethereum
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": "Wormhole Token Bridge (ETH)",
    "0x98f3c9e6e3face36baad05fe09d375ef1464288b": "Wormhole Core (ETH)",
    # deBridge DLN — Ethereum
    "0xef4fb24ad0916217251f553c0596f8edc630eb66": "deBridge DLN (ETH)",
    # LayerZero Endpoint v1 — Ethereum
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": "LayerZero Endpoint v1 (ETH)",
    # LayerZero Endpoint v2 — Ethereum
    "0x1a44076050125825900e736c501f859c50fe728c": "LayerZero Endpoint v2 (ETH)",
    # Mayan Swift — Ethereum
    "0xc38e4e6a15593f908255214653d3d947ca1c2338": "Mayan Swift Bridge (ETH)",
    # Wormhole — BSC
    "0xb6f6d86a8f9879a9c87f18830f2de421cd3923c0": "Wormhole Token Bridge (BSC)",
    # deBridge DLN — BSC
    "0x0fa205c0446cd9eedc7b4d4e0c11254eb28b11ce": "deBridge DLN (BSC)",
    # LayerZero Endpoint v1 — BSC
    "0x3c2269811836af69497e5f486a85d7316753cf62": "LayerZero Endpoint v1 (BSC)",
    # Wormhole — Polygon
    "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde": "Wormhole Token Bridge (Polygon)",
    # LayerZero Endpoint v1 — Polygon
    "0x3c2269811836af69497e5f486a85d7316753cf62": "LayerZero Endpoint v1 (Polygon)",
    # Wormhole — Arbitrum
    "0x0b2402144bb366a632d14b83f244d2e0e21bd39c": "Wormhole Token Bridge (Arbitrum)",
    # LayerZero Endpoint v1 — Arbitrum
    "0x3c2269811836af69497e5f486a85d7316753cf62": "LayerZero Endpoint v1 (Arbitrum)",
    # Wormhole — Base
    "0x8d2de8d2f73f1f4cab472ac9a881c9b123c79627": "Wormhole Token Bridge (Base)",
    # Stargate Finance Router — Ethereum (widely-used bridge aggregator)
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": "Stargate Finance Router (ETH)",
}

_MIXER_INTEL_FILE = Path(__file__).resolve().parent.parent / "investigation" / "mixer_service_intel.json"
_MIXER_TIER_RANK = {
    "unverified_candidate": 0,
    "verified_analytics": 1,
    "verified_primary": 2,
}


def _mixer_min_tier_rank() -> int:
    raw = (os.environ.get("DIVERG_MIXER_MIN_TIER") or "verified_analytics").strip().lower()
    return _MIXER_TIER_RANK.get(raw, _MIXER_TIER_RANK["verified_analytics"])


def _load_mixer_intel() -> tuple[dict[str, str], dict[str, str], tuple[str, ...]]:
    """
    Load known mixer/privacy service intel.
    Returns (evm_contract_map, evm_wallet_map, label_markers).
    """
    contracts: dict[str, str] = {}
    wallets: dict[str, str] = {}
    markers: list[str] = []
    min_rank = _mixer_min_tier_rank()
    try:
        if _MIXER_INTEL_FILE.is_file():
            raw = json.loads(_MIXER_INTEL_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                c = raw.get("evm_contracts")
                if isinstance(c, dict):
                    for k, v in c.items():
                        kk = str(k).strip().lower()
                        if kk.startswith("0x") and len(kk) == 42:
                            if isinstance(v, dict):
                                tier = str(v.get("tier") or "unverified_candidate").strip().lower()
                                if _MIXER_TIER_RANK.get(tier, 0) >= min_rank:
                                    contracts[kk] = str(v.get("service") or "Mixer/Privacy Service")[:120]
                            else:
                                # Backward-compatible string entries are treated as verified intel.
                                contracts[kk] = str(v or "Mixer/Privacy Service")[:120]
                w = raw.get("evm_wallets")
                if isinstance(w, dict):
                    for svc, addrs in w.items():
                        if isinstance(addrs, list):
                            for a in addrs:
                                if isinstance(a, dict):
                                    aa = str(a.get("address") or "").strip().lower()
                                    tier = str(a.get("tier") or "unverified_candidate").strip().lower()
                                    label = str(a.get("service") or svc or "Mixer/Privacy Wallet")[:120]
                                    if aa.startswith("0x") and len(aa) == 42 and _MIXER_TIER_RANK.get(tier, 0) >= min_rank:
                                        wallets[aa] = label
                                else:
                                    aa = str(a).strip().lower()
                                    if aa.startswith("0x") and len(aa) == 42:
                                        wallets[aa] = str(svc or "Mixer/Privacy Wallet")[:120]
                elif isinstance(w, list):
                    for a in w:
                        if isinstance(a, dict):
                            aa = str(a.get("address") or "").strip().lower()
                            tier = str(a.get("tier") or "unverified_candidate").strip().lower()
                            label = str(a.get("service") or "Mixer/Privacy Wallet")[:120]
                            if aa.startswith("0x") and len(aa) == 42 and _MIXER_TIER_RANK.get(tier, 0) >= min_rank:
                                wallets[aa] = label
                        else:
                            aa = str(a).strip().lower()
                            if aa.startswith("0x") and len(aa) == 42:
                                wallets[aa] = "Mixer/Privacy Wallet"
                m = raw.get("label_markers")
                if isinstance(m, list):
                    for x in m:
                        if isinstance(x, dict):
                            marker = str(x.get("marker") or "").strip().lower()
                            tier = str(x.get("tier") or "unverified_candidate").strip().lower()
                            if marker and _MIXER_TIER_RANK.get(tier, 0) >= min_rank:
                                markers.append(marker)
                        elif x is not None and str(x).strip():
                            markers.append(str(x).strip().lower())
    except Exception:
        pass

    # Environment override/extension for urgent intel updates
    extra_env = (os.environ.get("DIVERG_MIXER_LABEL_MARKERS") or "").strip()
    if extra_env:
        markers.extend([s.strip().lower() for s in extra_env.split(",") if s.strip()])

    # Optional explicit address list via env (comma-separated EVM addresses)
    extra_addr_env = (os.environ.get("DIVERG_KNOWN_MIXER_EVM") or "").strip()
    if extra_addr_env:
        for a in extra_addr_env.split(","):
            t = a.strip().lower()
            if t.startswith("0x") and len(t) == 42:
                contracts.setdefault(t, "Mixer/Privacy Service (env)")

    # Optional explicit mixer wallet address list via env (comma-separated EVM addresses)
    extra_wallet_env = (os.environ.get("DIVERG_KNOWN_MIXER_EVM_WALLETS") or "").strip()
    if extra_wallet_env:
        for a in extra_wallet_env.split(","):
            t = a.strip().lower()
            if t.startswith("0x") and len(t) == 42:
                wallets.setdefault(t, "Mixer/Privacy Wallet (env)")

    return contracts, wallets, tuple(dict.fromkeys(markers))


KNOWN_MIXER_EVM_CONTRACTS, KNOWN_MIXER_EVM_WALLETS, KNOWN_MIXER_LABEL_MARKERS = _load_mixer_intel()


def _normalize_evm_chain_slug(chain: str) -> str:
    c = (chain or "solana").strip().lower()
    aliases = {"bnb": "bsc", "matic": "polygon", "arb": "arbitrum", "op": "optimism", "avax": "avalanche", "eth": "ethereum"}
    return aliases.get(c, c)


def _is_evm_chain(chain: str) -> bool:
    return _normalize_evm_chain_slug(chain) in EVM_CHAIN_META


def _evm_v2_get(session: requests.Session, chain_slug: str, params: dict, api_key: str) -> dict | None:
    slug = _normalize_evm_chain_slug(chain_slug)
    if slug not in EVM_CHAIN_META:
        return None
    chain_id, _ = EVM_CHAIN_META[slug]
    q = {"chainid": chain_id, "apikey": api_key, **params}
    try:
        r = session.get(ETHERSCAN_V2_API, params=q, timeout=TIMEOUT)
        if r.ok:
            j = r.json()
            if j.get("status") == "1" and "result" in j:
                return j
    except Exception:
        pass
    if slug == "bsc":
        bkey = (os.environ.get("BSCSCAN_API_KEY") or "").strip()
        if bkey:
            try:
                q2 = {**params, "apikey": bkey}
                r2 = session.get("https://api.bscscan.com/api", params=q2, timeout=TIMEOUT)
                if r2.ok:
                    j2 = r2.json()
                    if j2.get("status") == "1" and "result" in j2:
                        return j2
            except Exception:
                pass
    return None


def _evm_token_transfers(session: requests.Session, token_contract: str, chain_slug: str, api_key: str, limit: int = 20) -> list:
    j = _evm_v2_get(
        session,
        chain_slug,
        {"module": "account", "action": "tokentx", "contractaddress": token_contract, "page": 1, "offset": limit, "sort": "asc"},
        api_key,
    )
    if not j or "result" not in j:
        return []
    res = j["result"]
    return res if isinstance(res, list) else []


def _evm_account_txlist(session: requests.Session, address: str, chain_slug: str, api_key: str, page_size: int = 30) -> list:
    j = _evm_v2_get(
        session,
        chain_slug,
        {"module": "account", "action": "txlist", "address": address, "page": 1, "offset": page_size, "sort": "desc"},
        api_key,
    )
    if not j or "result" not in j:
        return []
    res = j["result"]
    return res if isinstance(res, list) else []


def _explorer_host_for_chain(chain_slug: str) -> str:
    slug = _normalize_evm_chain_slug(chain_slug)
    if slug in EVM_CHAIN_META:
        return EVM_CHAIN_META[slug][1]
    return "https://etherscan.io"


def _evm_detect_mixer_hits(txlist: list[dict[str, Any]], chain_slug: str) -> list[dict[str, Any]]:
    """Detect interactions with known mixer/privacy contracts in EVM tx list."""
    host = _explorer_host_for_chain(chain_slug)
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for tx in txlist:
        tx_hash = str(tx.get("hash") or "").strip()
        if not tx_hash:
            continue
        to_addr = str(tx.get("to") or "").strip().lower()
        from_addr = str(tx.get("from") or "").strip().lower()

        if to_addr in KNOWN_MIXER_EVM_CONTRACTS:
            key = (tx_hash, to_addr, "outgoing")
            if key not in seen:
                seen.add(key)
                hits.append(
                    {
                        "tx_hash": tx_hash,
                        "counterparty": to_addr,
                        "service": KNOWN_MIXER_EVM_CONTRACTS[to_addr],
                        "direction": "outgoing",
                        "timestamp": tx.get("timeStamp", ""),
                        "value_eth": tx.get("value", "0"),
                        "explorer_url": f"{host}/tx/{tx_hash}",
                    }
                )
        elif to_addr in KNOWN_MIXER_EVM_WALLETS:
            key = (tx_hash, to_addr, "outgoing")
            if key not in seen:
                seen.add(key)
                hits.append(
                    {
                        "tx_hash": tx_hash,
                        "counterparty": to_addr,
                        "service": KNOWN_MIXER_EVM_WALLETS[to_addr],
                        "direction": "outgoing",
                        "timestamp": tx.get("timeStamp", ""),
                        "value_eth": tx.get("value", "0"),
                        "explorer_url": f"{host}/tx/{tx_hash}",
                    }
                )
        if from_addr in KNOWN_MIXER_EVM_CONTRACTS:
            key = (tx_hash, from_addr, "incoming")
            if key not in seen:
                seen.add(key)
                hits.append(
                    {
                        "tx_hash": tx_hash,
                        "counterparty": from_addr,
                        "service": KNOWN_MIXER_EVM_CONTRACTS[from_addr],
                        "direction": "incoming",
                        "timestamp": tx.get("timeStamp", ""),
                        "value_eth": tx.get("value", "0"),
                        "explorer_url": f"{host}/tx/{tx_hash}",
                    }
                )
        elif from_addr in KNOWN_MIXER_EVM_WALLETS:
            key = (tx_hash, from_addr, "incoming")
            if key not in seen:
                seen.add(key)
                hits.append(
                    {
                        "tx_hash": tx_hash,
                        "counterparty": from_addr,
                        "service": KNOWN_MIXER_EVM_WALLETS[from_addr],
                        "direction": "incoming",
                        "timestamp": tx.get("timeStamp", ""),
                        "value_eth": tx.get("value", "0"),
                        "explorer_url": f"{host}/tx/{tx_hash}",
                    }
                )
    return hits


def _summarize_service_hits(hits: list[dict[str, Any]], key: str = "service") -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for h in hits:
        svc = str(h.get(key) or "").strip()
        if svc:
            counts[svc] = counts.get(svc, 0) + 1
    return [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


# Platform identifiers for launchpad / token-creation sites
LAUNCHPAD_DOMAINS = (
    "liquid.af",
    "pump.fun",
    "pumps.fun",
    "raydium.io",
    "bonk.fun",
    "letsbonk",
    "meteora",
    "launchpad",
    "fairlaunch",
    "moonshot",
    "dexscreener",
)
# Fee/sniper/liquidity keywords in page content
FEE_PATTERNS = [
    re.compile(r"(\d+(?:\.\d+)?)\s*%\s*(?:fee|commission|tax)", re.I),
    re.compile(r"fee[s]?\s*[:\s]+(\d+(?:\.\d+)?)\s*%", re.I),
    re.compile(r"(\d+)\s*bps?\b", re.I),
    re.compile(r"transaction\s*(?:fee|tax)\s*[:\s]*(\d+(?:\.\d+)?)", re.I),
]
TOKEN_MINT_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")  # Solana base58-like
PROGRAM_ID_RE = re.compile(r"Program\s*(?:id|Id)?\s*[:\s]*([1-9A-HJ-NP-Za-km-z]{32,44})", re.I)

# Known CEX/mixer addresses (optional): tag as counterparty in flow graph. Extend via env DIVERG_KNOWN_CEX_MIXER (comma-separated).
_known_cex_mixer_raw = (os.environ.get("DIVERG_KNOWN_CEX_MIXER") or "").strip()
KNOWN_CEX_MIXER_ADDRESSES = {a.strip().lower() for a in _known_cex_mixer_raw.split(",") if a.strip()}


@dataclass
class Finding:
    title: str
    severity: str
    url: str
    category: str
    evidence: str
    impact: str
    remediation: str
    confidence: str = "medium"   # "high" | "medium" | "low"
    source: str = ""             # e.g. "helius_rpc", "arkham_api", "solscan", "header_analysis"
    proof: str = ""              # raw artifact: tx hash, API response snippet, header value
    verified: bool = False       # True if cross-checked against a second data source


@dataclass
class BlockchainInvestigationReport:
    target_url: str
    platform_type: str  # launchpad | exchange | unknown
    chain: str = "solana"  # solana | ethereum
    crypto_relation: str | None = None  # launchpad | exchange | dex | wallet | defi | nft | bridge | crypto-general (from Diverg profile)
    findings: list[Finding] = field(default_factory=list)
    tokens_discovered: list[str] = field(default_factory=list)
    wallet_labels: dict[str, str] = field(default_factory=dict)
    sniper_alerts: list[dict] = field(default_factory=list)
    liquidity_alerts: list[dict] = field(default_factory=list)
    fee_alerts: list[dict] = field(default_factory=list)
    fee_comparison: dict | None = None  # {"stated_pct": float, "on_chain_pct": float | None, "evidence": str}
    on_chain_used: bool = False
    errors: list[str] = field(default_factory=list)
    # Crime-report fields: risk score 0-100, structured report, linked wallets (counterparties + holders)
    risk_score: float = 0.0
    crime_report: dict | None = None  # summary, deployer_section, tokens_section, findings_with_evidence, flow_highlights, linked_wallets
    linked_wallets: list[dict] = field(default_factory=list)  # [{"address", "label", "source": "counterparty"|"holder"}, ...]
    counterparties: list[dict] = field(default_factory=list)  # [{"address", "name"}, ...] from Arkham
    deployer_address: str | None = None  # set in run() for crime report
    # Flow graph for Diverg report diagram: nodes (id, label, type), edges (from, to, amount, unit, date_str, count)
    flow_graph: dict | None = None  # {"nodes": [...], "edges": [...]}
    cross_chain: dict | None = None  # registry + CoinGecko hints
    evm_bridge_hits: list[dict] = field(default_factory=list)  # EVM bridge contract interactions
    evm_mixer_hits: list[dict] = field(default_factory=list)  # EVM mixer/privacy contract interactions


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


def _normalize_confidence(value: str | None) -> str:
    conf = str(value or "").strip().lower()
    if conf in {"high", "medium", "low"}:
        return conf
    return ""


def _default_finding_source(finding: Finding) -> str:
    title = (finding.title or "").lower()
    category = (finding.category or "").lower()
    if "arkham" in title or "arkham" in category:
        return "arkham_api"
    if "etherscan" in title or "ethereum" in category:
        return "etherscan_api"
    if "config" in category:
        return "config_check"
    if any(
        key in title
        for key in (
            "launchpad-style platform detected",
            "platform mentions",
            "fee / tax mention on platform",
        )
    ):
        return "web_scrape"
    return "analysis"


def _default_finding_confidence(finding: Finding, source: str) -> str:
    severity = str(finding.severity or "").strip().lower()
    if source in {"solscan_api", "etherscan_api", "arkham_api", "helius_rpc", "config_check"}:
        return "high"
    if source == "web_scrape":
        return "medium" if severity in {"high", "medium"} else "low"
    if severity in {"high", "medium"}:
        return "medium"
    return "low"


def _finalize_finding(finding: Finding) -> Finding:
    source = (finding.source or "").strip() or _default_finding_source(finding)
    confidence = _normalize_confidence(finding.confidence) or _default_finding_confidence(finding, source)
    proof = (finding.proof or "").strip() or (finding.evidence or "")[:280]
    verified = bool(finding.verified)
    if source == "config_check":
        verified = True
    return Finding(
        title=finding.title,
        severity=finding.severity,
        url=finding.url,
        category=finding.category,
        evidence=finding.evidence,
        impact=finding.impact,
        remediation=finding.remediation,
        confidence=confidence,
        source=source,
        proof=proof,
        verified=verified,
    )


def _finalize_findings(findings: list[Finding]) -> list[Finding]:
    return [_finalize_finding(f) for f in findings]


def _build_evidence_summary(findings: list[Finding]) -> dict:
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    sources: dict[str, int] = defaultdict(int)
    verified_count = 0
    for finding in findings:
        conf = _normalize_confidence(finding.confidence) or "medium"
        confidence_counts[conf] += 1
        source = (finding.source or "unknown").strip() or "unknown"
        sources[source] += 1
        if finding.verified:
            verified_count += 1
    total = len(findings)
    verified_ratio = round((verified_count / total), 2) if total else 0.0
    if confidence_counts["high"] >= 3 or verified_ratio >= 0.5:
        quality = "strong"
    elif confidence_counts["high"] >= 1 or confidence_counts["medium"] >= 3:
        quality = "moderate"
    else:
        quality = "limited"
    return {
        "total_findings": total,
        "confidence_counts": confidence_counts,
        "verified_count": verified_count,
        "unverified_count": max(0, total - verified_count),
        "verified_ratio": verified_ratio,
        "source_breakdown": dict(sorted(sources.items(), key=lambda item: (-item[1], item[0]))),
        "top_sources": [name for name, _count in sorted(sources.items(), key=lambda item: (-item[1], item[0]))[:5]],
        "quality": quality,
    }


def _severity_rank(severity: str) -> int:
    sev = str(severity or "").strip().lower()
    if sev == "critical":
        return 4
    if sev == "high":
        return 3
    if sev == "medium":
        return 2
    if sev == "low":
        return 1
    return 0


def _finding_risk_weight(finding: Finding) -> float:
    severity_weight = {"critical": 25.0, "high": 18.0, "medium": 10.0, "low": 4.0, "info": 0.0}
    confidence_weight = {"high": 1.0, "medium": 0.72, "low": 0.45}
    sev = str(finding.severity or "Info").strip().lower()
    conf = _normalize_confidence(finding.confidence) or "medium"
    base = severity_weight.get(sev, 0.0)
    multiplier = confidence_weight.get(conf, confidence_weight["medium"])
    if finding.verified and base > 0:
        multiplier *= 1.15
    elif base > 0:
        multiplier *= 0.9
    source = (finding.source or "").strip().lower()
    if source in {"web_scrape", "analysis"} and conf != "high":
        multiplier *= 0.9
    return base * multiplier


def _detect_platform(target_url: str) -> str:
    try:
        domain = urlparse(target_url).netloc.lower().replace("www.", "")
    except Exception:
        return "unknown"
    if any(l in domain for l in LAUNCHPAD_DOMAINS):
        return "launchpad"
    if any(k in domain for k in ("swap", "dex", "exchange", "trade")):
        return "exchange"
    return "unknown"


def _scrape_for_tokens_and_fees(session: requests.Session, target_url: str, run_start: float) -> dict:
    out = {"tokens": [], "fee_mentions": [], "program_id": None, "deployer_hints": [], "sniper_mentions": []}
    try:
        r = session.get(target_url, timeout=TIMEOUT)
        if not r.ok:
            return out
        text = r.text
        # Fee patterns
        for pat in FEE_PATTERNS:
            for m in pat.finditer(text):
                out["fee_mentions"].append(m.group(0).strip()[:80])
        # Program ID
        for m in PROGRAM_ID_RE.finditer(text):
            out["program_id"] = m.group(1)
            break
        # Token-like addresses (many false positives; cap)
        candidates = list(set(TOKEN_MINT_RE.findall(text)))
        for c in candidates[:30]:
            if len(c) >= 32 and len(c) <= 44:
                out["tokens"].append(c)
        # Sniper / bot mentions (investigation relevance)
        if re.search(r"sniper|first\s*block|frontrun|insider\s*buy|launch\s*bot", text, re.I):
            out["sniper_mentions"].append("Page mentions sniper/first-block/insider or launch bot.")
        if re.search(r"liquidity\s*(?:pull|remove|withdraw)|rug\s*pull|drain", text, re.I):
            out["liquidity_mentions"] = ["Page mentions liquidity pull or rug."]
    except Exception as e:
        out["errors"] = [str(e)]
    return out


def _solscan_get(
    session: requests.Session,
    path: str,
    params: dict,
    api_key: str,
) -> dict | None:
    """GET Solscan API with one retry on 429 to keep flow going."""
    url = f"{SOLSCAN_BASE.rstrip('/')}/{path.lstrip('/')}"
    headers = {"token": api_key}
    for attempt in range(2):
        try:
            r = session.get(url, params=params, headers=headers, timeout=TIMEOUT)
            if r.status_code == 401:
                return None
            if r.status_code == 429:
                if attempt == 0:
                    time.sleep(2.0)
                    continue
                return None
            if r.ok:
                return r.json()
            return None
        except Exception:
            if attempt == 0:
                time.sleep(1.0)
                continue
            return None
    return None


def _solscan_account_transfers(
    session: requests.Session,
    address: str,
    api_key: str,
    from_time: int | None = None,
    to_time: int | None = None,
    page_size: int = 20,
) -> list:
    params = {"address": address, "page_size": page_size, "sort_by": "block_time", "sort_order": "desc"}
    if from_time is not None:
        params["from_time"] = from_time
    if to_time is not None:
        params["to_time"] = to_time
    data = _solscan_get(session, "account/transfer", params, api_key)
    if not data or "data" not in data:
        return []
    return data.get("data", []) if isinstance(data["data"], list) else []


def _solscan_token_holders(
    session: requests.Session,
    token_mint: str,
    api_key: str,
    limit: int = 20,
) -> list:
    data = _solscan_get(
        session,
        "token/holders",
        {"token_address": token_mint, "page_size": limit},
        api_key,
    )
    if not data or "data" not in data:
        return []
    return data.get("data", []) if isinstance(data["data"], list) else []


def _solscan_token_transfers(
    session: requests.Session,
    token_mint: str,
    api_key: str,
    page_size: int = 20,
    sort_order: str = "asc",  # asc = earliest first (for sniper: first-block buys)
) -> list:
    """Get SPL token transfers for a mint. sort_order=asc gives earliest first for sniper window."""
    data = _solscan_get(
        session,
        "token/transfer",
        {"address": token_mint, "page_size": page_size, "sort_by": "block_time", "sort_order": sort_order},
        api_key,
    )
    if not data or "data" not in data:
        return []
    return data.get("data", []) if isinstance(data["data"], list) else []


def _solscan_account_defi_activities(
    session: requests.Session,
    address: str,
    api_key: str,
    activity_types: list[str] | None = None,
    page_size: int = 30,
) -> list:
    """Get DeFi activities (e.g. add/remove liquidity) for an account."""
    params = {"address": address, "page_size": page_size, "sort_by": "block_time", "sort_order": "desc"}
    if activity_types:
        params["activity_type"] = activity_types  # e.g. ["ACTIVITY_TOKEN_REMOVE_LIQ"]
    data = _solscan_get(session, "account/defi/activities", params, api_key)
    if not data or "data" not in data:
        return []
    return data.get("data", []) if isinstance(data["data"], list) else []


def _solscan_token_meta(session: requests.Session, token_mint: str, api_key: str) -> dict | None:
    """Token metadata: mint_authority, freeze_authority (rug/honeypot signals if still active)."""
    data = _solscan_get(session, "token/meta", {"address": token_mint}, api_key)
    if not isinstance(data, dict):
        return None
    if "data" in data and isinstance(data["data"], dict):
        return data["data"]
    return data


def _solscan_account_balance_change(
    session: requests.Session,
    address: str,
    api_key: str,
    flow: str = "out",
    page_size: int = 15,
) -> list:
    """Balance change activities (flow=out for outflows / dumps)."""
    data = _solscan_get(
        session,
        "account/balance_change",
        {"address": address, "flow": flow, "page_size": page_size, "sort_by": "block_time", "sort_order": "desc"},
        api_key,
    )
    if not data or "data" not in data:
        return []
    return data.get("data", []) if isinstance(data["data"], list) else []


# --- Stated fee extraction from scraped text (e.g. "5% fee", "100 bps") ---
STATED_FEE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*(?:fee|commission|tax)", re.I)
STATED_FEE_BPS_RE = re.compile(r"(\d+)\s*bps?\b", re.I)


def _extract_stated_fee_pct(fee_mentions: list[str]) -> float | None:
    """Extract first numeric fee % from fee mentions. 100 bps -> 1%."""
    for s in fee_mentions:
        m = STATED_FEE_RE.search(s)
        if m:
            return float(m.group(1))
        m = STATED_FEE_BPS_RE.search(s)
        if m:
            return float(m.group(1)) / 100.0
    return None


# --- Etherscan (Ethereum) ---
def _etherscan_get(session: requests.Session, params: dict, api_key: str) -> dict | None:
    params = {**params, "apikey": api_key}
    try:
        r = session.get(ETHERSCAN_BASE, params=params, timeout=TIMEOUT)
        if r.ok:
            j = r.json()
            if j.get("status") == "1" and "result" in j:
                return j
    except Exception:
        pass
    return None


def _etherscan_token_transfers(
    session: requests.Session,
    token_contract: str,
    api_key: str,
    limit: int = 20,
) -> list:
    """Get ERC-20 token transfers for a contract. Returns list of tx (to, from, value, timeStamp)."""
    j = _etherscan_get(
        session,
        {"module": "account", "action": "tokentx", "contractaddress": token_contract, "page": 1, "offset": limit, "sort": "asc"},
        api_key,
    )
    if not j or "result" not in j:
        return []
    res = j["result"]
    return res if isinstance(res, list) else []


def _etherscan_account_defi_style(session: requests.Session, address: str, api_key: str, page_size: int = 30) -> list:
    """Normal tx list for address (Ethereum has no single 'defi activities' endpoint; we use txlist)."""
    j = _etherscan_get(
        session,
        {"module": "account", "action": "txlist", "address": address, "page": 1, "offset": page_size, "sort": "desc"},
        api_key,
    )
    if not j or "result" not in j:
        return []
    res = j["result"]
    return res if isinstance(res, list) else []


def _heuristic_sniper(
    transfers_by_token: dict[str, list],
    same_wallet_min_tokens: int = 3,
) -> list[dict]:
    wallet_to_tokens = defaultdict(set)
    for token, txs in transfers_by_token.items():
        for t in txs[:15]:
            to_addr = (t.get("to_address") or t.get("to") or t.get("destination") or "").strip()
            if to_addr and to_addr != token:
                wallet_to_tokens[to_addr].add(token)
    alerts = []
    for wallet, tokens in wallet_to_tokens.items():
        if len(tokens) >= same_wallet_min_tokens:
            alerts.append({
                "wallet": wallet,
                "tokens_bought_early": list(tokens)[:10],
                "count": len(tokens),
                "description": f"Same wallet bought in early window across {len(tokens)} tokens (possible sniper).",
            })
    return alerts


def _heuristic_concentrated_holders(holders: list[dict], top_n: int = 10, threshold_pct: float = 40.0) -> list[dict]:
    alerts = []
    if not holders:
        return alerts
    total = sum(float(h.get("amount", 0) or h.get("balance", 0)) for h in holders)
    if total <= 0:
        return alerts
    top = holders[:top_n]
    top_amount = sum(float(h.get("amount", 0) or h.get("balance", 0)) for h in top)
    pct = (top_amount / total) * 100
    if pct >= threshold_pct:
        alerts.append({
            "top_n": top_n,
            "percentage": round(pct, 1),
            "description": f"Top {top_n} holders control {pct:.1f}% of supply (rug/coordinated dump risk).",
        })
    return alerts


def _compute_risk_score(report: BlockchainInvestigationReport) -> float:
    """Aggregate risk 0-100 from findings and alerts. Higher = more likely fraud/rug."""
    score = 0.0
    for f in report.findings:
        score += _finding_risk_weight(f)
    # Explicit risk signals (avoid double-counting with severity)
    for a in report.liquidity_alerts:
        if "remove" in str(a).lower() or "REMOVE_LIQ" in str(a):
            score += 22
        else:
            score += 12  # concentration
    if report.sniper_alerts:
        score += 20
    if report.counterparties:
        score += 5  # known counterparties (CEX/OTC) = traceability, slight risk if deployer
    evidence_summary = _build_evidence_summary(report.findings)
    if evidence_summary.get("quality") == "limited":
        score *= 0.82
    elif evidence_summary.get("quality") == "moderate":
        score *= 0.92
    if evidence_summary.get("verified_count", 0) >= 3:
        score += 4
    return min(100.0, round(score, 1))


def _explorer_url_address(address: str, chain: str = "solana") -> str:
    """Explorer URL for an address so evidence is one-click verifiable (Diverg standard)."""
    if not (address or "").strip():
        return ""
    addr = address.strip()
    ch = (chain or "solana").lower()
    if _is_evm_chain(ch):
        host = _explorer_host_for_chain(ch)
        return f"{host}/address/{addr}"
    return f"https://solscan.io/account/{addr}"


def _explorer_url_tx(tx_hash: str, chain: str = "solana") -> str:
    """Explorer URL for a transaction."""
    if not (tx_hash or "").strip():
        return ""
    h = tx_hash.strip()
    ch = (chain or "solana").lower()
    if _is_evm_chain(ch):
        host = _explorer_host_for_chain(ch)
        return f"{host}/tx/{h}"
    return f"https://solscan.io/tx/{h}"


def _normalize_transfer_to_edge(t: dict, token_symbol: str = "TOKEN", chain: str = "solana") -> dict | None:
    """Normalize Solscan or Etherscan transfer item to {from, to, amount, unit, block_time, date_str}."""
    from datetime import datetime, timezone
    from_addr = (t.get("from_address") or t.get("from_owner") or t.get("from") or t.get("source") or "").strip()
    to_addr = (t.get("to_address") or t.get("to_owner") or t.get("to") or t.get("destination") or "").strip()
    if not from_addr or not to_addr:
        return None
    amount_raw = t.get("amount") or t.get("amount_num") or t.get("value") or t.get("token_amount") or 0
    try:
        amount = float(amount_raw)
    except (TypeError, ValueError):
        amount = 0
    block_ts = t.get("block_time") or t.get("blockTime") or t.get("timeStamp")
    if block_ts is not None:
        try:
            ts = int(block_ts)
            if ts > 1e12:  # milliseconds
                ts = ts // 1000
            date_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            date_str = ""
    else:
        date_str = ""
    unit = (t.get("token_symbol") or t.get("symbol") or token_symbol or "SOL").strip() or "TOKEN"
    if chain == "ethereum" and not t.get("token_symbol"):
        unit = "ETH"
    return {"from": from_addr, "to": to_addr, "amount": amount, "unit": unit, "block_time": block_ts, "date_str": date_str}


def _build_flow_graph(
    report: BlockchainInvestigationReport,
    transfer_edges: list[dict],
    chain: str = "solana",
) -> dict:
    """Build nodes (address, label, type) and edges (from, to, amount, unit, date_str) for flow diagram. Dedupe edges by (from,to) with summed amount and latest date."""
    from collections import defaultdict
    nodes_map: dict[str, dict] = {}  # address -> {id, label, type}
    edges_agg: dict[tuple[str, str], list[dict]] = defaultdict(list)
    deployer = (report.deployer_address or "").strip()
    counterparty_addrs = {c.get("address", "").strip() for c in report.counterparties if c.get("address")}
    for e in transfer_edges:
        if not e.get("from") or not e.get("to"):
            continue
        fr, to = e["from"], e["to"]
        edges_agg[(fr, to)].append(e)
    # Build nodes from edges + deployer + counterparties + wallet_labels
    all_addrs = set()
    for (fr, to) in edges_agg:
        all_addrs.add(fr)
        all_addrs.add(to)
    all_addrs.add(deployer)
    all_addrs.update(counterparty_addrs)
    for a in report.wallet_labels:
        all_addrs.add(a)
    for addr in all_addrs:
        if not addr:
            continue
        label = report.wallet_labels.get(addr) or next((c.get("name", "") for c in report.counterparties if c.get("address") == addr), "")
        label_lower = (label or "").lower()
        if addr == deployer:
            ntype = "primary"
        elif (
            addr in counterparty_addrs
            or addr.lower() in KNOWN_CEX_MIXER_ADDRESSES
            or addr.lower() in KNOWN_MIXER_EVM_CONTRACTS
            or addr.lower() in KNOWN_MIXER_EVM_WALLETS
        ):
            if "mixer" in label_lower or "jambler" in label_lower or "tumbler" in label_lower:
                ntype = "mixer"
            elif addr.lower() in KNOWN_MIXER_EVM_CONTRACTS:
                ntype = "mixer"
            elif addr.lower() in KNOWN_MIXER_EVM_WALLETS:
                ntype = "mixer"
            elif any(x in label_lower for x in ("exchange", "cex", "binance", "coinbase", "kraken", "bybit", "okx", "kucoin")):
                ntype = "cex"
            else:
                ntype = "counterparty"
            if not label and addr.lower() in KNOWN_CEX_MIXER_ADDRESSES:
                label = "CEX/mixer (known)"
            if not label and addr.lower() in KNOWN_MIXER_EVM_CONTRACTS:
                label = KNOWN_MIXER_EVM_CONTRACTS.get(addr.lower(), "Mixer/Privacy Service")
            if not label and addr.lower() in KNOWN_MIXER_EVM_WALLETS:
                label = KNOWN_MIXER_EVM_WALLETS.get(addr.lower(), "Mixer/Privacy Wallet")
        else:
            ntype = "wallet"
        nodes_map[addr] = {"id": addr, "label": label or addr[:8] + "..." + addr[-4:] if len(addr) > 16 else addr, "type": ntype}
    # Dedupe edges: merge by (from, to), sum amount, keep latest date, count
    edges_out = []
    for (fr, to), elist in edges_agg.items():
        total = sum(x.get("amount") or 0 for x in elist)
        units = list(set(x.get("unit") or "TOKEN" for x in elist))
        unit = units[0] if units else "TOKEN"
        dates = [x.get("date_str") for x in elist if x.get("date_str")]
        date_str = max(dates) if dates else ""
        count = len(elist)
        edges_out.append({
            "from": fr, "to": to,
            "amount": round(total, 6), "unit": unit, "date_str": date_str,
            "count": count,
        })
    # Chronological order (earliest date first) for narrative/flow readability
    def _edge_sort_key(e):
        d = e.get("date_str") or ""
        return (d, e.get("from", ""), e.get("to", ""))
    edges_out.sort(key=_edge_sort_key)
    return {"nodes": list(nodes_map.values()), "edges": edges_out[:80]}


def _build_crime_report(report: BlockchainInvestigationReport) -> dict:
    """Structured crime report for export: verdict first (Diverg style), then summary, risk, deployer, tokens, findings, flow, red_flags, linked wallets, flow_graph, explorer_links, chronological_narrative."""
    chain = (report.chain or "solana").lower()[:10]
    deployer_addr = report.deployer_address
    evidence_summary = _build_evidence_summary(report.findings)
    # Verdict first: one-line risk + main reason (how Zach presents findings)
    risk = report.risk_score
    if risk >= 70:
        verdict_level = "High risk"
    elif risk >= 40:
        verdict_level = "Elevated risk"
    else:
        verdict_level = "Moderate/low risk"
    verdict_reasons = []
    if report.sniper_alerts:
        verdict_reasons.append("sniper/insider pattern")
    if report.liquidity_alerts:
        verdict_reasons.append("liquidity/rug signals")
    cex_any = any(
        c.get("name") and ("exchange" in str(c.get("name", "")).lower() or "cex" in str(c.get("name", "")).lower() or "binance" in str(c.get("name", "")).lower() or "coinbase" in str(c.get("name", "")).lower())
        for c in report.counterparties
    )
    if cex_any:
        verdict_reasons.append("CEX routing (compliance exposure)")
    high_findings = [f for f in report.findings if f.severity == "High"]
    if high_findings:
        verdict_reasons.append(f"{len(high_findings)} high-severity findings")
    if evidence_summary.get("verified_count", 0):
        verdict_reasons.append(f"{evidence_summary['verified_count']} verified evidence points")
    if not verdict_reasons:
        verdict_reasons.append("on-chain and counterparty context")
    verdict_one_line = f"{verdict_level} ({report.risk_score}/100). Main factors: {', '.join(verdict_reasons[:3])}."
    deployer_section = {
        "address": deployer_addr,
        "label": report.wallet_labels.get(deployer_addr, "") if deployer_addr else "",
        "counterparties": [c.get("name", c.get("address", "")) for c in report.counterparties[:10]],
        "outflows_noted": any("outflow" in f.title.lower() for f in report.findings),
    }
    if deployer_addr:
        deployer_section["explorer_url"] = _explorer_url_address(deployer_addr, chain)
    tokens_section = {
        "count": len(report.tokens_discovered or []),
        "mints": (report.tokens_discovered or [])[:10],
        "authority_risks": [f.title for f in report.findings if "mint authority" in f.title or "freeze authority" in f.title],
    }
    ordered_findings = sorted(
        report.findings,
        key=lambda f: (
            -_severity_rank(f.severity),
            -(1 if f.verified else 0),
            -({"high": 3, "medium": 2, "low": 1}.get(_normalize_confidence(f.confidence) or "medium", 2)),
            (f.title or "").lower(),
        ),
    )
    findings_with_evidence = [
        {
            "title": f.title,
            "severity": f.severity,
            "url": f.url,
            "category": f.category,
            "evidence": f.evidence[:2000],
            "impact": f.impact,
            "remediation": f.remediation,
            "confidence": f.confidence,
            "source": f.source,
            "proof": f.proof,
            "verified": f.verified,
        }
        for f in ordered_findings
    ]
    flow_highlights = []
    if report.counterparties:
        flow_highlights.append("Deployer counterparties (30d): " + ", ".join([c.get("name", c.get("address", "?"))[:30] for c in report.counterparties[:5]]))
        cex_like = [c for c in report.counterparties if c.get("name") and ("exchange" in str(c.get("name", "")).lower() or "cex" in str(c.get("name", "")).lower() or "binance" in str(c.get("name", "")).lower() or "coinbase" in str(c.get("name", "")).lower() or "kraken" in str(c.get("name", "")).lower())]
        if cex_like:
            flow_highlights.append("CEX/compliance exposure: deployer transacted with " + ", ".join([c.get("name", "?")[:25] for c in cex_like[:3]]) + ". Funds to CEX can be frozen or subpoenaed; include timestamps for each leg.")
    for f in report.findings:
        if "outflow" in f.title.lower() or "counterpart" in f.title.lower():
            flow_highlights.append(f.title + ": " + f.evidence[:200])
    # Chronological narrative (Diverg style): "On YYYY-MM-DD A sent X to B; ..." from flow graph edges (already sorted by date)
    chronological_narrative = []
    if report.flow_graph and report.flow_graph.get("edges"):
        for e in report.flow_graph["edges"][:20]:
            date_str = e.get("date_str") or "date unknown"
            amount = e.get("amount")
            unit = e.get("unit", "TOKEN")
            fr = (e.get("from") or "")[:8] + "..." if len(e.get("from") or "") > 12 else (e.get("from") or "?")
            to = (e.get("to") or "")[:8] + "..." if len(e.get("to") or "") > 12 else (e.get("to") or "?")
            chronological_narrative.append(f"On {date_str}: {fr} → {to} ({amount} {unit})")
    # Explorer links for every key address (one-click verification)
    explorer_links = []
    seen = set()
    if deployer_addr and deployer_addr not in seen:
        seen.add(deployer_addr)
        explorer_links.append({"address": deployer_addr, "label": report.wallet_labels.get(deployer_addr, "deployer"), "url": _explorer_url_address(deployer_addr, chain)})
    for c in report.counterparties[:15]:
        addr = (c.get("address") or "").strip()
        if addr and addr not in seen:
            seen.add(addr)
            explorer_links.append({"address": addr, "label": c.get("name", "counterparty"), "url": _explorer_url_address(addr, chain)})
    for w in report.linked_wallets[:15]:
        addr = (w.get("address") or "").strip()
        if addr and addr not in seen:
            seen.add(addr)
            explorer_links.append({"address": addr, "label": w.get("label", "linked"), "url": _explorer_url_address(addr, chain)})
    if report.flow_graph and report.flow_graph.get("nodes"):
        for n in report.flow_graph["nodes"]:
            addr = (n.get("id") or "").strip()
            if addr and addr not in seen:
                seen.add(addr)
                explorer_links.append({"address": addr, "label": n.get("label", "wallet"), "url": _explorer_url_address(addr, chain)})
    linked = list(report.linked_wallets)[:30]
    relation_label = f"Crypto relation: {report.crypto_relation}. " if report.crypto_relation else ""
    summary = (
        f"{relation_label}"
        f"Risk score {report.risk_score}/100. "
        f"Findings: {len(report.findings)} ({len([f for f in report.findings if f.severity == 'High'])} High). "
    )
    summary += (
        f"Evidence quality: {evidence_summary.get('quality', 'limited')} "
        f"({evidence_summary.get('verified_count', 0)} verified, "
        f"{evidence_summary.get('confidence_counts', {}).get('high', 0)} high-confidence). "
    )
    if report.sniper_alerts:
        summary += "Sniper pattern detected. "
    if report.liquidity_alerts:
        summary += "Liquidity/rug signals present. "
    if report.counterparties:
        summary += "Deployer counterparties identified. "
    cex_names = [c.get("name", "") for c in report.counterparties if c.get("name") and ("exchange" in str(c.get("name", "")).lower() or "cex" in str(c.get("name", "")).lower() or "binance" in str(c.get("name", "")).lower() or "coinbase" in str(c.get("name", "")).lower())]
    if cex_names:
        summary += "CEX routing present (compliance exposure). "
    # Red flags section (Diverg: call out patterns at a glance)
    red_flags = []
    if report.sniper_alerts:
        red_flags.append("Same wallet(s) sniping multiple launches (insider/front-running)")
    for a in report.liquidity_alerts:
        if "remove" in str(a).lower() or "REMOVE_LIQ" in str(a) or "drain" in str(a).lower():
            red_flags.append("LP removed or drained shortly after launch (rug)")
            break
    for f in report.findings:
        t = (f.title or "").lower()
        if "mint authority" in t or "freeze authority" in t:
            red_flags.append("Mint/freeze authority still active (honeypot risk)")
            break
    if report.fee_comparison and report.fee_comparison.get("on_chain_pct") is not None and report.fee_comparison.get("stated_pct") is not None:
        red_flags.append("Stated fee vs on-chain fee comparison available (check for mismatch)")
    if cex_any:
        red_flags.append("Funds to CEX (compliance exposure; note exchange and timestamp per leg)")
    for f in report.findings:
        if "partial" in (f.title or "").lower() or "escrow" in (f.title or "").lower():
            red_flags.append("Partial payments or escrow-related pattern")
            break
    if not red_flags:
        red_flags.append("No high-signal red flags in current data; review findings and flow.")
    # Data sources: 100% truthful attribution — no placeholder data passed as real
    data_sources = {
        "on_chain_used": report.on_chain_used,
        "on_chain_reason": "API key set; data from Solscan/Etherscan and optionally Arkham"
        if report.on_chain_used
        else "No SOLSCAN_PRO_API_KEY or ETHERSCAN_API_KEY set; on-chain checks skipped",
        "flow_graph_from_live_data_only": report.flow_graph is not None,
        "evidence_quality": evidence_summary,
    }
    out = {
        "verdict": verdict_one_line,
        "summary": summary.strip(),
        "risk_score": report.risk_score,
        "deployer_section": deployer_section,
        "tokens_section": tokens_section,
        "findings_with_evidence": findings_with_evidence[:50],
        "flow_highlights": flow_highlights[:15],
        "chronological_narrative": chronological_narrative[:25],
        "red_flags": red_flags[:20],
        "explorer_links": explorer_links[:40],
        "linked_wallets": linked,
        "data_sources": data_sources,
        "evidence_summary": evidence_summary,
    }
    if report.flow_graph:
        out["flow_graph"] = report.flow_graph
    return out


def run(
    target_url: str,
    scan_type: str = "full",
    deployer_address: str | None = None,
    token_addresses: list[str] | None = None,
    chain: str = "solana",
    crypto_relation: str | None = None,
    flow_depth: str = "full",  # "full" = default page sizes; "deep" = more transfer history for flow graph
) -> str:
    # Post-rug mode: no URL needed when deployer or tokens provided; use placeholder and focus on-chain
    if (not (target_url or "").strip() or (target_url or "").strip().lower().startswith("post-rug")) and (deployer_address or token_addresses):
        target_url = "https://post-rug.local"

    platform_type = _detect_platform(target_url) if target_url else "launchpad"
    if "post-rug.local" in (target_url or ""):
        platform_type = "launchpad"
    if (crypto_relation or "").strip() in ("launchpad", "exchange"):
        platform_type = (crypto_relation or "").strip()
    _chain_raw = (chain or "solana").lower().strip()
    if _is_evm_chain(_chain_raw):
        _chain_store = _normalize_evm_chain_slug(_chain_raw)
    else:
        _chain_store = _chain_raw[:12]
    report = BlockchainInvestigationReport(
        target_url=target_url,
        platform_type=platform_type,
        chain=_chain_store,
        crypto_relation=(crypto_relation or "").strip() or None,
    )
    report.deployer_address = deployer_address
    run_start = time.time()
    flow_edges: list[dict] = []
    is_deep = (flow_depth or "full").lower() == "deep"
    transfer_page = 50 if is_deep else 20
    account_page = 50 if is_deep else 30

    # 1) Web recon: platform type, fee mentions, token-like addresses, sniper/rug mentions (skip if post-rug placeholder)
    scraped = _scrape_for_tokens_and_fees(SESSION, target_url, run_start) if "post-rug.local" not in (target_url or "") else {"tokens": [], "fee_mentions": [], "program_id": None, "deployer_hints": [], "sniper_mentions": []}
    if scraped.get("fee_mentions"):
        for fee in scraped["fee_mentions"][:5]:
            report.findings.append(Finding(
                title="Fee / tax mention on platform [REVIEW]",
                severity="Info",
                url=target_url,
                category="Blockchain / Fees",
                evidence=fee,
                impact="High or opaque fees can indicate extractive design. Compare to stated fee and on-chain actual.",
                remediation="Disclose fees clearly; ensure on-chain fee matches marketing; audit fee collector wallet.",
            ))
    if scraped.get("sniper_mentions"):
        report.findings.append(Finding(
            title="Platform mentions sniper / first-block / insider or launch bot",
            severity="Medium",
            url=target_url,
            category="Blockchain / Sniper",
            evidence="; ".join(scraped["sniper_mentions"][:3]),
            impact="If platform runs or benefits from sniper bots, retail buys after insiders (unfair, potential market manipulation).",
            remediation="Confirm no platform-owned or affiliated wallet snipes launches; consider fair launch or delay.",
        ))
    if scraped.get("liquidity_mentions"):
        report.findings.append(Finding(
            title="Platform mentions liquidity pull or rug",
            severity="Low",
            url=target_url,
            category="Blockchain / Liquidity",
            evidence="; ".join(scraped.get("liquidity_mentions", [])[:3]),
            impact="Awareness of rug risk; verify LP lock or burn and deployer history.",
            remediation="Lock or burn LP; audit deployer history (e.g. via Solscan) for repeated rugs.",
        ))
    if report.platform_type == "launchpad":
        report.findings.append(Finding(
            title="Launchpad-style platform detected",
            severity="Info",
            url=target_url,
            category="Blockchain / Platform",
            evidence=f"Domain/content matches: {', '.join(LAUNCHPAD_DOMAINS[:5])}...",
            impact="Launchpads are high-risk for sniper bots, liquidity pulls, and fee extraction. On-chain checks recommended.",
            remediation="Run with SOLSCAN_PRO_API_KEY and deployer/token list for sniper, holder concentration, and LP checks.",
        ))
    tokens_from_scrape = [t for t in scraped.get("tokens", []) if len(t) >= 32][:15]
    if token_addresses:
        report.tokens_discovered = list(token_addresses)[:20]
    else:
        report.tokens_discovered = tokens_from_scrape

    stated_fee_pct = _extract_stated_fee_pct(scraped.get("fee_mentions", []))
    if stated_fee_pct is not None:
        report.fee_comparison = {"stated_pct": stated_fee_pct, "on_chain_pct": None, "evidence": f"Stated: {stated_fee_pct}%"}

    # 2) On-chain: Solana (Solscan) or Ethereum (Etherscan). Arkham is required whenever those APIs are used.
    solscan_key = (os.environ.get("SOLSCAN_PRO_API_KEY") or os.environ.get("SOLSCAN_API_KEY") or "").strip()
    etherscan_key = (os.environ.get("ETHERSCAN_API_KEY") or "").strip()
    arkham_key = (os.environ.get("ARKHAM_API_KEY") or "").strip()

    if _is_evm_chain(report.chain) and etherscan_key and not _over_budget(run_start):
        if not arkham_key:
            report.findings.append(Finding(
                title="ARKHAM_API_KEY required for Etherscan-backed on-chain investigation",
                severity="Medium",
                url=target_url,
                category="Blockchain / Config",
                evidence="ETHERSCAN_API_KEY is set but ARKHAM_API_KEY is missing.",
                impact="On-chain wallet intelligence and labeling are part of the standard investigation path.",
                remediation="Set ARKHAM_API_KEY in the environment and re-run.",
            ))
            report.errors.append("ARKHAM_API_KEY is required when ETHERSCAN_API_KEY is set.")
        else:
            report.on_chain_used = True
            transfers_by_token = {}
            ch_slug = report.chain
            for token in (report.tokens_discovered or [])[:5]:
                if _over_budget(run_start):
                    break
                if not token.startswith("0x") or len(token) != 42:
                    continue
                txs = _evm_token_transfers(SESSION, token, ch_slug, etherscan_key, limit=20)
                if txs:
                    transfers_by_token[token] = [{"to": t.get("to"), "from": t.get("from"), "value": t.get("value"), "timeStamp": t.get("timeStamp")} for t in txs]
                    for txrow in txs:
                        edge = _normalize_transfer_to_edge(txrow, token_symbol="TOKEN", chain=ch_slug)
                        if edge:
                            flow_edges.append(edge)
            if transfers_by_token:
                sniper_alerts = _heuristic_sniper(transfers_by_token, same_wallet_min_tokens=3)
                report.sniper_alerts.extend(sniper_alerts)
                for a in sniper_alerts:
                    report.findings.append(Finding(
                        title="Same wallet bought early across multiple tokens [SNIPER RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Sniper",
                        evidence=a.get("description", ""),
                        impact="Possible platform or insider sniper buying every launch before retail.",
                        remediation="Verify wallet is not platform-owned; consider fair launch or delay.",
                        confidence="high",
                        source="etherscan_api",
                        proof=a.get("description", ""),
                        verified=True,
                    ))

            # Bridge contract detection: scan deployer/wallet txlist for interactions with known bridge contracts
            if deployer_address and not _over_budget(run_start):
                _bridge_raw_txs = _evm_account_txlist(SESSION, deployer_address, ch_slug, etherscan_key, page_size=50)
                evm_bridge_hits = [
                    {
                        "tx_hash": tx.get("hash", ""),
                        "counterparty": tx.get("to", ""),
                        "bridge": EVM_BRIDGE_CONTRACTS[tx.get("to", "").lower()],
                        "timestamp": tx.get("timeStamp", ""),
                        "value_eth": tx.get("value", "0"),
                        "explorer_url": f"{_explorer_host_for_chain(ch_slug)}/tx/{tx.get('hash', '')}",
                    }
                    for tx in _bridge_raw_txs
                    if tx.get("to", "").lower() in EVM_BRIDGE_CONTRACTS
                ]
                if evm_bridge_hits:
                    _bridge_labels = sorted({h["bridge"] for h in evm_bridge_hits})
                    report.findings.append(Finding(
                        title="EVM Bridge Interaction Detected",
                        severity="Medium",
                        url=target_url,
                        category="Blockchain / Cross-chain",
                        evidence=(
                            f"Deployer/wallet {deployer_address[:12]}… interacted with "
                            f"{len(evm_bridge_hits)} bridge transaction(s) on {ch_slug}: "
                            + ", ".join(_bridge_labels[:4])
                        ),
                        impact=(
                            "Funds may have crossed chain boundaries via a bridge protocol. "
                            "Investigate origin and destination chains for full flow."
                        ),
                        remediation="Trace bridge transactions on Wormholescan, LayerZero Scan, or the relevant bridge explorer.",
                        confidence="medium",
                        source="etherscan_api",
                        proof=", ".join(h["tx_hash"][:12] + "…" for h in evm_bridge_hits[:3]),
                        verified=True,
                    ))
                    report.evm_bridge_hits = evm_bridge_hits[:10]

                # Mixer/privacy service detection on EVM side (e.g. Tornado-style contracts)
                evm_mixer_hits = _evm_detect_mixer_hits(_bridge_raw_txs, ch_slug)
                if evm_mixer_hits:
                    _svc = _summarize_service_hits(evm_mixer_hits)
                    _incoming = sum(1 for h in evm_mixer_hits if h.get("direction") == "incoming")
                    _outgoing = sum(1 for h in evm_mixer_hits if h.get("direction") == "outgoing")
                    report.findings.append(Finding(
                        title="EVM Mixer/Privacy Service Interaction Detected",
                        severity="Medium",
                        url=target_url,
                        category="Blockchain / Mixer",
                        evidence=(
                            f"Deployer/wallet {deployer_address[:12]}… interacted with "
                            f"{len(evm_mixer_hits)} known mixer/privacy transaction(s) on {ch_slug} "
                            f"({_outgoing} outgoing, {_incoming} incoming): "
                            + ", ".join(x["name"] for x in _svc[:4])
                        ),
                        impact=(
                            "Funds may have passed through a privacy/mixing service. "
                            "Treat as risk context and verify flows on-chain."
                        ),
                        remediation="Verify each tx and counterparty on explorer and corroborate with additional sources.",
                        confidence="medium",
                        source="etherscan_api",
                        proof=", ".join(h["tx_hash"][:12] + "…" for h in evm_mixer_hits[:3]),
                        verified=True,
                    ))
                    report.evm_mixer_hits = evm_mixer_hits[:10]

            # Arkham Intel (EVM): deployer label, batch sniper/holder wallets, counterparties
            ak_chn = evm_chain_slug_for_arkham(ch_slug)
            if not _over_budget(run_start):
                if deployer_address:
                    label = legacy_label(SESSION, deployer_address, arkham_key)
                    if label:
                        report.wallet_labels[deployer_address] = label
                        report.findings.append(Finding(
                            title=f"Deployer wallet labeled (Arkham): {label}",
                            severity="Info",
                            url=target_url,
                            category="Blockchain / Intel",
                            evidence=f"Address {deployer_address[:12]}... → {label}",
                            impact="Entity attribution helps assess insider or platform-operated risk.",
                            remediation="Cross-check with platform's stated treasury/fee collector.",
                        ))
                addresses_to_label: list[str] = []
                if deployer_address:
                    addresses_to_label.append(deployer_address)
                for a in report.sniper_alerts:
                    w = a.get("wallet")
                    if w and w not in addresses_to_label:
                        addresses_to_label.append(w)
                if addresses_to_label:
                    batch_labels = intel_batch(SESSION, addresses_to_label[:30], arkham_key, chain=ak_chn)
                    for addr, name in batch_labels.items():
                        report.wallet_labels[addr] = name
                    if batch_labels and not any(
                        f.title.startswith("Deployer wallet labeled") for f in report.findings
                    ):
                        for addr, name in list(batch_labels.items())[:3]:
                            report.findings.append(Finding(
                                title=f"Wallet labeled (Arkham Intel): {name}",
                                severity="Info",
                                url=target_url,
                                category="Blockchain / Intel",
                                evidence=f"{addr[:12]}... → {name}",
                                impact="Entity attribution for deployer/sniper wallets aids investigation.",
                                remediation="Cross-check with platform and CEX off-ramp.",
                                confidence="high",
                                source="arkham_api",
                                proof=f"{addr} → {name}",
                                verified=True,
                            ))
                if deployer_address:
                    counterparties = intel_counterparties(
                        SESSION, deployer_address, arkham_key, chain=ak_chn, limit=8, time_last="30d",
                    )
                    if counterparties:
                        names = []
                        for cp in counterparties[:6]:
                            addr_obj = cp.get("address") if isinstance(cp, dict) else None
                            if isinstance(addr_obj, dict):
                                addr_str = addr_obj.get("address")
                                entity = addr_obj.get("arkhamEntity") or addr_obj.get("arkhamLabel")
                                if entity and isinstance(entity, dict):
                                    name = entity.get("name", "?")
                                else:
                                    name = addr_obj.get("name", "?")
                                names.append(name)
                                if addr_str and isinstance(addr_str, str):
                                    report.counterparties.append({"address": addr_str, "name": name})
                            elif isinstance(cp, dict):
                                addr_str = cp.get("address") if isinstance(cp.get("address"), str) else None
                                name = cp.get("name", "?")
                                if addr_str:
                                    report.counterparties.append({"address": addr_str, "name": name})
                                if cp.get("name"):
                                    names.append(cp["name"])
                        if names:
                            report.findings.append(Finding(
                                title="Deployer top counterparties (Arkham) [INTEL]",
                                severity="Info",
                                url=target_url,
                                category="Blockchain / Intel",
                                evidence="Top counterparties (30d): " + ", ".join(names[:6]),
                                impact="Reveals CEX off-ramp, linked entities, or OTC.",
                                remediation="Use for flow analysis; check if any counterparty is platform-related.",
                                confidence="high",
                                source="arkham_api",
                                proof="Counterparties: " + ", ".join(names[:6]),
                                verified=True,
                            ))

    elif solscan_key and not _over_budget(run_start):
        if not arkham_key:
            report.findings.append(Finding(
                title="ARKHAM_API_KEY required for Solscan-backed on-chain investigation",
                severity="Medium",
                url=target_url,
                category="Blockchain / Config",
                evidence="SOLSCAN_PRO_API_KEY (or SOLSCAN_API_KEY) is set but ARKHAM_API_KEY is missing.",
                impact="On-chain wallet intelligence and labeling are part of the standard investigation path.",
                remediation="Set ARKHAM_API_KEY in the environment and re-run.",
            ))
            report.errors.append("ARKHAM_API_KEY is required when Solscan API keys are set.")
        else:
            report.on_chain_used = True
            # --- Sniper across launches: token/transfer per token, earliest first ---
            transfers_by_token = {}
            for token in (report.tokens_discovered or [])[:5]:
                if _over_budget(run_start):
                    break
                txs = _solscan_token_transfers(SESSION, token, solscan_key, page_size=transfer_page, sort_order="asc")
                if txs:
                    transfers_by_token[token] = txs
                    for t in txs:
                        edge = _normalize_transfer_to_edge(t, token_symbol="TOKEN", chain="solana")
                        if edge:
                            flow_edges.append(edge)
            if len(transfers_by_token) >= 2:
                sniper_alerts = _heuristic_sniper(transfers_by_token, same_wallet_min_tokens=3)
                report.sniper_alerts.extend(sniper_alerts)
                for a in sniper_alerts:
                    report.findings.append(Finding(
                        title="Same wallet bought early across multiple tokens [SNIPER RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Sniper",
                        evidence=a.get("description", ""),
                        impact="Possible platform or insider sniper buying every launch before retail.",
                        remediation="Verify wallet is not platform-owned; consider fair launch or delay.",
                        confidence="high",
                        source="solscan_api",
                        proof=a.get("description", ""),
                        verified=True,
                    ))
            # --- Deployer: serial launcher + defi (LP remove); collect account transfers for flow graph ---
            if deployer_address:
                txs = _solscan_account_transfers(SESSION, deployer_address, solscan_key, page_size=account_page)
                if txs:
                    for t in txs:
                        edge = _normalize_transfer_to_edge(t, token_symbol="SOL", chain="solana")
                        if edge:
                            flow_edges.append(edge)
                    tokens_involved = set()
                    for t in txs:
                        for k in ("token_address", "mint", "token"):
                            if t.get(k):
                                tokens_involved.add(str(t[k]))
                    if len(tokens_involved) >= 5:
                        report.findings.append(Finding(
                            title="Deployer interacts with many tokens [POSSIBLE SERIAL LAUNCHER]",
                            severity="Medium",
                            url=target_url,
                            category="Blockchain / Deployer",
                            evidence=f"Deployer {deployer_address[:8]}... has transfers involving {len(tokens_involved)}+ tokens.",
                            impact="Serial token creators have higher rug/dead-token history in aggregate; check deployer on Solscan.",
                            remediation="Audit deployer history (tokens created, LP retention, early sells) via Solscan/Arkham.",
                        ))
                # LP removal: deployer defi activities REMOVE_LIQ
                defi = _solscan_account_defi_activities(
                    SESSION, deployer_address, solscan_key,
                    activity_types=["ACTIVITY_TOKEN_REMOVE_LIQ"],
                    page_size=20,
                )
                if defi:
                    report.liquidity_alerts.append({
                        "address": deployer_address,
                        "remove_liq_count": len(defi),
                        "description": f"Deployer has {len(defi)} remove-liquidity (REMOVE_LIQ) activity/activities.",
                    })
                    report.findings.append(Finding(
                        title="Deployer has remove-liquidity (LP pull) activity [RUG RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Liquidity",
                        evidence=f"Deployer {deployer_address[:12]}...: {len(defi)} ACTIVITY_TOKEN_REMOVE_LIQ.",
                        impact="LP can be pulled after launch; classic rug. Verify LP lock or burn.",
                        remediation="Lock or burn LP; audit deployer for repeated remove-liq on past tokens.",
                        confidence="high",
                        source="solscan_api",
                        proof=f"{len(defi)} REMOVE_LIQ activities for {deployer_address}",
                        verified=True,
                    ))
                # Deployer outflows (balance_change) — dump / cash-out signal
                if not _over_budget(run_start):
                    balance_changes = _solscan_account_balance_change(SESSION, deployer_address, solscan_key, flow="out", page_size=15)
                    if len(balance_changes) >= 5:
                        report.findings.append(Finding(
                            title="Deployer has many recent outflows [POSSIBLE DUMP/CASH-OUT]",
                            severity="Medium",
                            url=target_url,
                            category="Blockchain / Intel",
                            evidence=f"Deployer {deployer_address[:12]}...: {len(balance_changes)} outflow activities (Solscan balance_change).",
                            impact="Frequent outflows can indicate cashing out or dumping; correlate with token sells.",
                            remediation="Review deployer balance_change and transfer history on Solscan for timing vs token launches.",
                        ))
                    label = legacy_label(SESSION, deployer_address, arkham_key)
                    if label:
                        report.wallet_labels[deployer_address] = label
                        report.findings.append(Finding(
                            title=f"Deployer wallet labeled (Arkham): {label}",
                            severity="Info",
                            url=target_url,
                            category="Blockchain / Intel",
                            evidence=f"Address {deployer_address[:12]}... → {label}",
                            impact="Entity attribution helps assess insider or platform-operated sniper risk.",
                            remediation="Cross-check with platform's stated treasury/fee collector.",
                        ))
            # --- Token meta: mint/freeze authority (honeypot/rug) ---
            for token in (report.tokens_discovered or [])[:2]:
                if _over_budget(run_start):
                    break
                meta = _solscan_token_meta(SESSION, token, solscan_key)
                if not meta:
                    continue
                mint_authority = meta.get("mint_authority") or meta.get("mintAuthority")
                freeze_authority = meta.get("freeze_authority") or meta.get("freezeAuthority")
                if mint_authority and str(mint_authority).lower() not in ("null", "none", "revoked", "n/a", ""):
                    report.findings.append(Finding(
                        title="Token has active mint authority [HONEYPOT/RUG RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Token",
                        evidence=f"Mint authority: {str(mint_authority)[:20]}... (token {token[:12]}...). Creator can mint unlimited supply.",
                        impact="Deployer can dilute holders to zero; revoke mint authority or verify lock.",
                        remediation="Revoke mint authority on launch or use immutable mint; check on Solscan token meta.",
                        confidence="high",
                        source="solscan_api",
                        proof=f"mint_authority={str(mint_authority)[:44]}, token={token}",
                        verified=True,
                    ))
                if freeze_authority and str(freeze_authority).lower() not in ("null", "none", "revoked", "n/a", ""):
                    report.findings.append(Finding(
                        title="Token has active freeze authority [HONEYPOT RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Token",
                        evidence=f"Freeze authority: {str(freeze_authority)[:20]}... (token {token[:12]}...). Creator can freeze accounts.",
                        impact="Deployer can freeze sells (honeypot: buy works, sell blocked); revoke freeze authority.",
                        remediation="Revoke freeze authority; check on Solscan token meta.",
                        confidence="high",
                        source="solscan_api",
                        proof=f"freeze_authority={str(freeze_authority)[:44]}, token={token}",
                        verified=True,
                    ))
            # --- Holder concentration + optional fee from transfers ---
            on_chain_fee_pct = None
            holder_addresses_for_arkham = []
            for token in (report.tokens_discovered or [])[:3]:
                if _over_budget(run_start):
                    break
                holders = _solscan_token_holders(SESSION, token, solscan_key, limit=15)
                for h in holders[:3]:
                    owner = h.get("owner") or h.get("address") or h.get("owner_address")
                    if owner and owner not in holder_addresses_for_arkham:
                        holder_addresses_for_arkham.append(owner)
                conc = _heuristic_concentrated_holders(holders, top_n=10, threshold_pct=40.0)
                report.liquidity_alerts.extend(conc)
                for a in conc:
                    report.findings.append(Finding(
                        title="Concentrated token holders [RUG RISK]",
                        severity="High",
                        url=target_url,
                        category="Blockchain / Liquidity",
                        evidence=a.get("description", ""),
                        impact="Top holders can dump and rug; verify LP lock and deployer sell pattern.",
                        remediation="Check LP lock/burn; monitor deployer and top wallets for early sells (Solscan/Arkham).",
                        confidence="high",
                        source="solscan_api",
                        proof=a.get("description", ""),
                        verified=True,
                    ))
                # Fee from first token's transfers (Solscan may include fee in decoded)
                if on_chain_fee_pct is None and stated_fee_pct is not None:
                    txs = _solscan_token_transfers(SESSION, token, solscan_key, page_size=10, sort_order="desc")
                    for t in txs:
                        fee_pct = t.get("fee_pct") or t.get("fee_percent") or (float(t.get("fee", 0) or 0) * 100 if t.get("fee") else None)
                        if fee_pct is not None and isinstance(fee_pct, (int, float)):
                            on_chain_fee_pct = float(fee_pct)
                            break
            if stated_fee_pct is not None and report.fee_comparison:
                report.fee_comparison["on_chain_pct"] = on_chain_fee_pct
                report.fee_comparison["evidence"] = f"Stated: {stated_fee_pct}%" + (f"; on-chain observed: {on_chain_fee_pct}%" if on_chain_fee_pct is not None else "; on-chain fee not in API response")
                if on_chain_fee_pct is not None and abs(on_chain_fee_pct - stated_fee_pct) > 0.5:
                    report.findings.append(Finding(
                        title="Stated fee vs on-chain fee mismatch [REVIEW]",
                        severity="Medium",
                        url=target_url,
                        category="Blockchain / Fees",
                        evidence=report.fee_comparison["evidence"],
                        impact="Users may be charged different than advertised; or fee not applied consistently.",
                        remediation="Align on-chain fee with stated fee; audit fee collector logic.",
                        confidence="medium",
                        source="solscan_api",
                        proof=report.fee_comparison["evidence"],
                        verified=False,
                    ))
            # --- Arkham Intel: batch labels + deployer counterparties ---
            if not _over_budget(run_start):
                addresses_to_label = []
                if deployer_address:
                    addresses_to_label.append(deployer_address)
                for a in report.sniper_alerts:
                    w = a.get("wallet")
                    if w and w not in addresses_to_label:
                        addresses_to_label.append(w)
                for addr in holder_addresses_for_arkham[:5]:
                    if addr and addr not in addresses_to_label:
                        addresses_to_label.append(addr)
                if addresses_to_label:
                    batch_labels = intel_batch(SESSION, addresses_to_label[:30], arkham_key, chain="solana")
                    for addr, name in batch_labels.items():
                        report.wallet_labels[addr] = name
                    if batch_labels and not any(f.title.startswith("Deployer wallet labeled") for f in report.findings):
                        for addr, name in list(batch_labels.items())[:3]:
                            report.findings.append(Finding(
                                title=f"Wallet labeled (Arkham Intel): {name}",
                                severity="Info",
                                url=target_url,
                                category="Blockchain / Intel",
                                evidence=f"{addr[:12]}... → {name}",
                                impact="Entity attribution for deployer/sniper/holders aids crime investigation.",
                                remediation="Cross-check with platform and CEX off-ramp; use counterparties for flow.",
                                confidence="high",
                                source="arkham_api",
                                proof=f"{addr} → {name}",
                                verified=True,
                            ))
                if deployer_address:
                    counterparties = intel_counterparties(SESSION, deployer_address, arkham_key, chain="solana", limit=8, time_last="30d")
                    if counterparties:
                        names = []
                        for cp in counterparties[:6]:
                            addr_obj = cp.get("address") if isinstance(cp, dict) else None
                            addr_str = None
                            if isinstance(addr_obj, dict):
                                addr_str = addr_obj.get("address")
                                entity = addr_obj.get("arkhamEntity") or addr_obj.get("arkhamLabel")
                                if entity and isinstance(entity, dict):
                                    name = entity.get("name", "?")
                                else:
                                    name = addr_obj.get("name", "?")
                                names.append(name)
                                if addr_str and isinstance(addr_str, str):
                                    report.counterparties.append({"address": addr_str, "name": name})
                            elif isinstance(cp, dict):
                                addr_str = cp.get("address") if isinstance(cp.get("address"), str) else None
                                name = cp.get("name", "?")
                                if addr_str:
                                    report.counterparties.append({"address": addr_str, "name": name})
                                if cp.get("name"):
                                    names.append(cp["name"])
                        if names:
                            report.findings.append(Finding(
                                title="Deployer top counterparties (Arkham) [INTEL]",
                                severity="Info",
                                url=target_url,
                                category="Blockchain / Intel",
                                evidence="Top counterparties (30d): " + ", ".join(names[:6]),
                                impact="Reveals CEX off-ramp, linked entities, or OTC; useful for tracing proceeds.",
                                remediation="Use for flow analysis and compliance; check if any counterparty is platform-related.",
                                confidence="high",
                                source="arkham_api",
                                proof="Counterparties: " + ", ".join(names[:6]),
                                verified=True,
                            ))
                # Multi-hop (deep): add 1-hop transfers from counterparties so flow graph shows paths beyond deployer
                if is_deep and report.counterparties and not _over_budget(run_start):
                    for cp in report.counterparties[:3]:
                        addr = (cp.get("address") or "").strip()
                        if not addr or len(addr) < 32:
                            continue
                        if _over_budget(run_start):
                            break
                        try:
                            cpt_txs = _solscan_account_transfers(SESSION, addr, solscan_key, page_size=15)
                            if cpt_txs:
                                for t in cpt_txs:
                                    edge = _normalize_transfer_to_edge(t, token_symbol="SOL", chain="solana")
                                    if edge:
                                        flow_edges.append(edge)
                        except Exception:
                            pass
    else:
        if report.platform_type == "launchpad":
            report.findings.append(Finding(
                title="On-chain investigation skipped (no API key)",
                severity="Info",
                url=target_url,
                category="Blockchain / Config",
                evidence="Set SOLSCAN_PRO_API_KEY (Solana) or ETHERSCAN_API_KEY (Ethereum) for on-chain checks.",
                impact="Without on-chain data, sniper/liquidity/fee abuse cannot be confirmed.",
                remediation="Get API keys for your chain explorer (Solscan or Etherscan) and ARKHAM_API_KEY; re-run scan.",
            ))
        report.errors.append("No on-chain API key set; checks skipped.")

    for fee in scraped.get("fee_mentions", [])[:5]:
        report.fee_alerts.append({"mention": fee})

    report.findings = _finalize_findings(report.findings)
    # Crime report: risk score, linked wallets, structured report
    report.risk_score = _compute_risk_score(report)
    report.linked_wallets = [
        {"address": c.get("address", ""), "label": c.get("name", ""), "source": "counterparty"}
        for c in report.counterparties if c.get("address")
    ]
    for addr, label in report.wallet_labels.items():
        if addr == report.deployer_address:
            continue
        if not any(lw.get("address") == addr for lw in report.linked_wallets):
            report.linked_wallets.append({"address": addr, "label": label or "", "source": "holder"})
    # Build flow graph for Diverg report diagram (nodes + edges from transfers)
    if report.on_chain_used and flow_edges:
        try:
            report.flow_graph = _build_flow_graph(report, flow_edges, report.chain)
        except Exception:
            report.flow_graph = None

    try:
        from cross_chain_hints import lookup_evm_token, lookup_solana_mint, summarize_cross_chain_payload
        xc_sources: list[dict[str, Any]] = []
        for tok in (report.tokens_discovered or [])[:5]:
            if not tok:
                continue
            if tok.startswith("0x") and len(tok) == 42 and _is_evm_chain(report.chain):
                r = lookup_evm_token(report.chain, tok)
                if r.get("candidates"):
                    xc_sources.append(r)
            elif len(tok) >= 32 and report.chain == "solana":
                r = lookup_solana_mint(tok)
                if r.get("candidates"):
                    xc_sources.append(r)
        if xc_sources:
            cc_payload: dict[str, Any] = {
                "lookups": xc_sources,
                "note": "Investigative hints only; verify on explorers.",
            }
            cc_payload["summary"] = summarize_cross_chain_payload(cc_payload)
            report.cross_chain = cc_payload
            titles = []
            for block in xc_sources:
                for c in (block.get("candidates") or [])[:4]:
                    fc = c.get("foreign_chain", "?")
                    fa = (c.get("foreign_address") or "")[:18]
                    tier = c.get("confidence_tier") or c.get("confidence", "")
                    ex = c.get("foreign_explorer_url")
                    if ex:
                        titles.append(f"{fc} {fa}… ({tier}) — {ex}")
                    else:
                        titles.append(f"{fc} {fa}… ({tier})")
            if titles:
                report.findings.append(Finding(
                    title="Cross-chain asset hints [REVIEW]",
                    severity="Info",
                    url=target_url,
                    category="Blockchain / Cross-chain",
                    evidence="; ".join(titles[:6]),
                    impact="Token may have bridged or wrapped counterparts elsewhere; confirms nothing about misconduct.",
                    remediation="Verify mappings on official bridge registries and destination-chain explorers.",
                    confidence="medium",
                    source="cross_chain_hints",
                    proof="; ".join(titles[:3]),
                    verified=False,
                ))
    except Exception as _xce:
        report.cross_chain = {
            "error": str(_xce),
            "summary": {
                "kind": "error",
                "error": str(_xce),
                "candidate_count": 0,
                "sources": [],
                "explorer_links": [],
                "has_high_tier": False,
            },
        }

    report.crime_report = _build_crime_report(report)
    if isinstance(report.crime_report, dict):
        if report.cross_chain:
            report.crime_report["cross_chain"] = report.cross_chain
        if report.evm_bridge_hits:
            report.crime_report["evm_bridge"] = report.evm_bridge_hits
        if report.evm_mixer_hits:
            report.crime_report["evm_mixer"] = report.evm_mixer_hits
            report.crime_report["evm_mixer_summary"] = _summarize_service_hits(report.evm_mixer_hits)

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    import sys as _sys
    url = _sys.argv[1] if len(_sys.argv) > 1 else "https://liquid.af"
    print(run(url, scan_type="full"))
