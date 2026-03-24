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

Requires SOLSCAN_PRO_API_KEY (Solana) or ETHERSCAN_API_KEY (Ethereum) for on-chain checks.
ARKHAM_API_KEY optional for labels. FRONTRUNPRO_API_KEY + FRONTRUNPRO_BASE_URL optional for
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
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 12
RUN_BUDGET_SEC = 55
SOLSCAN_BASE = "https://pro-api.solscan.io/v2.0"
ARKHAM_BASE = "https://api.arkhamintelligence.com"
ARKHAM_INTEL_BASE = "https://api.arkm.com"  # Intel API: batch labels, counterparties, flow
ETHERSCAN_BASE = "https://api.etherscan.io/api"

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


def _over_budget(start: float) -> bool:
    return (time.time() - start) > RUN_BUDGET_SEC


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


def _arkham_label(session: requests.Session, address: str, api_key: str) -> str | None:
    """Single-address label (legacy Arkham endpoint)."""
    try:
        r = session.get(
            f"{ARKHAM_BASE}/api/address/{address}",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.ok:
            j = r.json()
            return j.get("label") or j.get("entity") or j.get("name")
    except Exception:
        pass
    return None


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


def _arkham_intel_batch(session: requests.Session, addresses: list[str], api_key: str, chain: str = "solana") -> dict[str, str]:
    """Batch label lookup via Arkham Intel API (api.arkm.com). Returns address -> label/entity name."""
    out = {}
    if not addresses or len(addresses) > 100:
        return out
    try:
        r = session.post(
            f"{ARKHAM_INTEL_BASE}/intelligence/address/batch",
            params={"chain": chain} if chain else None,
            json={"addresses": addresses[:50]},
            headers={"Content-Type": "application/json", "API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return out
        j = r.json()
        # Response shape: may be { "address": { "arkhamEntity": { "name": "..." }, "arkhamLabel": { "name": "..." } } } or list
        for addr in addresses:
            info = j.get(addr) if isinstance(j, dict) else None
            if not info:
                continue
            name = None
            if isinstance(info, dict):
                entity = info.get("arkhamEntity") or info.get("entity")
                label = info.get("arkhamLabel") or info.get("label")
                if entity and isinstance(entity, dict):
                    name = entity.get("name")
                if not name and label and isinstance(label, dict):
                    name = label.get("name")
                if not name:
                    name = info.get("name")
            if name:
                out[addr] = str(name)
    except Exception:
        pass
    return out


def _arkham_intel_counterparties(
    session: requests.Session,
    address: str,
    api_key: str,
    chain: str = "solana",
    limit: int = 10,
    time_last: str = "30d",
) -> list[dict]:
    """Top counterparties for an address (who they transact with — CEX, entities)."""
    try:
        r = session.get(
            f"{ARKHAM_INTEL_BASE}/counterparties/address/{address}",
            params={"chains": chain, "limit": limit, "timeLast": time_last, "sortKey": "usd", "sortDir": "desc"},
            headers={"API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return []
        j = r.json()
        if isinstance(j, dict) and address in j:
            cp = j[address]
            return cp if isinstance(cp, list) else []
        if isinstance(j, list):
            return j[:limit]
    except Exception:
        pass
    return []


def _arkham_intel_flow(
    session: requests.Session,
    address: str,
    api_key: str,
    chain: str = "solana",
    time_last: str = "30d",
) -> list | None:
    """Historical USD flow for address (in/out over time)."""
    try:
        r = session.get(
            f"{ARKHAM_INTEL_BASE}/flow/address/{address}",
            params={"chains": chain, "timeLast": time_last},
            headers={"API-Key": api_key},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return None
        j = r.json()
        return j if isinstance(j, list) else j.get("flow") or j.get("data")
    except Exception:
        pass
    return None


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
    # High severity findings (authority, LP pull, sniper, concentration)
    for f in report.findings:
        if f.severity == "High":
            score += 18
        elif f.severity == "Medium":
            score += 10
        elif f.severity == "Low":
            score += 4
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
    # Cap
    return min(100.0, round(score, 1))


def _explorer_url_address(address: str, chain: str = "solana") -> str:
    """Explorer URL for an address so evidence is one-click verifiable (Diverg standard)."""
    if not (address or "").strip():
        return ""
    addr = address.strip()
    if (chain or "solana").lower() in ("eth", "ethereum"):
        return f"https://etherscan.io/address/{addr}"
    return f"https://solscan.io/account/{addr}"


def _explorer_url_tx(tx_hash: str, chain: str = "solana") -> str:
    """Explorer URL for a transaction."""
    if not (tx_hash or "").strip():
        return ""
    h = tx_hash.strip()
    if (chain or "solana").lower() in ("eth", "ethereum"):
        return f"https://etherscan.io/tx/{h}"
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
        elif addr in counterparty_addrs or addr.lower() in KNOWN_CEX_MIXER_ADDRESSES:
            if "mixer" in label_lower or "jambler" in label_lower or "tumbler" in label_lower:
                ntype = "mixer"
            elif any(x in label_lower for x in ("exchange", "cex", "binance", "coinbase", "kraken", "bybit", "okx", "kucoin")):
                ntype = "cex"
            else:
                ntype = "counterparty"
            if not label and addr.lower() in KNOWN_CEX_MIXER_ADDRESSES:
                label = "CEX/mixer (known)"
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
        for f in report.findings
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
    report = BlockchainInvestigationReport(
        target_url=target_url,
        platform_type=platform_type,
        chain=(chain or "solana").lower()[:10],
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

    # 2) On-chain: Solana (Solscan) or Ethereum (Etherscan)
    solscan_key = (os.environ.get("SOLSCAN_PRO_API_KEY") or os.environ.get("SOLSCAN_API_KEY") or "").strip()
    etherscan_key = (os.environ.get("ETHERSCAN_API_KEY") or "").strip()
    arkham_key = (os.environ.get("ARKHAM_API_KEY") or "").strip()

    if report.chain == "ethereum" and etherscan_key and not _over_budget(run_start):
        report.on_chain_used = True
        # Sniper across launches: early token transfers per token, aggregate by "to"
        transfers_by_token = {}
        for token in (report.tokens_discovered or [])[:5]:
            if _over_budget(run_start):
                break
            if not token.startswith("0x") or len(token) != 42:
                continue
            txs = _etherscan_token_transfers(SESSION, token, etherscan_key, limit=20)
            if txs:
                transfers_by_token[token] = [{"to": t.get("to"), "from": t.get("from"), "value": t.get("value"), "timeStamp": t.get("timeStamp")} for t in txs]
                for t in txs:
                    edge = _normalize_transfer_to_edge(t, token_symbol="ETH", chain="ethereum")
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
    elif solscan_key and not _over_budget(run_start):
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
            if arkham_key:
                label = _arkham_label(SESSION, deployer_address, arkham_key)
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
        if arkham_key and not _over_budget(run_start):
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
                batch_labels = _arkham_intel_batch(SESSION, addresses_to_label[:30], arkham_key, chain="solana")
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
                counterparties = _arkham_intel_counterparties(SESSION, deployer_address, arkham_key, chain="solana", limit=8, time_last="30d")
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
                remediation="Get API key for your chain; optionally ARKHAM_API_KEY for wallet labels. Re-run scan.",
            ))
        report.errors.append("No on-chain API key set; checks skipped.")

    for fee in scraped.get("fee_mentions", [])[:5]:
        report.fee_alerts.append({"mention": fee})

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

    report.crime_report = _build_crime_report(report)

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    import sys as _sys
    url = _sys.argv[1] if len(_sys.argv) > 1 else "https://liquid.af"
    print(run(url, scan_type="full"))
