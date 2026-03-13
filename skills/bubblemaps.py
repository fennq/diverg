"""
Bubblemaps — on-chain intelligence for token holder maps, wallet clusters, and transfer relationships.

Uses Bubblemaps Data API (https://docs.bubblemaps.io): GET /maps/{chain}/{token_address}.
Returns: top holders, relationships (grouped transfers), clusters, decentralization score,
identified supply (CEX/DEX/contract share). Fact-only: data from API when BUBBLEMAPS_API_KEY set.

Chains: eth, base, solana, tron, bsc, apechain, ton, polygon, avalanche, sonic, monad.
Ref: https://bubblemaps.io/ — "The Onchain Intelligence Layer"
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from stealth import get_session

SESSION = get_session()
TIMEOUT = 25
BUBBLEMAPS_BASE = "https://api.bubblemaps.io"

CHAIN_ALIASES = {
    "ethereum": "eth",
    "solana": "solana",
    "bnb": "bsc",
    "binance": "bsc",
    "polygon": "polygon",
    "avax": "avalanche",
    "avalanche": "avalanche",
    "base": "base",
    "tron": "tron",
    "ton": "ton",
    "apechain": "apechain",
    "sonic": "sonic",
    "monad": "monad",
}


@dataclass
class BubblemapsReport:
    chain: str
    token_address: str
    api_used: bool = False
    error: str | None = None
    decentralization_score: float | None = None
    top_holders_count: int = 0
    relationships_count: int = 0
    clusters_count: int = 0
    share_in_cexs: float | None = None
    share_in_dexs: float | None = None
    share_in_other_contracts: float | None = None
    top_holders_preview: list[dict] = field(default_factory=list)
    relationships_preview: list[dict] = field(default_factory=list)
    clusters_preview: list[dict] = field(default_factory=list)
    metadata: dict | None = None


def _normalize_chain(chain: str) -> str:
    c = (chain or "solana").strip().lower()
    return CHAIN_ALIASES.get(c, c) if c in CHAIN_ALIASES else c


def run(
    token_address: str,
    chain: str = "solana",
    return_nodes: bool = True,
    return_relationships: bool = True,
    return_clusters: bool = True,
    return_decentralization_score: bool = True,
    use_magic_nodes: bool = True,
) -> str:
    """
    Fetch Bubblemaps map data for a token. Fact-only: uses live API when BUBBLEMAPS_API_KEY is set.
    token_address: contract/mint address. chain: eth, solana, bsc, etc.
    """
    token_address = (token_address or "").strip()
    if not token_address or len(token_address) < 20:
        out = BubblemapsReport(chain=chain, token_address=token_address or "", api_used=False, error="Missing or invalid token_address")
        return json.dumps(asdict(out), indent=2)

    chain_id = _normalize_chain(chain)
    api_key = (os.environ.get("BUBBLEMAPS_API_KEY") or "").strip()
    if not api_key:
        out = BubblemapsReport(
            chain=chain_id,
            token_address=token_address,
            api_used=False,
            error="BUBBLEMAPS_API_KEY not set. Get key from api@bubblemaps.io. Data only from live API.",
        )
        return json.dumps(asdict(out), indent=2)

    url = f"{BUBBLEMAPS_BASE}/maps/{chain_id}/{token_address}"
    params = {
        "return_nodes": "true" if return_nodes else "false",
        "return_relationships": "true" if return_relationships else "false",
        "return_clusters": "true" if return_clusters else "false",
        "return_decentralization_score": "true" if return_decentralization_score else "false",
        "use_magic_nodes": "true" if use_magic_nodes else "false",
    }
    headers = {"X-ApiKey": api_key}

    report = BubblemapsReport(chain=chain_id, token_address=token_address)
    try:
        r = SESSION.get(url, params=params, headers=headers, timeout=TIMEOUT)
        if r.status_code == 429:
            report.error = "Rate limited (daily query-seconds). Retry after midnight UTC."
            return json.dumps(asdict(report), indent=2)
        if r.status_code == 404:
            report.error = "No holders found for this token (404)."
            return json.dumps(asdict(report), indent=2)
        if r.status_code != 200:
            report.error = f"API HTTP {r.status_code}: {r.text[:200]}"
            return json.dumps(asdict(report), indent=2)

        data = r.json()
        report.api_used = True
        report.metadata = data.get("metadata")
        report.decentralization_score = data.get("decentralization_score")

        meta = data.get("metadata") or {}
        identified = meta.get("identified_supply") or {}
        report.share_in_cexs = identified.get("share_in_cexs")
        report.share_in_dexs = identified.get("share_in_dexs")
        report.share_in_other_contracts = identified.get("share_in_other_contracts")

        nodes = data.get("nodes")
        if nodes:
            top = nodes.get("top_holders") or []
            report.top_holders_count = len(top)
            for h in top[:15]:
                addr = h.get("address", "")
                details = h.get("address_details") or {}
                holder_data = h.get("holder_data") or {}
                report.top_holders_preview.append({
                    "address": addr,
                    "label": details.get("label"),
                    "is_cex": details.get("is_cex"),
                    "is_dex": details.get("is_dex"),
                    "share": holder_data.get("share"),
                    "rank": holder_data.get("rank"),
                })
        rels = data.get("relationships") or []
        report.relationships_count = len(rels)
        for rel in rels[:20]:
            report.relationships_preview.append({
                "from": rel.get("from_address"),
                "to": rel.get("to_address"),
                "total_transfers": (rel.get("data") or {}).get("total_transfers"),
                "total_value": (rel.get("data") or {}).get("total_value"),
            })
        clusters = data.get("clusters") or []
        report.clusters_count = len(clusters)
        for cl in clusters[:10]:
            report.clusters_preview.append({
                "share": cl.get("share"),
                "holder_count": cl.get("holder_count"),
                "holders_sample": (cl.get("holders") or [])[:5],
            })
    except requests.RequestException as e:
        report.error = f"Request failed: {e}"
    except Exception as e:
        report.error = str(e)

    return json.dumps(asdict(report), indent=2)


if __name__ == "__main__":
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    chain = sys.argv[2] if len(sys.argv) > 2 else "solana"
    print(run(token, chain=chain))
