"""
Arkham Intel API client — address intelligence (labels, entities) across chains.
Requires ARKHAM_API_KEY. Base: https://api.arkm.com
Docs: https://intel.arkm.com/llms.txt
"""
import os
from typing import Optional

import requests

ARKHAM_KEY = os.environ.get("ARKHAM_API_KEY", "").strip()
BASE_URL = "https://api.arkm.com"


def address_intelligence_all(address: str) -> Optional[dict]:
    """
    GET /intelligence/address/{address}/all
    Returns multi-chain intelligence for the address (entity, labels, tags per chain).
    """
    if not ARKHAM_KEY:
        return None
    try:
        r = requests.get(
            f"{BASE_URL}/intelligence/address/{address}/all",
            headers={"API-Key": ARKHAM_KEY},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def summarize_for_report(data: Optional[dict]) -> dict:
    """Extract entity name, label, and chain info for the investigation report."""
    if not data or not isinstance(data, dict):
        return {}
    out = {"chains": list(data.keys()) if data else []}
    # One chain (e.g. solana) may have arkhamEntity, arkhamLabel, etc.
    for chain, obj in data.items():
        if not isinstance(obj, dict):
            continue
        entity = obj.get("arkhamEntity") or obj.get("predictedEntity")
        label = obj.get("arkhamLabel") or obj.get("userLabel")
        if entity and isinstance(entity, dict):
            out["entity_name"] = entity.get("name")
            out["entity_type"] = entity.get("type")
            out["entity_id"] = entity.get("id")
        if label and isinstance(label, dict):
            out["label_name"] = label.get("name")
            out["label_note"] = label.get("note")
        break
    return out
