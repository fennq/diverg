"""
Arkham Intel API client — address intelligence (labels, entities) across chains.
Requires ARKHAM_API_KEY. Base: https://api.arkm.com
Docs: https://intel.arkm.com/llms.txt

Prefer investigation.arkham_intel for new code; this module keeps backward-compatible imports.
"""
import os
from typing import Optional

from arkham_intel import address_intelligence_all as _address_intel_tuple
from arkham_intel import get_arkham_api_key, summarize_for_report

ARKHAM_KEY = os.environ.get("ARKHAM_API_KEY", "").strip()
BASE_URL = "https://api.arkm.com"


def address_intelligence_all(address: str) -> Optional[dict]:
    """
    GET /intelligence/address/{address}/all
    Returns multi-chain intelligence for the address (entity, labels, tags per chain).
    On failure or missing key, returns None (legacy behavior).
    """
    key = get_arkham_api_key()
    if not key:
        return None
    data, _err = _address_intel_tuple(address, api_key=key)
    return data
