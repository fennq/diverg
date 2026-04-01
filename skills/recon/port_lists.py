"""
Port lists for native (Rust) TCP probes — aligned with recon scan modes.

NMAP_TOP_50_TCP: typical ordering for nmap --top-ports 50 (TCP), used when
port_range is top100 (historical name: "top100" still scans 50 ports like nmap).
"""

from __future__ import annotations

# Typical nmap --top-ports 50 ordering (TCP). Documented reference; no nmap binary required.
NMAP_TOP_50_TCP: tuple[int, ...] = (
    80,
    23,
    443,
    21,
    22,
    25,
    3389,
    110,
    445,
    139,
    143,
    53,
    135,
    3306,
    8080,
    1723,
    111,
    995,
    993,
    5900,
    1025,
    587,
    8888,
    199,
    1720,
    465,
    548,
    113,
    81,
    6001,
    10000,
    514,
    5060,
    179,
    1026,
    2000,
    8443,
    8000,
    32768,
    554,
    26,
    1433,
    49152,
    2001,
    515,
    8008,
    49154,
    1027,
    5666,
    646,
)

# Extra high-signal ports for wider native scans (top1000 mode subset — not full 1000).
_ADDITIONAL_WIDE: tuple[int, ...] = (
    19,
    79,
    88,
    106,
    119,
    161,
    162,
    389,
    427,
    512,
    513,
    520,
    631,
    636,
    873,
    902,
    1080,
    1099,
    1521,
    1830,
    1900,
    2049,
    2181,
    2375,
    2379,
    3000,
    3128,
    3478,
    3632,
    4369,
    5000,
    5001,
    5432,
    5601,
    5672,
    5901,
    5984,
    6379,
    7001,
    7002,
    7199,
    8001,
    8009,
    8010,
    8081,
    8088,
    8161,
    8880,
    9000,
    9001,
    9042,
    9091,
    9200,
    9300,
    9418,
    9999,
    11211,
    27017,
    50000,
)


def ports_for_native_scan(port_range: str) -> list[int]:
    """Return port list to send to diverg-recon for known modes."""
    pr = port_range.strip().lower()
    if pr == "top10":
        return list(NMAP_TOP_50_TCP[:10])
    if pr == "top100":
        return list(NMAP_TOP_50_TCP)
    if pr == "top1000":
        merged: list[int] = []
        seen: set[int] = set()
        for p in NMAP_TOP_50_TCP + _ADDITIONAL_WIDE:
            if p not in seen:
                seen.add(p)
                merged.append(p)
        return merged[:400]
    return []


def parse_custom_port_list(port_range: str) -> list[int] | None:
    """
    Parse a simple -p style list: "80,443", "22-25", "80,8080-8082".
    Returns None if empty or invalid (caller should use nmap).
    """
    s = port_range.strip()
    if not s or s.lower() in ("top10", "top100", "top1000"):
        return None
    out: list[int] = []
    seen: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a.strip()), int(b.strip())
            except ValueError:
                return None
            if lo > hi or lo < 1 or hi > 65535:
                return None
            for p in range(lo, hi + 1):
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        else:
            try:
                p = int(part)
            except ValueError:
                return None
            if p < 1 or p > 65535:
                return None
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out if out else None
