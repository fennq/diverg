"""
Soft-404 baseline fingerprinting.

Before any path-probing, call ``capture_baseline(session, base_url)`` to
learn how the target responds to guaranteed-nonexistent paths.  Then call
``is_soft_404(resp, baseline)`` on every probe response to reject custom
error pages and SPA catch-all routes that return HTTP 200.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass(frozen=True)
class _Sample:
    status: int
    length: int
    body_hash: str
    snippet: str


@dataclass
class Baseline:
    samples: list[_Sample] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return len(self.samples) == 0


_PROBE_SUFFIXES = ["", ".php", "/admin"]
_LENGTH_TOLERANCE = 0.15
_TIMEOUT = 5


def _body_hash(text: str) -> str:
    return hashlib.sha256(text[:4096].encode("utf-8", errors="replace")).hexdigest()


def capture_baseline(
    session: requests.Session,
    base_url: str,
    *,
    timeout: float = _TIMEOUT,
) -> Baseline:
    """Probe 3 random nonexistent paths and record their responses."""
    base = base_url.rstrip("/")
    samples: list[_Sample] = []
    for suffix in _PROBE_SUFFIXES:
        probe_path = f"/{uuid.uuid4().hex[:12]}{suffix}"
        try:
            resp = session.get(
                f"{base}{probe_path}",
                timeout=timeout,
                allow_redirects=False,
            )
            body = resp.text or ""
            samples.append(
                _Sample(
                    status=resp.status_code,
                    length=len(body),
                    body_hash=_body_hash(body),
                    snippet=body[:200].strip().lower(),
                )
            )
        except requests.RequestException:
            continue
    return Baseline(samples=samples)


def is_soft_404(
    resp: requests.Response,
    baseline: Baseline,
    *,
    length_tolerance: float = _LENGTH_TOLERANCE,
) -> bool:
    """Return True if *resp* looks like a soft-404 based on the baseline."""
    if baseline.empty:
        return False

    body = resp.text or ""
    resp_len = len(body)
    resp_hash = _body_hash(body)

    for sample in baseline.samples:
        if resp.status_code != sample.status:
            continue

        if resp_hash == sample.body_hash:
            return True

        if sample.length > 0:
            ratio = abs(resp_len - sample.length) / sample.length
            if ratio <= length_tolerance:
                resp_snippet = body[:200].strip().lower()
                if resp_snippet and sample.snippet and resp_snippet == sample.snippet:
                    return True

    return False
