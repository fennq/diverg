"""
Per-thread optional HTTP session override for scan skills (authenticated scans).

ThreadPoolExecutor workers run one skill at a time per thread; the orchestrator
sets the active session for the duration of run_skill_variant / run_skill.
"""

from __future__ import annotations

import threading
from typing import Any

_tls = threading.local()


def set_active_http_session(session: Any | None) -> None:
    if session is None:
        if hasattr(_tls, "session"):
            delattr(_tls, "session")
    else:
        _tls.session = session


def get_active_http_session() -> Any | None:
    return getattr(_tls, "session", None)


def clear_active_http_session() -> None:
    if hasattr(_tls, "session"):
        delattr(_tls, "session")
