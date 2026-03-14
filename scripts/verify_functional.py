#!/usr/bin/env python3
"""
Verify Diverg bot and efficiency features are functional.
Run from project root: python scripts/verify_functional.py
Use project venv if available: ./venv/bin/python scripts/verify_functional.py

Checks:
- Cache key normalization and get/set
- Cache hit path in _run_skill_with_timeout
- build_adaptive_attack_plan
- One real skill run via _run_skill_with_timeout (recon; may see DNS errors in isolated envs)
- Fact/accuracy tests: only report what we have evidence for (tests/test_facts_and_accuracy.py)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "test")
os.environ.setdefault("OPENAI_API_KEY", "test")


def main() -> int:
    failed: list[str] = []

    # 1. Cache key and get/set
    try:
        from bot import (
            _skill_cache_key,
            _normalize_cache_target,
            _skill_cache_get,
            _skill_cache_set,
        )
        assert _normalize_cache_target("recon", "https://example.com/path") == "example.com"
        assert _normalize_cache_target("osint", "sub.example.com") == "sub.example.com"
        key = _skill_cache_key("recon", "https://example.com", "techstack")
        assert key == "recon:example.com:techstack"
        assert _skill_cache_get(key) is None
        _skill_cache_set(key, '{"findings": []}')
        assert _skill_cache_get(key) == '{"findings": []}'
        print("[OK] Cache key normalization and get/set")
    except Exception as e:
        failed.append(f"Cache: {e}")
        print(f"[FAIL] Cache: {e}")

    # 2. Cache hit path
    try:
        from bot import _run_skill_with_timeout
        out = _run_skill_with_timeout("recon", "https://example.com", scan_type="techstack")
        assert out == '{"findings": []}', repr(out)
        print("[OK] Cache hit path in _run_skill_with_timeout")
    except Exception as e:
        failed.append(f"Cache hit: {e}")
        print(f"[FAIL] Cache hit: {e}")

    # 3. build_adaptive_attack_plan
    try:
        from bot import build_adaptive_attack_plan
        plan = build_adaptive_attack_plan("example.com", "https://example.com", "quick-audit", "balanced")
        assert "phase1" in plan and "phase2" in plan and "phase3" in plan
        assert len(plan["phase1"]) >= 1
        print("[OK] build_adaptive_attack_plan")
    except Exception as e:
        failed.append(f"Attack plan: {e}")
        print(f"[FAIL] build_adaptive_attack_plan: {e}")

    # 4. Real skill run (cache miss) — clear cache first so we actually run
    try:
        from bot import _skill_cache_key, _run_skill_with_timeout, _skill_result_cache
        k = _skill_cache_key("recon", "testverify.example.com", "techstack")
        if k in _skill_result_cache:
            del _skill_result_cache[k]
        result = _run_skill_with_timeout("recon", "testverify.example.com", scan_type="techstack", port_range="top10")
        data = json.loads(result)
        assert "target" in data or "technologies" in data or "errors" in data
        print("[OK] Real skill run (recon)")
    except Exception as e:
        failed.append(f"Real skill: {e}")
        print(f"[FAIL] Real skill run: {e}")

    # 5. Fact/accuracy tests — we only bring facts; no invented counts or verdicts
    try:
        sys.path.insert(0, str(ROOT / "skills"))
        from tests.test_facts_and_accuracy import run_all as run_accuracy_tests
        accuracy_failed = run_accuracy_tests()
        if accuracy_failed:
            for name in accuracy_failed:
                failed.append(f"Accuracy:{name}")
            print(f"[FAIL] Fact/accuracy: {len(accuracy_failed)} test(s) failed")
        else:
            print("[OK] Fact/accuracy tests (evidence-only outputs)")
    except Exception as e:
        failed.append(f"Fact/accuracy: {e}")
        print(f"[FAIL] Fact/accuracy: {e}")

    if failed:
        print(f"\n{len(failed)} check(s) failed.")
        return 1
    print("\nAll functional and fact/accuracy checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
