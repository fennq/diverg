"""Tests for false-positive memory file helpers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import api_server  # noqa: E402


def test_fp_memory_read_has_rules_list() -> None:
    data = api_server._read_fp_memory()
    assert isinstance(data, dict)
    assert isinstance(data.get("rules"), list)


def test_fp_memory_write_roundtrip(tmp_path: Path) -> None:
    backup = api_server.FP_MEMORY_PATH
    try:
        api_server.FP_MEMORY_PATH = tmp_path / "fp_memory.json"
        payload = {"version": "v1", "rules": [{"active": True, "title_contains": "x"}]}
        api_server._write_fp_memory(payload)
        raw = json.loads(api_server.FP_MEMORY_PATH.read_text(encoding="utf-8"))
        assert raw["version"] == "v1"
        assert len(raw["rules"]) == 1
    finally:
        api_server.FP_MEMORY_PATH = backup
